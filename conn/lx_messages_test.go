/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — the message set comes back to the pool clean, whatever part
 * of it a call used.
 */

package conn

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv6"
)

func messagePristine(m *ipv6.Message) bool {
	return m.Addr == nil && m.N == 0 && m.NN == 0 && m.Flags == 0 &&
		len(m.OOB) == 0 && len(m.Buffers) == 1 && m.Buffers[0] == nil
}

// trackMessageSets makes the bind remember every message set it creates, so
// that a test can look at them after they went back to the pool.
func trackMessageSets(bind *StdNetBind) func() []*[]ipv6.Message {
	var (
		access sync.Mutex
		sets   []*[]ipv6.Message
	)
	create := bind.msgsPool.New
	bind.msgsPool.New = func() any {
		set := create().(*[]ipv6.Message)
		access.Lock()
		sets = append(sets, set)
		access.Unlock()
		return set
	}
	return func() []*[]ipv6.Message {
		access.Lock()
		defer access.Unlock()
		return append([]*[]ipv6.Message(nil), sets...)
	}
}

func requireSetsPristine(t *testing.T, sets []*[]ipv6.Message) {
	t.Helper()
	if len(sets) == 0 {
		t.Fatal("no message set was created")
	}
	for _, set := range sets {
		for i := range *set {
			if !messagePristine(&(*set)[i]) {
				t.Fatalf("message %d of %d is not reset: %+v", i, len(*set), (*set)[i])
			}
		}
	}
}

// However a call filled the front of the set, all of it comes back clean.
func TestPutMessagesResetsUsed(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	fills := map[string]func(msg *ipv6.Message){
		"send": func(msg *ipv6.Message) {
			msg.Addr = &net.UDPAddr{}
			msg.Buffers = append(msg.Buffers[:0], []byte{1}, []byte{2}, []byte{3})
			msg.OOB = msg.OOB[:cap(msg.OOB)]
		},
		// no address, no control data: a buffer is all that marks it
		"connected send": func(msg *ipv6.Message) {
			msg.Buffers[0] = []byte{1}
		},
		"receive": func(msg *ipv6.Message) {
			msg.Buffers[0] = make([]byte, 16)
			msg.OOB = msg.OOB[:cap(msg.OOB)]
			msg.N, msg.NN, msg.Flags = 7, 3, 1
			msg.Addr = &net.UDPAddr{}
		},
		// a receive attaches a buffer to a message the kernel then leaves alone
		"receive, nothing read": func(msg *ipv6.Message) {
			msg.Buffers[0] = make([]byte, 16)
			msg.OOB = msg.OOB[:cap(msg.OOB)]
		},
	}
	for name, fill := range fills {
		for _, used := range []int{0, 1, 5, IdealBatchSize} {
			msgs := bind.getMessages()
			for i := 0; i < used; i++ {
				fill(&(*msgs)[i])
			}
			bind.putMessages(msgs)
			for i := range *msgs {
				if !messagePristine(&(*msgs)[i]) {
					t.Fatalf("%s, %d used: message %d is not reset", name, used, i)
				}
			}
		}
	}
}

// A message that segments were coalesced into must go out as one datagram
// when the same set is filled again without offload.
func TestSetMessageBufferDropsCoalescedSegments(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	msgs := bind.getMessages()
	endpoint := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("127.0.0.1:1")}
	bufs := [][]byte{make([]byte, 100), make([]byte, 100), make([]byte, 100)}
	n := coalesceMessages(&net.UDPAddr{}, endpoint, bufs, 0, *msgs, func(control *[]byte, gsoSize uint16) {})
	if n != 1 || len((*msgs)[0].Buffers) != 3 {
		t.Fatalf("expected three segments in one message, got %d messages, %d buffers", n, len((*msgs)[0].Buffers))
	}
	for i := range bufs {
		setMessageBuffer(&(*msgs)[i], bufs[i])
	}
	for i := range bufs {
		if len((*msgs)[i].Buffers) != 1 || &(*msgs)[i].Buffers[0][0] != &bufs[i][0] {
			t.Fatalf("message %d does not carry exactly its own buffer", i)
		}
	}
	bind.putMessages(msgs)
	requireSetsPristine(t, []*[]ipv6.Message{msgs})
}

// One datagram each way through real sockets: what arrives is what was sent,
// and every message set is clean afterwards.
func TestSendReceiveLeaveSetsPristine(t *testing.T) {
	receiver := NewStdNetBind(nil).(*StdNetBind)
	receiverSets := trackMessageSets(receiver)
	receiveFuncs, port, err := receiver.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	sender := NewStdNetBind(nil).(*StdNetBind)
	senderSets := trackMessageSets(sender)
	_, _, err = sender.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const offset = 16
	payloads := [][]byte{bytes.Repeat([]byte{0xA5}, 1200), bytes.Repeat([]byte{0x5A}, 900)}
	endpoint := &StdNetEndpoint{AddrPort: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}

	batch := receiver.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, batch)
	endpoints := make([]Endpoint, batch)

	type result struct {
		packets [][]byte
		err     error
	}
	results := make(chan result, 1)
	go func() {
		var received [][]byte
		for len(received) < len(payloads) {
			count, err := receiveFuncs[0](bufs, sizes, endpoints)
			if err != nil {
				results <- result{err: err}
				return
			}
			for i := 0; i < count; i++ {
				if sizes[i] == 0 {
					continue
				}
				received = append(received, bytes.Clone(bufs[i][:sizes[i]]))
			}
		}
		results <- result{packets: received}
	}()

	for _, payload := range payloads {
		buf := append(make([]byte, offset), payload...)
		err = sender.Send([][]byte{buf}, endpoint, offset)
		if err != nil {
			t.Fatal(err)
		}
	}

	select {
	case got := <-results:
		if got.err != nil {
			t.Fatal(got.err)
		}
		for i, payload := range payloads {
			if !bytes.Equal(got.packets[i], payload) {
				t.Fatalf("datagram %d arrived changed: %d bytes, want %d", i, len(got.packets[i]), len(payload))
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("datagrams did not arrive")
	}
	requireSetsPristine(t, senderSets())
	if !supportsMsgX {
		requireSetsPristine(t, receiverSets())
	}
}
