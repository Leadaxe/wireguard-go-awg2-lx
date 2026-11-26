/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 158 part 2 — the read datagram count.
 */

package conn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func readsInBatches() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "android"
}

func TestReadDatagramCountRange(t *testing.T) {
	bind := NewStdNetBind(nil).(*StdNetBind)
	for _, count := range []int{0, -1, IdealBatchSize + 1} {
		if bind.SetReadDatagramCount(count) == nil {
			t.Errorf("count %d was accepted", count)
		}
	}
	for _, count := range []int{1, 8, IdealBatchSize} {
		if err := bind.SetReadDatagramCount(count); err != nil {
			t.Errorf("count %d: %v", count, err)
		}
	}
	_, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if err = bind.SetReadDatagramCount(8); !errors.Is(err, ErrBindAlreadyOpen) {
		t.Fatalf("changing the count of an open bind returned %v", err)
	}
}

func TestReadDatagramCountBatchSize(t *testing.T) {
	unset := NewStdNetBind(nil).BatchSize()
	bind := NewStdNetBind(nil).(*StdNetBind)
	if err := bind.SetReadDatagramCount(8); err != nil {
		t.Fatal(err)
	}
	want := unset
	if readsInBatches() {
		if unset != IdealBatchSize {
			t.Fatalf("batch size without the setting is %d", unset)
		}
		want = 8
	}
	if got := bind.BatchSize(); got != want {
		t.Fatalf("batch size is %d, want %d", got, want)
	}
}

// Below a full batch the sockets must come up without receive offload, on
// every open, and keep whatever segmentation offload the kernel gives.
func TestReadDatagramCountOffload(t *testing.T) {
	if !readsInBatches() {
		t.Skip("no offload on this platform")
	}
	full := NewStdNetBind(nil).(*StdNetBind)
	if _, _, err := full.Open(0); err != nil {
		t.Fatal(err)
	}
	tx4, tx6 := testTxOffload(full)
	rx4, rx6 := testRxOffload(full)
	full.Close()
	t.Logf("full batch: tx4=%v rx4=%v tx6=%v rx6=%v", tx4, rx4, tx6, rx6)
	if !rx4 && !rx6 {
		t.Skip("this kernel gives no receive offload: there is nothing to turn off")
	}

	small := NewStdNetBind(nil).(*StdNetBind)
	if err := small.SetReadDatagramCount(8); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, _, err := small.Open(0); err != nil {
			t.Fatal(err)
		}
		if srx4, srx6 := testRxOffload(small); srx4 || srx6 {
			t.Fatalf("open %d: receive offload is on below a full batch", attempt)
		}
		if stx4, stx6 := testTxOffload(small); stx4 != tx4 || stx6 != tx6 {
			t.Fatalf("open %d: segmentation offload changed with the read count", attempt)
		}
		if got := small.BatchSize(); got != 8 {
			t.Fatalf("open %d: batch size is %d", attempt, got)
		}
		small.Close()
	}
}

// A burst of datagrams comes out of a bind whole and in order whatever the
// count, and no read returns more than the bind promised.
func TestReadDatagramCountDelivers(t *testing.T) {
	const datagrams = 60
	for _, count := range []int{0, 1, 8, IdealBatchSize} {
		bind := NewStdNetBind(nil).(*StdNetBind)
		if count > 0 {
			if err := bind.SetReadDatagramCount(count); err != nil {
				t.Fatal(err)
			}
		}
		receiveFuncs, port, err := bind.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		source, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatal(err)
		}
		want := make([][]byte, datagrams)
		for i := range want {
			// the same length in runs of four, so that offload has something to coalesce
			want[i] = bytes.Repeat([]byte{byte(i)}, 200+(i/4)*17)
			binary.BigEndian.PutUint32(want[i][4:], uint32(i))
			if _, err = source.Write(want[i]); err != nil {
				t.Fatal(err)
			}
		}

		batch := bind.BatchSize()
		slab := make([]byte, batch*65535)
		packets := make([]ReceivedPacket, batch)
		done := make(chan error, 1)
		var got [][]byte
		go func() {
			for len(got) < datagrams {
				n, err := receiveFuncs[0](slab, packets)
				if err != nil {
					done <- err
					return
				}
				if n > batch {
					done <- errors.New("a read returned more datagrams than the batch size")
					return
				}
				for i := 0; i < n; i++ {
					if packets[i].Size > 0 {
						got = append(got, bytes.Clone(packets[i].Bytes(slab)))
					}
				}
			}
			done <- nil
		}()
		select {
		case err = <-done:
			if err != nil {
				t.Fatalf("count %d: %v", count, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("count %d: datagrams did not arrive", count)
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("count %d: datagram %d arrived changed or out of order", count, i)
			}
		}
		source.Close()
		bind.Close()
	}
}

// One Send may carry more datagrams than a read takes: an AmneziaWG
// handshake burst, a batch of injected packets. The message set is not sized
// by the read count, so they all go out.
func TestSendMoreThanReadCount(t *testing.T) {
	const datagrams = 40
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	bind := NewStdNetBind(nil).(*StdNetBind)
	if err = bind.SetReadDatagramCount(8); err != nil {
		t.Fatal(err)
	}
	if _, _, err = bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	const offset = 16
	bufs := make([][]byte, datagrams)
	for i := range bufs {
		bufs[i] = append(make([]byte, offset), bytes.Repeat([]byte{byte(i)}, 300+(i/8)*40)...)
	}
	endpoint := &StdNetEndpoint{AddrPort: sink.LocalAddr().(*net.UDPAddr).AddrPort()}
	endpoint.AddrPort = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), endpoint.Port())
	if err = bind.Send(bufs, endpoint, offset); err != nil {
		var gsoDisabled ErrUDPGSODisabled
		if !errors.As(err, &gsoDisabled) || gsoDisabled.RetryErr != nil {
			t.Fatal(err)
		}
	}
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	packet := make([]byte, 65535)
	for i := range bufs {
		n, err := sink.Read(packet)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(packet[:n], bufs[i][offset:]) {
			t.Fatalf("datagram %d arrived changed or out of order", i)
		}
	}
}

// testTxOffload and testRxOffload report the offload state of the first
// socket of each family.
func testTxOffload(s *StdNetBind) (v4, v6 bool) {
	if len(s.v4) > 0 {
		v4 = s.v4[0].txOffload.Load()
	}
	if len(s.v6) > 0 {
		v6 = s.v6[0].txOffload.Load()
	}
	return
}

func testRxOffload(s *StdNetBind) (v4, v6 bool) {
	if len(s.v4) > 0 {
		v4 = s.v4[0].rxOffload
	}
	if len(s.v6) > 0 {
		v6 = s.v6[0].rxOffload
	}
	return
}
