/* SPDX-License-Identifier: MIT
 *
 * lx: sing-box-lx SPEC 101 — what the handshake burst relies on: a send of one
 * datagram asks for no segmentation, while the same datagrams in one send are
 * coalesced with the first one's length as the segment size.
 */

package conn

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestLXCoalesceJunkBurst(t *testing.T) {
	endpoint := &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("192.0.2.1:51820")}
	newMsgs := func() []ipv6.Message {
		msgs := make([]ipv6.Message, IdealBatchSize)
		for i := range msgs {
			msgs[i].Buffers = make(net.Buffers, 1)
			msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
		}
		return msgs
	}
	// Proton's junk (jc=3, 1-3 bytes) ahead of a 148-byte initiation
	burst := [][]byte{make([]byte, 2), make([]byte, 2), make([]byte, 1), make([]byte, 148)}

	var sizes []uint16
	record := func(control *[]byte, gsoSize uint16) { sizes = append(sizes, gsoSize) }

	n := coalesceMessages(&net.UDPAddr{}, endpoint, burst, 0, newMsgs(), record)
	if n != 2 || len(sizes) != 1 || sizes[0] != 2 {
		t.Fatalf("one send of the burst: %d messages, segment sizes %v; want 2 messages and a 2-byte segment", n, sizes)
	}

	sizes = nil
	for i := range burst {
		msgs := newMsgs()
		n = coalesceMessages(&net.UDPAddr{}, endpoint, burst[i:i+1], 0, msgs, record)
		if n != 1 || len(msgs[0].Buffers) != 1 {
			t.Fatalf("datagram %d alone: %d messages, %d buffers; want 1 and 1", i, n, len(msgs[0].Buffers))
		}
	}
	if len(sizes) != 0 {
		t.Fatalf("datagrams sent alone asked for segmentation: %v", sizes)
	}
}
