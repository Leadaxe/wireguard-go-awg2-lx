/* SPDX-License-Identifier: MIT
 *
 * lx: buffers of queued packets on upstream's packetBuf model (lx_buffers.go,
 * sing-box-lx SPEC 158 line 1.15). An AmneziaWG datagram is built around the
 * packet in place: the transport padding (s4) in front and a 3.x tail behind.
 * A TUN batch sits in one shared slab, 64 bytes between packets, so an AWG
 * layout written there would land in the neighbour. These tests send whole
 * batches under a wide s4 and random trailers and require every packet to
 * arrive intact, over each outbound path and each receive copy mode.
 */

package device

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/tun"
)

// batchTun is a chanTun that hands over up to batch packets per read, packed
// into the slab with tun.ReadPacketSpacing between them, as a GSO TUN does.
type batchTun struct {
	*chanTun
	batch int
}

func (t *batchTun) BatchSize() int { return t.batch }

func (t *batchTun) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	var first []byte
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt, ok := <-t.toDevice:
		if !ok {
			return 0, os.ErrClosed
		}
		first = pkt
	}
	offset := tun.ReadPacketSpacing
	n := 0
	put := func(pkt []byte) {
		size := copy(slab[offset:], pkt)
		packets[n] = tun.ReadPacket{Offset: offset, Size: size}
		offset += size + tun.ReadPacketSpacing
		n++
	}
	put(first)
	for n < t.batch && n < len(packets) {
		select {
		case pkt := <-t.toDevice:
			put(pkt)
		default:
			return n, nil
		}
	}
	return n, nil
}

const lxBuffersS4 = 100

func newLXBuffersPair(t *testing.T, tunA tun.Device, setup func(devA, devB *Device)) *paddedPair {
	t.Helper()
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pkA, pkB := skA.publicKey(), skB.publicKey()
	key := newHeaderKey(t)
	lines := strings.Replace(awg3DeviceLines(key), fmt.Sprintf("s4=%d\n", awg3S4), fmt.Sprintf("s4=%d\n", lxBuffersS4), 1)

	bindA, bindB := newChanBindPair()
	tunB := newChanTun()
	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)
	if setup != nil {
		setup(devA, devB)
	}
	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + lines +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n", hex.EncodeToString(pkB[:]), testIPB)
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + lines +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n", hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatal(err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatal(err)
	}
	if err := devA.Up(); err != nil {
		t.Fatal(err)
	}
	if err := devB.Up(); err != nil {
		t.Fatal(err)
	}
	pair := &paddedPair{devA: devA, devB: devB, tunB: tunB}
	if ct, ok := tunA.(*chanTun); ok {
		pair.tunA = ct
	} else {
		pair.tunA = tunA.(*batchTun).chanTun
	}
	return pair
}

// sendBatch establishes the session with one packet, then sends count packets
// of distinct sizes and contents at once and requires each to arrive intact.
func sendBatch(t *testing.T, pair *paddedPair, count int) {
	t.Helper()
	warm := buildIPv4Packet(testIPA, testIPB, 20)
	resend := func() { pair.tunA.toDevice <- append([]byte(nil), warm...) }
	resend()
	awaitPacket(t, pair.tunB, warm, resend)

	want := make(map[string]bool, count)
	for i := range count {
		pkt := buildIPv4Packet(testIPA, testIPB, 40+i*37)
		for j := 28; j < len(pkt); j++ {
			pkt[j] = byte(i*31 + j)
		}
		want[string(pkt)] = true
		pair.tunA.toDevice <- pkt
	}
	deadline := time.After(5 * time.Second)
	for len(want) > 0 {
		select {
		case got := <-pair.tunB.fromDevice:
			if bytes.Equal(got, warm) {
				continue
			}
			if !want[string(got)] {
				t.Fatalf("a packet arrived corrupted or twice (len %d)", len(got))
			}
			delete(want, string(got))
		case <-deadline:
			t.Fatalf("%d of %d packets did not arrive", len(want), count)
		}
	}
}

// A TUN batch in one shared slab under a wide s4 and AWG 3.x tails: every
// packet gets a buffer of its own, none spills into its neighbour.
func TestLXBuffersAWGBatchFromSharedSlab(t *testing.T) {
	pair := newLXBuffersPair(t, &batchTun{chanTun: newChanTun(), batch: 8}, nil)
	sendBatch(t, pair, 8)
}

// send_by_mtu: the TUN reads straight into a buffer of the packet's own; the
// packet is moved behind the wide s4 in place.
func TestLXBuffersTunReadsByMTU(t *testing.T) {
	pair := newLXBuffersPair(t, newChanTun(), func(devA, _ *Device) {
		devA.SetTunReadsByMTU(true)
	})
	sendBatch(t, pair, 8)
}

// Every receive copy mode delivers the same packets.
func TestLXBuffersReceiveCopyModes(t *testing.T) {
	for name, mode := range map[string]int32{"memory": ReceiveCopyMemory, "auto": ReceiveCopyAuto, "speed": ReceiveCopySpeed} {
		t.Run(name, func(t *testing.T) {
			pair := newLXBuffersPair(t, newChanTun(), func(_, devB *Device) {
				devB.SetReceiveCopy(mode)
			})
			sendBatch(t, pair, 8)
		})
	}
}

// A reconfigured s4 while packets are queued: elements laid out for the old
// padding are moved (or regrown) under the new one.
func TestLXBuffersS4ChangeInFlight(t *testing.T) {
	pair := newLXBuffersPair(t, &batchTun{chanTun: newChanTun(), batch: 8}, nil)
	sendBatch(t, pair, 4)
	for _, dev := range []*Device{pair.devA, pair.devB} {
		if err := dev.IpcSet("s4=300\n"); err != nil {
			t.Fatal(err)
		}
	}
	sendBatch(t, pair, 8)
}
