/* SPDX-License-Identifier: MIT
 *
 * Receive backlog stand: how much memory a queued inbound transport packet
 * pins, and what the receive path costs per packet.
 *
 * A datagram is read into a MaxMessageSize slot because one read may return a
 * coalesced batch. A transport packet then waits for decryption and for the
 * TUN in the peer's inbound queue. When the consumer is slower than the
 * socket, the queue fills, and what each queued packet keeps alive decides the
 * process footprint: a whole read slot, or just the packet.
 *
 * The stand wires two real Devices through the in-memory bind, blocks the
 * receiving TUN, floods until the receive side stops accepting, and measures
 * the heap growth. It then opens the TUN and checks that every packet comes
 * out byte-exact and in order — a queued packet that still aliased a reused
 * read slot would not.
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// rxSeqOffset is where the stand writes a packet's sequence number: the first
// bytes of the payload behind the IPv4 header.
const rxSeqOffset = ipv4.HeaderLen

// rxSinkTun is a receiving TUN that can be held shut. While shut, Write blocks,
// so everything the device has accepted stays queued inside it.
type rxSinkTun struct {
	*chanTun
	batch int // BatchSize reported to the device; 0 means 1

	gate sync.RWMutex // the stand holds the write lock to shut the TUN

	template  []byte // expected packet, sequence field aside
	delivered atomic.Int64
	next      uint64 // expected sequence; only Write touches it
	corrupt   atomic.Int64
	minCap    atomic.Int64 // smallest cap() of a buffer handed to Write
}

func newRxSinkTun(template []byte, batch int) *rxSinkTun {
	t := &rxSinkTun{chanTun: newChanTun(), batch: batch, template: template, next: 1}
	t.minCap.Store(1 << 62)
	return t
}

func (t *rxSinkTun) BatchSize() int {
	if t.batch > 1 {
		return t.batch
	}
	return 1
}

func (t *rxSinkTun) Write(bufs [][]byte, offset int) (int, error) {
	t.gate.RLock()
	defer t.gate.RUnlock()
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		if c := int64(cap(b)); c < t.minCap.Load() {
			t.minCap.Store(c)
		}
		pkt := b[offset:]
		if len(pkt) != len(t.template) {
			t.corrupt.Add(1)
			continue
		}
		seq := binary.BigEndian.Uint64(pkt[rxSeqOffset:])
		if seq == 0 {
			continue // the warm-up packet, sent until the session is up
		}
		if seq != t.next ||
			!bytes.Equal(pkt[:rxSeqOffset], t.template[:rxSeqOffset]) ||
			!bytes.Equal(pkt[rxSeqOffset+8:], t.template[rxSeqOffset+8:]) {
			t.corrupt.Add(1)
		}
		t.next = seq + 1
		t.delivered.Add(1)
	}
	return len(bufs), nil
}

type rxStand struct {
	devA, devB *Device
	tunA       *chanTun
	tunB       *rxSinkTun
	peerOnA    *Peer // B, as A knows it
	peerOnB    *Peer // A, as B knows it
	template   []byte
	dst        []byte
}

// newRxStand builds A → B with transport padding s4 on both ends (0 is plain
// WireGuard). prepare, if set, runs on B before it is brought up.
func newRxStand(tb testing.TB, s4, payloadLen, tunBatch int, prepare func(devB *Device)) *rxStand {
	tb.Helper()
	skA, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	pkA, pkB := skA.publicKey(), skB.publicKey()

	template := buildIPv4Packet(testIPA, testIPB, payloadLen)
	bindA, bindB := newChanBindPair()
	tunA := newChanTun()
	tunB := newRxSinkTun(template, tunBatch)
	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "rxA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "rxB: "), 1)
	tb.Cleanup(devA.Close)
	tb.Cleanup(devB.Close)

	cfgA := fmt.Sprintf(
		"private_key=%s\ns4=%d\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), s4, hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\ns4=%d\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), s4, hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		tb.Fatal(err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		tb.Fatal(err)
	}
	if prepare != nil {
		prepare(devB)
	}
	if err := devA.Up(); err != nil {
		tb.Fatal(err)
	}
	if err := devB.Up(); err != nil {
		tb.Fatal(err)
	}

	s := &rxStand{
		devA: devA, devB: devB, tunA: tunA, tunB: tunB,
		peerOnA: devA.LookupPeer(pkB), peerOnB: devB.LookupPeer(pkA),
		template: template, dst: testIPB.AsSlice(),
	}
	if s.peerOnA == nil || s.peerOnB == nil {
		tb.Fatal("the peers are not configured")
	}
	s.warmUp(tb)
	return s
}

// packet returns the stand's packet carrying seq.
func (s *rxStand) packet(seq uint64) []byte {
	pkt := bytes.Clone(s.template)
	binary.BigEndian.PutUint64(pkt[rxSeqOffset:], seq)
	return pkt
}

// rxSenderWindow caps what the stand lets pile up on the sending device. It
// keeps the sender's own queues out of the measurement and stays below the
// point where injection starts dropping.
const rxSenderWindow = 256

// inject hands pkt to A the way a userspace network stack does, with
// packet-sized buffers, and reports false when A's queue is at the window.
func (s *rxStand) inject(pkt []byte) bool {
	if s.peerOnA.queuedOutboundPackets.Load() >= rxSenderWindow {
		return false
	}
	s.devA.InputPacket(s.dst, [][]byte{pkt})
	return true
}

// warmUp sends sequence-0 packets until one crosses, so the handshake is done
// and its allocations are behind us before anything is measured.
func (s *rxStand) warmUp(tb testing.TB) {
	tb.Helper()
	// B must have seen a packet for the session to count as established both ways.
	sawWrite := func() bool { return s.tunB.minCap.Load() != 1<<62 }
	deadline := time.Now().Add(20 * time.Second)
	for !sawWrite() {
		if time.Now().After(deadline) {
			tb.Fatal("no packet crossed the tunnel during warm-up")
		}
		s.inject(s.packet(0))
		time.Sleep(20 * time.Millisecond)
	}
	// let the retries drain
	for s.peerOnA.queuedOutboundPackets.Load() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
}

func poolCount(p *WaitPool) uint32 {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.count
}

func rxHeapAlloc() uint64 {
	runtime.GC()
	runtime.GC() // a second cycle empties the sync.Pool victim caches
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// rxBacklogResult is what one backlog run observed.
type rxBacklogResult struct {
	queued   int    // packets B was holding when it stopped accepting
	held     uint32 // compact buffers B had out at that point
	retained uint64 // heap growth with the backlog in place
	sent     uint64
}

// runBacklog shuts B's TUN, floods from A until B stops accepting, measures,
// then opens the TUN and waits for everything to arrive.
func (s *rxStand) runBacklog(tb testing.TB) rxBacklogResult {
	tb.Helper()
	idle := rxHeapAlloc()

	s.tunB.gate.Lock()
	var sent atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		pkt := s.packet(0)
		for seq := uint64(1); ; {
			select {
			case <-stop:
				return
			default:
			}
			binary.BigEndian.PutUint64(pkt[rxSeqOffset:], seq)
			if !s.inject(pkt) {
				time.Sleep(time.Millisecond)
				continue
			}
			sent.Store(seq)
			seq++
		}
	}()

	// B has stopped accepting when the sender has made no progress for a second.
	var last uint64
	stable := 0
	deadline := time.Now().Add(60 * time.Second)
	for stable < 20 {
		if time.Now().After(deadline) {
			close(stop)
			s.tunB.gate.Unlock()
			tb.Fatal("the flood never stalled")
		}
		time.Sleep(50 * time.Millisecond)
		if now := sent.Load(); now == last && now > 0 {
			stable++
		} else {
			last, stable = now, 0
		}
	}
	queued := len(s.peerOnB.queue.inbound.c) + 2 // + one in the TUN write, one in the reader's hands
	retained := rxHeapAlloc() - idle
	held := poolCount(s.devB.pool.inboundCompact)

	close(stop)
	<-done
	s.tunB.gate.Unlock()

	total := sent.Load()
	s.awaitDelivered(tb, total)
	return rxBacklogResult{queued: queued, held: held, retained: retained, sent: total}
}

// awaitDelivered waits until B's TUN has seen total packets, intact and in order.
func (s *rxStand) awaitDelivered(tb testing.TB, total uint64) {
	tb.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for s.tunB.delivered.Load() < int64(total) {
		if time.Now().After(deadline) {
			tb.Fatalf("delivered %d of %d packets", s.tunB.delivered.Load(), total)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := s.tunB.corrupt.Load(); n != 0 {
		tb.Fatalf("%d packets arrived damaged or out of order", n)
	}
}

// TestInboundBacklogMemory measures what a full receive backlog pins and
// checks the packets survive the wait. The bound is loose on purpose: past the
// slot budget a queued 1.4 KiB packet must cost a few KiB, not a 64 KiB slot.
func TestInboundBacklogMemory(t *testing.T) {
	for _, tc := range []struct {
		name string
		s4   int
	}{
		{"wireguard", 0},
		{"awg-s4", 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRxStand(t, tc.s4, 1380, 1, nil)
			r := s.runBacklog(t)
			perPacket := r.retained / uint64(r.queued)
			t.Logf("backlog: %d packets queued on the receiver, %d sent in all; heap grew by %.1f MiB (%d bytes per queued packet); read slot is %d bytes",
				r.queued, r.sent, float64(r.retained)/(1<<20), perPacket, MaxMessageSize)
			limit := uint64(inboundSlotBudget*MaxMessageSize) + uint64(r.queued)*(8<<10)
			if MaxMessageSize > inboundCompactSize && r.retained > limit {
				t.Errorf("the backlog pins %.1f MiB, over %.1f MiB: read slots went into the queue past the budget",
					float64(r.retained)/(1<<20), float64(limit)/(1<<20))
			}
		})
	}
}

// BenchmarkInboundTransport is the per-packet cost of the whole A → B path
// with a TUN that keeps up.
func BenchmarkInboundTransport(b *testing.B) {
	for _, tc := range []struct {
		name       string
		s4, length int
	}{
		{"wireguard-1380", 0, 1380},
		{"awg-s4-1380", 60, 1380},
		{"wireguard-64", 0, 64},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := newRxStand(b, tc.s4, tc.length, 1, nil)
			pkt := s.packet(0)
			b.SetBytes(int64(len(s.template)))
			b.ReportAllocs()
			b.ResetTimer()
			start := s.tunB.delivered.Load()
			for i := 0; i < b.N; i++ {
				binary.BigEndian.PutUint64(pkt[rxSeqOffset:], uint64(i)+1)
				for !s.inject(pkt) {
					runtime.Gosched()
				}
			}
			progress, since := int64(-1), time.Now()
			for {
				got := s.tunB.delivered.Load() - start
				if got >= int64(b.N) || s.tunB.corrupt.Load() != 0 {
					break
				}
				if got != progress {
					progress, since = got, time.Now()
				} else if time.Since(since) > 10*time.Second {
					b.Fatalf("delivered %d of %d packets and stopped; %d still queued on the sender",
						got, b.N, s.peerOnA.queuedOutboundPackets.Load())
				}
				runtime.Gosched()
			}
			b.StopTimer()
			if n := s.tunB.corrupt.Load(); n != 0 {
				b.Fatalf("%d packets arrived damaged or out of order", n)
			}
		})
	}
}
