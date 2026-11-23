//go:build linux || darwin

/* SPDX-License-Identifier: MIT
 *
 * lx: packet-sized buffers for queued transport packets (lx_packet_sized.go):
 * which buffer a queued packet holds in each direction, and that every buffer
 * is given back on every way out. The stand is in lx_backlog_stand_test.go.
 *
 * Windows and iOS read into buffers that are already packet-sized on the
 * receive side, so half of this has no subject there.
 */

package device

import (
	"bytes"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func poolCount(p *WaitPool) uint32 {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.count
}

// boundedPools gives dev the pool accounting of a mobile build.
func boundedPools(dev *Device, limit uint32) {
	dev.pool.messageBuffers = NewWaitPool(limit, func() any { return new([MaxMessageSize]byte) })
	dev.sizing.compactPool = NewWaitPool(limit, func() any { return new([compactSize]byte) })
}

// eventually polls cond until it holds; the receive path releases a packet's
// buffers just after the TUN write returns, on its own goroutine.
func eventually(tb testing.TB, what string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// bareDevice is a Device with its pools and nothing running, behind a TUN that
// takes one packet at a time.
func bareDevice() *Device {
	dev := new(Device)
	dev.tun.device = newChanTun()
	dev.PopulatePools()
	return dev
}

func newPoolDevice(t *testing.T, limit uint32) *Device {
	t.Helper()
	dev := bareDevice()
	boundedPools(dev, limit)
	if !dev.sizing.inbound {
		t.Fatal("a device without a batching TUN must queue packet-sized buffers")
	}
	return dev
}

// stagedElement is an element as the receive routine queues it, and the read
// slot it was read into when the element did not take it.
func stagedElement(dev *Device, padding, messageLen int) (elem *QueueInboundElement, kept *[MaxMessageSize]byte) {
	slot := dev.GetMessageBuffer()
	for i := range slot {
		slot[i] = byte(i)
	}
	elem = dev.GetInboundElement()
	elem.padding = uint32(padding)
	if dev.stageInbound(elem, slot, slot[padding:padding+messageLen]) {
		return elem, nil
	}
	return elem, slot
}

// putInbound releases elem the way every release site in the receive path
// does: the read slot first, then the element.
func putInbound(dev *Device, elem *QueueInboundElement) {
	dev.PutMessageBuffer(elem.buffer)
	dev.PutInboundElement(elem)
}

func wantPools(t *testing.T, dev *Device, slots, compact uint32, when string) {
	t.Helper()
	if got := poolCount(dev.pool.messageBuffers); got != slots {
		t.Fatalf("%s: %d read slots out, want %d", when, got, slots)
	}
	if got := poolCount(dev.sizing.compactPool); got != compact {
		t.Fatalf("%s: %d packet-sized buffers out, want %d", when, got, compact)
	}
}

// TestInboundElementBuffers covers which buffer a queued element holds.
func TestInboundElementBuffers(t *testing.T) {
	const padding = 60

	t.Run("fits", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		elem, slot := stagedElement(dev, padding, 1432)
		if slot == nil || elem.buffer != nil || elem.compact == nil {
			t.Fatal("a message that fits must be queued in a packet-sized buffer, the read slot left with the caller")
		}
		want := bytes.Clone(slot[padding : padding+1432])
		clear(slot[:]) // the next read reuses the slot
		if !bytes.Equal(elem.packet, want) {
			t.Fatal("the queued message still aliases the read slot")
		}
		wantPools(t, dev, 1, 1, "queued")

		// as after decryption in place: packet is the plaintext behind the header
		elem.packet = elem.packet[MessageTransportOffsetContent : MessageTransportOffsetContent+1400]
		frame := elem.tunFrame()
		if len(frame) != MessageTransportOffsetContent+1400 || &frame[0] != &elem.compact[0] {
			t.Fatalf("TUN frame is not the packet-sized buffer from its start: len %d", len(frame))
		}
		putInbound(dev, elem)
		wantPools(t, dev, 1, 0, "released")
		dev.PutMessageBuffer(slot)
	})

	t.Run("largest", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		elem, slot := stagedElement(dev, padding, compactSize)
		if slot == nil || len(elem.packet) != compactSize {
			t.Fatal("a message of exactly the buffer size must be queued in one, whole")
		}
		putInbound(dev, elem)
		dev.PutMessageBuffer(slot)
		wantPools(t, dev, 0, 0, "released")
	})

	t.Run("too-large", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		elem, slot := stagedElement(dev, padding, compactSize+1)
		if slot != nil || elem.compact != nil || elem.buffer == nil {
			t.Fatal("a message larger than a packet-sized buffer must take its read slot")
		}
		if &elem.packet[0] != &elem.buffer[padding] {
			t.Fatal("an element in a read slot points into it, uncopied")
		}
		elem.packet = elem.packet[MessageTransportOffsetContent : MessageTransportOffsetContent+2000]
		frame := elem.tunFrame()
		if &frame[0] != &elem.buffer[padding] || len(frame) != MessageTransportOffsetContent+2000 {
			t.Fatal("TUN frame must start behind the padding in the read slot")
		}
		putInbound(dev, elem)
		wantPools(t, dev, 0, 0, "released")
	})
}

// TestInboundStagingAllocs: nothing on the per-packet path allocates.
func TestInboundStagingAllocs(t *testing.T) {
	dev := bareDevice()
	slot := dev.GetMessageBuffer()
	message := slot[:1432]
	elem := dev.GetInboundElement() // warm the pools
	dev.stageInbound(elem, slot, message)
	putInbound(dev, elem)
	allocs := testing.AllocsPerRun(1000, func() {
		elem := dev.GetInboundElement()
		dev.stageInbound(elem, slot, message)
		putInbound(dev, elem)
	})
	if allocs != 0 {
		t.Fatalf("staging a packet allocates %.1f times", allocs)
	}
}

// TestInboundQueueCleanup: a peer's inbound queue that is dropped with packets
// still in it (the peer was removed) gives back every buffer of a bounded
// pool, packet-sized or not.
func TestInboundQueueCleanup(t *testing.T) {
	dev := newPoolDevice(t, 64)
	var kept []*[MaxMessageSize]byte
	func() {
		q := newAutodrainingInboundQueue(dev)
		// a bare Device has no bind to size a pooled container by
		container := new(QueueInboundElementsContainer)
		for _, messageLen := range []int{1432, 1432, 1432, compactSize + 1, compactSize + 1} {
			elem, slot := stagedElement(dev, 0, messageLen)
			if slot != nil {
				kept = append(kept, slot)
			}
			container.elems = append(container.elems, elem)
		}
		q.c <- container
	}()
	for _, slot := range kept { // the receive routine's own slots
		dev.PutMessageBuffer(slot)
	}
	wantPools(t, dev, 2, 3, "queued")
	eventually(t, "the dropped queue is flushed", func() bool {
		runtime.GC()
		return poolCount(dev.pool.messageBuffers) == 0 && poolCount(dev.sizing.compactPool) == 0
	})
}

// TestInboundStoppedPeer: packets for a peer that is not running are dropped
// in the receive routine, with both of their buffers.
func TestInboundStoppedPeer(t *testing.T) {
	s := newStand(t, 60, 1380, 1, func(devB *Device) { boundedPools(devB, 512) })
	before := s.tunB.writes.Load()
	s.peerOnB.Stop()
	for seq := uint64(1); seq <= 200; seq++ {
		for s.peerOnA.queuedOutboundPackets.Load() >= 256 {
			time.Sleep(time.Millisecond)
		}
		s.inject(s.packet(seq))
	}
	eventually(t, "the sender has drained", func() bool { return s.peerOnA.queuedOutboundPackets.Load() == 0 })
	eventually(t, "the receiver holds only its read slot", func() bool {
		return poolCount(s.devB.pool.messageBuffers) == 1 && poolCount(s.devB.sizing.compactPool) == 0
	})
	if got := s.tunB.writes.Load(); got != before {
		t.Fatalf("a stopped peer delivered %d packets", got-before)
	}
}

// TestBacklogPacketSized: a full backlog costs about a packet per packet in
// both directions, and the packets survive the wait. The bounds are loose on
// purpose: a queued 1.4 KiB packet must cost a few KiB, not a 64 KiB buffer.
func TestBacklogPacketSized(t *testing.T) {
	if standUDP() {
		t.Skip("bounds are for the in-memory bind")
	}
	if testing.Short() {
		t.Skip("floods the pipeline until it stalls")
	}
	const perPacket = 6 << 10
	check := func(t *testing.T, r standBacklog) {
		t.Helper()
		t.Log(r)
		if r.queued < 1000 {
			t.Fatalf("only %d packets queued: the stand did not build a backlog", r.queued)
		}
		if limit := uint64(r.queued) * perPacket; r.retained > limit {
			t.Errorf("the backlog pins %.1f MiB, over %.1f MiB: full-size buffers are waiting in the queues",
				float64(r.retained)/(1<<20), float64(limit)/(1<<20))
		}
	}
	for _, s4 := range []int{0, 60} {
		name := "wireguard"
		if s4 != 0 {
			name = "awg-s4"
		}
		t.Run("rx/"+name, func(t *testing.T) {
			s := newStand(t, s4, 1380, 1, nil)
			check(t, s.runRxBacklog(t, nil))
			if MaxMessageSize > compactSize {
				if got := s.tunB.minCap.Load(); got != compactSize {
					t.Fatalf("TUN was handed a smallest buffer of capacity %d, want a packet-sized %d", got, compactSize)
				}
			}
		})
		t.Run("tx/"+name, func(t *testing.T) {
			s := newStand(t, s4, 1380, 1, nil)
			check(t, s.runTxBacklog(t))
		})
	}
}

// TestBatchedTunKeepsFullBuffers: a TUN that moves packets in batches only
// ever sees read slots, whose capacity it may merge into, and is read into
// full-size buffers, because one read may return more than its MTU.
func TestBatchedTunKeepsFullBuffers(t *testing.T) {
	const s4 = 60
	s := newStand(t, s4, 1380, 2, nil)
	if s.devB.sizing.inbound || s.devB.sizing.tunRead.Load() {
		t.Fatal("a device behind a batching TUN must keep full-size buffers in both directions")
	}
	if got := s.devB.tunReadSize(s4); got != MaxMessageSize {
		t.Fatalf("TUN read buffer is %d bytes, want %d", got, MaxMessageSize)
	}
	s.runRxBacklog(t, nil)
	if got := s.tunB.minCap.Load(); got < MaxMessageSize-s4 {
		t.Fatalf("batched TUN was handed capacity %d, want the read slot's %d", got, MaxMessageSize-s4)
	}
}

// TestInboundBoundedPools runs the backlog with mobile-style pool limits: the
// receiver must stop at the limit instead of growing, deliver everything once
// the TUN opens, and end with every buffer back in its pool.
func TestInboundBoundedPools(t *testing.T) {
	if standUDP() {
		t.Skip("exact counts need the in-memory bind")
	}
	const limit = 64
	s := newStand(t, 60, 1380, 1, func(devB *Device) { boundedPools(devB, limit) })
	var held uint32
	r := s.runRxBacklog(t, func() { held = poolCount(s.devB.sizing.compactPool) })
	t.Logf("bounded: %v", r)
	if held != limit {
		t.Fatalf("receiver stalled with %d packet-sized buffers out, want its limit of %d", held, limit)
	}
	eventually(t, "every buffer is back in its pool", func() bool {
		// one receive routine, one read slot
		return poolCount(s.devB.sizing.compactPool) == 0 && poolCount(s.devB.pool.messageBuffers) == 1
	})
}

// TestInboundOversizeMessage: a message that does not fit a packet-sized
// buffer crosses in its read slot, intact.
func TestInboundOversizeMessage(t *testing.T) {
	if MaxMessageSize <= compactSize {
		t.Skip("read slots are packet-sized on this platform")
	}
	s := newStand(t, 60, 2100, 1, nil)
	for seq := uint64(1); seq <= 50; seq++ {
		s.inject(s.packet(seq))
		s.sent.Store(int64(seq))
	}
	s.awaitDelivered(t)
	if got := s.tunB.minCap.Load(); got <= compactSize {
		t.Fatalf("a %d-byte packet was handed over in a buffer of capacity %d", len(s.template), got)
	}
}

// TestTunReadSize: the read loop allocates for the MTU in the layout
// RoutineEncryption builds, and grows with the padding.
func TestTunReadSize(t *testing.T) {
	s := newStand(t, 0, 1380, 1, nil)
	dev := s.devA
	if !dev.sizing.tunRead.Load() {
		t.Fatal("a device behind a one-packet TUN must size its read buffers")
	}
	mtu := int(dev.tun.mtu.Load())
	plain := dev.tunReadSize(0)
	if _, offset, alloc := dev.outboundLayout(mtu); plain != alloc || plain < offset+mtu {
		t.Fatalf("read buffer is %d bytes; the injection path allocates %d for an MTU-sized packet", plain, alloc)
	}
	if plain > 2048 {
		t.Fatalf("read buffer for MTU %d is %d bytes", mtu, plain)
	}
	if padded := dev.tunReadSize(200); padded != plain+200 {
		t.Fatalf("read buffer under 200 bytes of padding is %d, want %d", padded, plain+200)
	}
}

// TestTunReadStalePadding: the TUN reader is already waiting in Read, with
// buffers sized for no padding, when the device is first configured. The
// packet it then returns must be moved to a buffer that fits the padding, not
// dropped: every MTU-sized packet crosses, the first one included.
func TestTunReadStalePadding(t *testing.T) {
	s := newStand(t, 60, 1400, 1, nil) // an MTU-sized packet
	for seq := uint64(1); seq <= 10; seq++ {
		s.tunA.toDevice <- s.packet(seq)
		s.sent.Store(int64(seq))
	}
	s.awaitDelivered(t)
}

// TestTunReadFollowsPadding: raising the transport padding at runtime moves
// the read loop to larger buffers, and full-size packets keep crossing.
func TestTunReadFollowsPadding(t *testing.T) {
	s := newStand(t, 0, 1400, 1, nil) // an MTU-sized packet
	s.tunB.lossy = true               // packets in flight across the change are dropped
	for _, dev := range []*Device{s.devA, s.devB} {
		if err := dev.IpcSet("s4=300\n"); err != nil {
			t.Fatal(err)
		}
	}
	feedUntilDelivered(t, s, 20)
}

// TestTunReadOverrun: a TUN that returns a packet larger than its MTU costs
// that packet, and the device reads into full-size buffers from then on.
func TestTunReadOverrun(t *testing.T) {
	s := newStand(t, 0, 1780, 1, nil) // 1800 bytes over an MTU of 1420
	s.tunB.lossy = true
	feedUntilDelivered(t, s, 20)
	if s.devA.sizing.tunRead.Load() {
		t.Fatal("the device must stop sizing read buffers after an oversized read")
	}
	if got := s.devA.tunReadSize(0); got != MaxMessageSize {
		t.Fatalf("read buffer is %d bytes after an oversized read, want %d", got, MaxMessageSize)
	}
}

// feedUntilDelivered pushes packets through A's TUN until n have arrived
// intact at B.
func feedUntilDelivered(t *testing.T, s *stand, n int64) {
	t.Helper()
	start := s.tunB.delivered.Load()
	deadline := time.Now().Add(15 * time.Second)
	for seq := uint64(1); s.tunB.delivered.Load()-start < n; seq++ {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d packets crossed", s.tunB.delivered.Load()-start, n)
		}
		s.tunA.toDevice <- s.packet(seq)
		time.Sleep(5 * time.Millisecond)
	}
	if c := s.tunB.corrupt.Load(); c != 0 {
		t.Fatalf("%d packets arrived damaged or out of order", c)
	}
}

// mergingTun says, like sing-box's device with a return path attached, that
// what it is written may be coalesced in place.
type mergingTun struct {
	*standSinkTun
	merges atomic.Bool
}

func (t *mergingTun) MergesWrites() bool { return t.merges.Load() }

// TestWriteMergerKeepsSlots: while the TUN says it merges writes, inbound
// packets keep their read slots; when it stops, they are packet-sized again.
func TestWriteMergerKeepsSlots(t *testing.T) {
	if MaxMessageSize <= compactSize {
		t.Skip("read slots are packet-sized on this platform")
	}
	dev := new(Device)
	tunDev := &mergingTun{standSinkTun: &standSinkTun{chanTun: newChanTun()}}
	dev.tun.device = tunDev
	dev.PopulatePools()
	if !dev.sizing.inbound {
		t.Fatal("a one-packet TUN must allow packet-sized inbound buffers")
	}
	tunDev.merges.Store(true)
	elem, slot := stagedElement(dev, 0, 1432)
	if slot != nil || elem.compact != nil {
		t.Fatal("a packet for a merging TUN must keep its read slot")
	}
	putInbound(dev, elem)
	tunDev.merges.Store(false)
	elem, slot = stagedElement(dev, 0, 1432)
	if slot == nil || elem.compact == nil {
		t.Fatal("a packet for a TUN that stopped merging must be packet-sized")
	}
	putInbound(dev, elem)
	dev.PutMessageBuffer(slot)
}

// TestTunReadStaleMTU: a packet that fills a buffer sized for an MTU that has
// since grown is dropped, but the device keeps sizing its read buffers.
func TestTunReadStaleMTU(t *testing.T) {
	s := newStand(t, 0, 1380, 1, nil)
	dev := s.devA
	stale := dev.tunReadSize(0)
	dev.tun.mtu.Store(1800)
	if !dev.tunReadOverran(stale, stale, 0) {
		t.Fatal("a packet that fills a stale buffer must be dropped")
	}
	if !dev.sizing.tunRead.Load() {
		t.Fatal("a stale buffer is not the TUN breaking its MTU")
	}
	if got := dev.tunReadSize(0); got <= stale {
		t.Fatalf("read buffer for MTU 1800 is %d, not above %d", got, stale)
	}
}
