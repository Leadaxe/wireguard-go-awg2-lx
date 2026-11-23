//go:build !windows && !ios

/* SPDX-License-Identifier: MIT
 *
 * lx: which buffer a queued inbound packet owns, and that the buffer and the
 * slot budget are given back on every way out (lx_inbound_compact.go). The
 * end-to-end stand lives in lx_rx_backlog_test.go.
 *
 * Windows and iOS read into slots that are already packet-sized, so nothing
 * is ever copied there and these tests have no subject.
 */

package device

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

// boundedPools gives dev the pool accounting of a mobile build.
func boundedPools(dev *Device, limit uint32) {
	dev.pool.messageBuffers = NewWaitPool(limit, func() any { return new([MaxMessageSize]byte) })
	dev.pool.inboundCompact = NewWaitPool(limit, func() any { return new([inboundCompactSize]byte) })
}

// putInbound releases elem the way every release site in the receive path
// does: the read slot first, then the element.
func putInbound(dev *Device, elem *QueueInboundElement) {
	dev.PutMessageBuffer(elem.buffer)
	dev.PutInboundElement(elem)
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

func newPoolDevice(t *testing.T, limit uint32) *Device {
	t.Helper()
	dev := new(Device)
	dev.PopulatePools()
	boundedPools(dev, limit)
	if !dev.pool.compactInbound {
		t.Fatal("a device without a merging TUN must be able to queue compact buffers")
	}
	return dev
}

func patternSlot(dev *Device) *[MaxMessageSize]byte {
	slot := dev.GetMessageBuffer()
	for i := range slot {
		slot[i] = byte(i)
	}
	return slot
}

// TestStageInbound covers the choice itself. Within the slot budget a packet
// takes the read slot, as upstream. Past it, a message that fits is copied and
// leaves the slot with the caller; one that does not fit takes the slot anyway.
func TestStageInbound(t *testing.T) {
	const padding = 60

	t.Run("within-budget", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		slot := patternSlot(dev)
		message := slot[padding : padding+1400]
		elem := dev.GetInboundElement()
		elem.padding = padding
		if !dev.stageInbound(elem, slot, message) {
			t.Fatal("the first packet must cross in its read slot, uncopied")
		}
		if elem.buffer != slot || elem.compact != nil || &elem.packet[0] != &slot[padding] {
			t.Fatal("the element must own the read slot and point into it")
		}
		if got := dev.pool.inboundSlots.Load(); got != 1 {
			t.Fatalf("slots in the queues = %d, want 1", got)
		}
		putInbound(dev, elem)
		if got := dev.pool.inboundSlots.Load(); got != 0 {
			t.Fatalf("slots in the queues = %d after release", got)
		}
		if got := poolCount(dev.pool.messageBuffers); got != 0 {
			t.Fatalf("read slots outstanding = %d after release", got)
		}
	})

	t.Run("past-budget-fits", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		dev.pool.inboundSlots.Store(inboundSlotBudget)
		slot := patternSlot(dev)
		message := slot[padding : padding+1400]
		want := bytes.Clone(message)
		elem := dev.GetInboundElement()
		elem.padding = padding
		if dev.stageInbound(elem, slot, message) {
			t.Fatal("a 1400-byte message took the read slot past the budget")
		}
		if elem.buffer != nil || elem.compact == nil {
			t.Fatal("the element must own a compact buffer only")
		}
		clear(slot[:]) // the next read reuses the slot
		if !bytes.Equal(elem.packet, want) {
			t.Fatal("the queued message still aliases the read slot")
		}
		// as after decryption: packet is the plaintext behind the header
		elem.packet = elem.packet[MessageTransportOffsetContent : MessageTransportOffsetContent+1000]
		frame := elem.tunFrame()
		if len(frame) != MessageTransportOffsetContent+1000 || &frame[0] != &elem.compact[0] {
			t.Fatalf("TUN frame is not the compact buffer from its start: len %d", len(frame))
		}
		if got := poolCount(dev.pool.inboundCompact); got != 1 {
			t.Fatalf("compact pool holds %d outstanding, want 1", got)
		}
		putInbound(dev, elem)
		if got := poolCount(dev.pool.inboundCompact); got != 0 {
			t.Fatalf("compact pool holds %d outstanding after release", got)
		}
		if got := poolCount(dev.pool.messageBuffers); got != 1 {
			t.Fatalf("read slots outstanding = %d, want the caller's 1", got)
		}
		if got := dev.pool.inboundSlots.Load(); got != inboundSlotBudget {
			t.Fatalf("a compact element moved the slot count to %d", got)
		}
	})

	t.Run("past-budget-too-large", func(t *testing.T) {
		dev := newPoolDevice(t, 8)
		dev.pool.inboundSlots.Store(inboundSlotBudget)
		slot := patternSlot(dev)
		message := slot[padding : padding+inboundCompactSize+1]
		elem := dev.GetInboundElement()
		elem.padding = padding
		if !dev.stageInbound(elem, slot, message) {
			t.Fatal("a message larger than a compact buffer must take the read slot")
		}
		if elem.buffer != slot || elem.compact != nil {
			t.Fatal("the element must own the read slot only")
		}
		elem.packet = elem.packet[MessageTransportOffsetContent : MessageTransportOffsetContent+2000]
		frame := elem.tunFrame()
		if &frame[0] != &slot[padding] || len(frame) != MessageTransportOffsetContent+2000 {
			t.Fatal("TUN frame must start behind the padding in the read slot")
		}
		if got := dev.pool.inboundSlots.Load(); got != inboundSlotBudget+1 {
			t.Fatalf("slots in the queues = %d, want %d", got, inboundSlotBudget+1)
		}
		putInbound(dev, elem)
		if got := dev.pool.inboundSlots.Load(); got != inboundSlotBudget {
			t.Fatalf("slots in the queues = %d after release, want %d", got, inboundSlotBudget)
		}
		if got := poolCount(dev.pool.messageBuffers); got != 0 {
			t.Fatalf("read slots outstanding = %d after release", got)
		}
	})
}

// TestStageInboundAllocs: the copy must not put an allocation on the
// per-packet path.
func TestStageInboundAllocs(t *testing.T) {
	dev := new(Device)
	dev.PopulatePools()
	dev.pool.inboundSlots.Store(inboundSlotBudget) // the copying path
	slot := dev.GetMessageBuffer()
	message := slot[:1432]
	// warm the pools
	elem := dev.GetInboundElement()
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
// still in it (the peer was removed) must give back their buffers and their
// place in the slot budget, on every platform, not only where pools are
// bounded.
func TestInboundQueueCleanup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit uint32 // 0: unbounded pools, as on linux and darwin
	}{
		{"unbounded-pools", 0},
		{"bounded-pools", 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := new(Device)
			dev.PopulatePools()
			if tc.limit != 0 {
				boundedPools(dev, tc.limit)
			}
			if !dev.needsInboundQueueFinalizer() {
				t.Fatal("a device that budgets read slots must clean up dropped queues")
			}
			func() {
				q := newAutodrainingInboundQueue(dev)
				// a bare Device has no bind to size a pooled container by
				container := new(QueueInboundElementsContainer)
				for i := 0; i < 3; i++ { // three in slots
					slot := dev.GetMessageBuffer()
					elem := dev.GetInboundElement()
					dev.stageInbound(elem, slot, slot[:1400])
					container.elems = append(container.elems, elem)
				}
				dev.pool.inboundSlots.Add(inboundSlotBudget) // and two copied
				slot := dev.GetMessageBuffer()
				for i := 0; i < 2; i++ {
					elem := dev.GetInboundElement()
					if dev.stageInbound(elem, slot, slot[:1400]) {
						t.Fatal("expected a compact copy past the budget")
					}
					container.elems = append(container.elems, elem)
				}
				dev.PutMessageBuffer(slot)
				dev.pool.inboundSlots.Add(-inboundSlotBudget)
				q.c <- container
			}()
			if got := dev.pool.inboundSlots.Load(); got != 3 {
				t.Fatalf("slots in the queue = %d, want 3", got)
			}
			eventually(t, "the dropped queue is flushed", func() bool {
				runtime.GC()
				return dev.pool.inboundSlots.Load() == 0
			})
			if tc.limit != 0 {
				if got := poolCount(dev.pool.messageBuffers); got != 0 {
					t.Fatalf("%d read slots never came back", got)
				}
				if got := poolCount(dev.pool.inboundCompact); got != 0 {
					t.Fatalf("%d compact buffers never came back", got)
				}
			}
		})
	}
}

// TestInboundStoppedPeer: packets for a peer that is not running are dropped
// in the receive routine; that way out must settle the budget too.
func TestInboundStoppedPeer(t *testing.T) {
	s := newRxStand(t, 60, 1380, 1, func(devB *Device) { boundedPools(devB, 512) })
	before := s.tunB.delivered.Load()
	s.peerOnB.Stop()
	for seq := uint64(1); seq <= 200; seq++ {
		for !s.inject(s.packet(seq)) {
			time.Sleep(time.Millisecond)
		}
	}
	eventually(t, "the sender has drained", func() bool { return s.peerOnA.queuedOutboundPackets.Load() == 0 })
	eventually(t, "the receiver holds only its read slot", func() bool {
		return poolCount(s.devB.pool.messageBuffers) == 1 &&
			poolCount(s.devB.pool.inboundCompact) == 0 &&
			s.devB.pool.inboundSlots.Load() == 0
	})
	if got := s.tunB.delivered.Load(); got != before {
		t.Fatalf("a stopped peer delivered %d packets", got-before)
	}
}

// TestInboundTunCapacity: under a backlog, a TUN that takes one packet at a
// time is handed compact buffers; one that writes in batches only ever sees
// read slots, whose capacity it may merge into.
func TestInboundTunCapacity(t *testing.T) {
	const s4 = 60
	for _, tc := range []struct {
		name    string
		batch   int
		compact bool
	}{
		{"single-packet-tun", 1, true},
		{"batched-tun", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRxStand(t, s4, 1380, tc.batch, nil)
			if s.devB.pool.compactInbound != tc.compact {
				t.Fatalf("compactInbound = %v, want %v", s.devB.pool.compactInbound, tc.compact)
			}
			s.tunB.minCap.Store(1 << 62)
			s.runBacklog(t)
			got := s.tunB.minCap.Load()
			if tc.compact && got != inboundCompactSize {
				t.Fatalf("TUN was handed a smallest buffer of capacity %d, want a compact %d", got, inboundCompactSize)
			}
			if !tc.compact && got < MaxMessageSize-s4 {
				t.Fatalf("batched TUN was handed capacity %d, want the read slot's %d", got, MaxMessageSize-s4)
			}
			eventually(t, "no read slot is counted in the queues", func() bool {
				return s.devB.pool.inboundSlots.Load() == 0
			})
		})
	}
}

// TestInboundBoundedPools runs the backlog with mobile-style pool limits: the
// receiver must stop at the limit instead of growing, deliver everything once
// the TUN opens, and end with every buffer back in its pool.
func TestInboundBoundedPools(t *testing.T) {
	const limit = 64
	s := newRxStand(t, 60, 1380, 1, func(devB *Device) {
		boundedPools(devB, limit)
		// room for the slot budget and the reader's own slot, so that the
		// compact pool is the limit the backlog runs into
		devB.pool.messageBuffers = NewWaitPool(inboundSlotBudget+limit, func() any { return new([MaxMessageSize]byte) })
	})
	r := s.runBacklog(t)
	if r.held != limit {
		t.Fatalf("receiver stalled with %d compact buffers out, want its limit of %d", r.held, limit)
	}
	t.Logf("bounded: receiver stopped with %d compact buffers out, heap grew by %.2f MiB, %d sent in all",
		r.held, float64(r.retained)/(1<<20), r.sent)
	eventually(t, "every buffer is back in its pool", func() bool {
		// one receive routine, one read slot
		return poolCount(s.devB.pool.inboundCompact) == 0 &&
			poolCount(s.devB.pool.messageBuffers) == 1 &&
			s.devB.pool.inboundSlots.Load() == 0
	})
}
