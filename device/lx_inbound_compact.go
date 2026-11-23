/* SPDX-License-Identifier: MIT
 *
 * lx: packet-sized storage for queued inbound transport packets.
 *
 * A datagram is read into a MaxMessageSize slot, because one read may return
 * a coalesced batch. Upstream then hands that whole slot to the decryption and
 * inbound queues along with the packet, and takes a fresh slot for the next
 * read. A packet waiting for the TUN therefore pins about 64 KiB, whatever its
 * size, and a receive backlog of a few thousand packets costs hundreds of MiB.
 *
 * Here a device lets about inboundSlotBudget read slots travel with packets
 * at a time. While fewer are in flight, a packet crosses exactly as upstream,
 * without a copy. Past that, the receive routine keeps its slot and copies the
 * classified, unmasked transport message into a buffer of inboundCompactSize
 * bytes; only that buffer travels on. So the copy is paid when packets pile up
 * inside the device, which is when the consumer, not the receive routine, is
 * the slow side. The send path already sizes the buffers of injected packets
 * this way (GetOutboundBuffer).
 *
 * An element owns exactly one of the two buffers, so the two kinds share a
 * queue. Upstream's release sites are untouched: they still return elem.buffer
 * and then the element; a compact element has no buffer to return there and
 * gives its copy back in PutInboundElement.
 *
 * A read slot travels with the packet regardless of the budget when:
 *   - the TUN writes in batches or coalesces segments: it may merge packets in
 *     place and wants the slot's capacity behind the first packet;
 *   - the message does not fit in inboundCompactSize (a tunnel MTU above
 *     2016): such packets pin a slot each, as before;
 *   - the platform's read slots are already that small (Windows, iOS).
 * Handshake messages are not touched either; their queue carries slots.
 *
 * The compact pool carries the same accounting as messageBuffers, so a
 * platform with bounded pools keeps a bound on its queued packets.
 */

package device

import (
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
)

// inboundCompactSize is the capacity of a packet-sized inbound buffer: a
// transport message for any tunnel MTU up to 2016 bytes.
const inboundCompactSize = 2048

// populateInboundCompact sets up the compact pool and decides, once, whether
// this device may queue packet-sized buffers. The TUN does not change after
// NewDevice, so neither does the answer.
func (device *Device) populateInboundCompact() {
	device.pool.inboundCompact = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([inboundCompactSize]byte)
	})
	device.pool.compactInbound = MaxMessageSize > inboundCompactSize &&
		!tunWritesInPlace(device.tun.device)
}

// tunWritesInPlace reports whether the TUN may merge the packets of one Write
// in place, which takes the read slot's capacity behind the first packet.
func tunWritesInPlace(dev tun.Device) bool {
	if dev == nil {
		return false
	}
	if _, ok := dev.(tun.GRODevice); ok {
		return true
	}
	return dev.BatchSize() > 1
}

// inboundSlotBudget is how many read slots may travel with packets through
// the queues of one device before further packets are copied out instead: one
// read batch, shared by all its receive routines. It caps what a backlog of
// ordinary packets pins in slots at about 8 MiB.
const inboundSlotBudget = conn.IdealBatchSize

// stageInbound gives elem the storage it will carry through the queues.
// message is the transport message inside slot, header first. It reports
// whether elem took slot itself; if so the caller needs a new one.
//
// The budget check and the increment are not one step: receive routines
// running side by side can overshoot it by one slot each, which is harmless.
func (device *Device) stageInbound(elem *QueueInboundElement, slot *[MaxMessageSize]byte, message []byte) (tookSlot bool) {
	if device.pool.compactInbound {
		if len(message) <= inboundCompactSize && device.pool.inboundSlots.Load() >= inboundSlotBudget {
			compact := device.pool.inboundCompact.Get().(*[inboundCompactSize]byte)
			elem.compact = compact
			elem.packet = compact[:copy(compact[:], message)]
			return false
		}
		device.pool.inboundSlots.Add(1)
	}
	elem.buffer = slot
	elem.packet = message
	return true
}

// settleInbound closes the books on elem as it goes back to its pool. The
// caller has already returned elem.buffer, as upstream does; what is left is
// the compact copy, or the slot's place in the budget.
func (device *Device) settleInbound(elem *QueueInboundElement) {
	switch {
	case elem.compact != nil:
		device.pool.inboundCompact.Put(elem.compact)
	case elem.buffer != nil && device.pool.compactInbound:
		device.pool.inboundSlots.Add(-1)
	}
}

// tunFrame is what the TUN is given for a decrypted element: the transport
// header as headroom, then the plaintext. A compact buffer starts at the
// header; a read slot still has the transport padding in front of it.
func (elem *QueueInboundElement) tunFrame() []byte {
	end := MessageTransportOffsetContent + len(elem.packet)
	if elem.compact != nil {
		return elem.compact[:end]
	}
	start := int(elem.padding)
	return elem.buffer[start : start+end]
}
