/* SPDX-License-Identifier: MIT
 *
 * lx: packet-sized buffers for queued transport packets, in both directions.
 *
 * Upstream reads every datagram and every TUN packet into a MaxMessageSize
 * buffer (64 KiB on Linux, macOS, Android), because one read may return a
 * coalesced batch, and that buffer then travels with the packet through the
 * crypto queue and the peer's sequential queue. A 1.4 KiB packet waiting there
 * pins 64 KiB, so a backlog of a few thousand packets costs hundreds of MiB.
 *
 * Inbound. The receive routine cannot know a datagram's size before it reads,
 * so it keeps reading into full slots. A transport message that fits is then
 * copied into a packet-sized ("compact") buffer, which is what goes into the
 * queues; the slot never leaves the receive routine and is read into again.
 * Decryption runs in place in the compact buffer, as it did in the slot.
 *
 * The copy is one pass over about 1.4 KiB. On a router-class CPU it is paid
 * back by the slot staying in cache: upstream takes a cold 64 KiB slot from
 * the pool for every packet. Measured on a Cortex-A55; the numbers are in the
 * sing-box-lx spec WG_QUEUED_PACKET_BUFFERS.
 *
 * The slot travels with the packet, as upstream, when
 *   - the TUN writes in batches or coalesces segments, or says it currently
 *     hands written packets to something that does (MergesWrites): a merge
 *     happens in place and wants the capacity behind the first packet,
 *   - the message does not fit a compact buffer: more than 2048 bytes on the
 *     wire, transport padding aside,
 *   - the platform's read slots are already that small (Windows, iOS).
 * Handshake messages are not touched: they are few and short-lived.
 *
 * The compact pool has the accounting of messageBuffers, and like that pool
 * it is taken from by the receive routine only, so a bounded platform keeps
 * its backpressure where upstream has it and nothing downstream can wait for
 * a buffer held further downstream.
 *
 * Outbound. A TUN that hands over one packet per read never returns more than
 * its MTU, so the read loop allocates for the MTU plus what RoutineEncryption
 * builds around the plaintext, the same layout the injection path
 * (InputPacket) uses. Nothing is copied. A TUN that reads in batches may
 * return a segmented super-packet and keeps full-size buffers. If a TUN ever
 * fills a sized buffer, so that the packet may be cut short and has no room
 * for the tag, that packet is dropped and the device goes back to full-size
 * read buffers for good; a buffer that is merely stale, because the MTU just
 * grew, costs the packet only.
 *
 * A full-size buffer also had room to shift a packet when the transport
 * padding (s4) was raised while the packet was in flight. A sized one does
 * not, so RoutineEncryption moves such a packet into a larger buffer.
 */

package device

import (
	"sync/atomic"

	"github.com/sagernet/wireguard-go/tun"

	"golang.org/x/crypto/chacha20poly1305"
)

// compactSize is the capacity of a compact buffer, the packet-sized buffer an
// inbound transport message waits in. It holds a message of up to that many
// bytes on the wire, transport padding aside: a plaintext of at most 2016
// bytes, which covers every tunnel MTU in common use with one size class.
const compactSize = 2048

// packetSizing is the device's state for this file. Everything but tunRead is
// set once, in PopulatePools, before any routine of the device starts, and is
// read-only afterwards.
type packetSizing struct {
	// compactPool has the accounting of pool.messageBuffers, so that a
	// platform with bounded pools bounds a backlog of compact buffers too.
	compactPool *WaitPool
	// inbound is whether transport messages are queued in compact buffers at
	// all: not when the TUN batches, and not when read slots are already small.
	inbound bool
	// merger is the TUN, if it can tell at runtime that it merges writes.
	merger writeMerger
	// tunRead is whether TUN read buffers are sized for the MTU. The read
	// loop turns it off for good when the TUN breaks its MTU.
	tunRead atomic.Bool
}

// writeMerger is implemented by a TUN that may hand the packets it is written
// to something that coalesces them in place, although it takes one packet per
// call itself: sing-box's WireGuard device while a return path to a GSO TUN is
// attached. The answer may change during the device's life, so it is asked
// per packet.
type writeMerger interface {
	MergesWrites() bool
}

func (device *Device) populatePacketSizing() {
	sizing := &device.sizing
	sizing.compactPool = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([compactSize]byte)
	})
	batched := tunBatches(device.tun.device)
	sizing.inbound = MaxMessageSize > compactSize && !batched
	sizing.merger, _ = device.tun.device.(writeMerger)
	sizing.tunRead.Store(!batched)
}

// tunBatches reports whether dev moves several packets per call. Such a TUN
// may merge written packets in place, using the capacity behind each one, and
// may return segments of a super-packet larger than its MTU from one read, so
// it needs full-size buffers in both directions.
func tunBatches(dev tun.Device) bool {
	if _, ok := dev.(tun.GRODevice); ok {
		return true
	}
	return dev.BatchSize() > 1
}

// stageInbound puts `message`, which was read into `slot`, on elem, and
// reports whether elem took the slot. If it did not, the message was copied
// into a compact buffer and the caller keeps reading into the slot.
//
// It is called by the receive routine only. That is where upstream waits for
// a read slot, so a bounded compact pool applies its backpressure at the same
// point, and nothing downstream ever waits for a buffer.
func (device *Device) stageInbound(elem *QueueInboundElement, slot *[MaxMessageSize]byte, message []byte) (tookSlot bool) {
	if device.sizing.inbound && len(message) <= compactSize && !device.tunMergesWrites() {
		compact := device.sizing.compactPool.Get().(*[compactSize]byte)
		elem.compact = compact
		elem.packet = compact[:copy(compact[:], message)]
		return false
	}
	elem.buffer = slot
	elem.packet = message
	return true
}

func (device *Device) tunMergesWrites() bool {
	merger := device.sizing.merger
	return merger != nil && merger.MergesWrites()
}

// settleInbound returns the buffer PutInboundElement's callers do not know
// about. They return the read slot themselves, as upstream wrote them; routing
// the compact buffer through the one function every release path ends in
// means a release site added upstream later cannot leak it.
func (device *Device) settleInbound(elem *QueueInboundElement) {
	if elem.compact != nil {
		device.sizing.compactPool.Put(elem.compact)
	}
}

// tunFrame is what the TUN is given for a decrypted element: the plaintext
// with MessageTransportOffsetContent bytes of headroom in front, where the
// transport header was.
func (elem *QueueInboundElement) tunFrame() []byte {
	end := MessageTransportOffsetContent + len(elem.packet)
	if elem.compact != nil {
		return elem.compact[:end]
	}
	// in a read slot the message sits behind the transport padding, which is
	// left where it arrived
	start := int(elem.padding)
	return elem.buffer[start : start+end]
}

// outboundBufferSize is the buffer an outbound element needs for a plaintext
// that ends at `end`: the AEAD tag and the bytes RoutineEncryption appends
// before sealing. The injection path computes the same in outboundLayout.
func (device *Device) outboundBufferSize(end int) int {
	return min(end+chacha20poly1305.Overhead+device.outboundTailroom(end), MaxMessageSize)
}

// DisablePacketSizedTunReads makes the TUN read loop take full-size buffers,
// as upstream does. It is a diagnostic switch (sing-box-lx
// lx.wg.buffers.send_by_mtu): it takes sized read buffers out of the picture
// without rebuilding. The loop checks the size before every read, so the
// change applies from the next packet; there is no way back, as there is none
// after the TUN broke its MTU.
//
// Inbound messages keep their compact buffers either way.
func (device *Device) DisablePacketSizedTunReads() {
	device.sizing.tunRead.Store(false)
}

// tunReadSize is the buffer a TUN read needs under transport padding
// `padding`: room for one MTU-sized packet, or MaxMessageSize when the TUN
// may return more than that. The padding is the caller's, not the device's
// current one, so that the size matches the offset the caller reads at.
func (device *Device) tunReadSize(padding uint32) int {
	if !device.sizing.tunRead.Load() {
		return MaxMessageSize
	}
	offset := MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize
	return device.outboundBufferSize(offset + int(device.tun.mtu.Load()))
}

// newTunReadElement is NewOutboundElement with a buffer of `size` bytes;
// upstream's always takes MaxMessageSize.
func (device *Device) newTunReadElement(size int) *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetOutboundBuffer(size)
	elem.nonce = 0
	elem.padding = device.paddings.transport.Load()
	elem.isKeepalive = false
	return elem
}

// resizeTunRead replaces the read loop's buffers after the MTU or the padding
// grew past what they were allocated for. They are idle between reads, so
// nothing is lost.
func (device *Device) resizeTunRead(elems []*QueueOutboundElement, bufs [][]byte, size int) {
	for i, elem := range elems {
		device.PutOutboundBuffer(elem.buffer)
		elem.buffer = device.GetOutboundBuffer(size)
		bufs[i] = elem.buffer
	}
}

// tunReadOverran reports a packet that fills its sized read buffer and must
// be dropped: it may be cut short, and there is no room for the tag.
//
// Two things look like this. If the buffer is still what the MTU and
// `padding` call for, the TUN returned more than its MTU; it cannot be
// trusted again, so the device stops sizing read buffers. Otherwise the MTU
// has just grown, the buffer was merely stale, and the next read gets a
// larger one.
func (device *Device) tunReadOverran(end, size int, padding uint32) bool {
	if size == MaxMessageSize || end+chacha20poly1305.Overhead <= size {
		return false
	}
	if device.tunReadSize(padding) > size {
		return true
	}
	if device.sizing.tunRead.CompareAndSwap(true, false) {
		device.log.Errorf("TUN returned a packet larger than its MTU; reading into full-size buffers from now on")
	}
	return true
}

// regrowOutbound moves elem's packet into a buffer that holds it at `offset`,
// and reports false when no datagram can.
//
// RoutineEncryption shifts a packet in place when it was read under a smaller
// transport padding than the device has now: reconfigured while the packet
// was in flight, or the TUN reader was already waiting in Read. A full-size
// buffer always had room for the shift; a sized one may not.
func (device *Device) regrowOutbound(elem *QueueOutboundElement, offset int) bool {
	end := offset + len(elem.packet)
	if end+chacha20poly1305.Overhead > MaxMessageSize {
		return false
	}
	grown := device.GetOutboundBuffer(device.outboundBufferSize(end))
	copy(grown[offset:], elem.packet)
	device.PutOutboundBuffer(elem.buffer)
	elem.buffer = grown
	elem.packet = grown[offset:end]
	return true
}
