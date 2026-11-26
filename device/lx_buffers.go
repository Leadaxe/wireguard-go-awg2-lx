/* SPDX-License-Identifier: MIT
 *
 * lx: buffers of queued packets on top of upstream's packetBuf model
 * (sing-box-lx SPEC 158, line 1.15).
 *
 * Upstream reads a TUN batch and a receive batch into one shared slab and
 * copies a packet that fits into a 2 KiB "small" buffer before it is queued
 * (outbound always where a small pool exists, inbound on darwin/ios only).
 * Three things are ours on top of that:
 *
 *   - AmneziaWG layout. Upstream's headroom (24) and tailroom (31) are fixed,
 *     and packets of one batch sit 64 bytes apart in a shared slab. An AWG
 *     datagram needs the transport padding (S4) in front of the header and,
 *     under AWG 3.x, a content padding addition or random trailer behind the
 *     plaintext. Written into a shared slab they would land in the neighbouring
 *     packet. So while the AWG layout is in use every outbound packet sits in a
 *     buffer of its own: the copy upstream already makes goes to an offset
 *     behind S4 and keeps room for the tail, into a small buffer when that fits
 *     and a sized one otherwise. Plain WireGuard keeps upstream's path as is.
 *
 *   - lx.wg.buffers.send_by_mtu (SetTunReadsByMTU). Off: upstream's read into
 *     the shared slab plus the copy. On, for a TUN that hands over one packet
 *     per read: the TUN reads straight into a buffer of the packet's own,
 *     sized for the MTU and the AWG layout, and nothing is copied.
 *
 *   - lx.wg.buffers.receive_copy (SetReceiveCopy). auto: upstream (copy a
 *     transport message into a small buffer on darwin/ios); memory: on every
 *     platform; speed: nowhere. A TUN that merges written packets in place
 *     keeps the slab either way: the merge wants the capacity behind the
 *     first packet.
 */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/sagernet/wireguard-go/tun"

	"golang.org/x/crypto/chacha20poly1305"
)

// Receive copy modes (sing-box-lx lx.wg.buffers.receive_copy).
const (
	ReceiveCopyMemory int32 = iota // copy into a small buffer on every platform (default)
	ReceiveCopyAuto                // as upstream: darwin/ios only
	ReceiveCopySpeed               // never copy
)

type lxBufferState struct {
	receiveCopy atomic.Int32
	tunByMTU    atomic.Bool
	// mtuBufs pools the buffers the TUN reads into under send_by_mtu; mtuSize
	// is the slab size they were made for, a buffer of another size is dropped.
	mtuBufs sync.Pool
	mtuSize atomic.Int32
	// merger is the TUN, if it can tell at runtime that it merges writes.
	merger writeMerger
}

// writeMerger is implemented by a TUN that may hand the packets it is written
// to something that coalesces them in place, although it takes one packet per
// call itself: sing-box's WireGuard device while a return path to a GSO TUN is
// attached. The answer may change during the device's life, so it is asked
// per packet.
type writeMerger interface {
	MergesWrites() bool
}

// SetReceiveCopy sets lx.wg.buffers.receive_copy; it applies from the next read.
func (device *Device) SetReceiveCopy(mode int32) {
	device.lxBuffers.receiveCopy.Store(mode)
}

// SetTunReadsByMTU sets lx.wg.buffers.send_by_mtu; it applies from the next read.
func (device *Device) SetTunReadsByMTU(enabled bool) {
	device.lxBuffers.tunByMTU.Store(enabled)
}

func (device *Device) initLXBuffers() {
	device.lxBuffers.merger, _ = device.tun.device.(writeMerger)
}

// tunMergesWrites reports whether written packets may be coalesced in place.
func (device *Device) tunMergesWrites() bool {
	if _, ok := device.tun.device.(tun.GRODevice); ok {
		return true
	}
	merger := device.lxBuffers.merger
	return merger != nil && merger.MergesWrites()
}

// copyTransport reports whether a transport message of size bytes is copied
// out of the receive slab into a small buffer before it is queued.
func (device *Device) copyTransport(size int) bool {
	if !device.hasDistinctSmallPacketBufPool() || size > smallPacketBufSize || device.tunMergesWrites() {
		return false
	}
	switch device.lxBuffers.receiveCopy.Load() {
	case ReceiveCopySpeed:
		return false
	case ReceiveCopyAuto:
		return runtime.GOOS == "darwin" || runtime.GOOS == "ios"
	default:
		return true
	}
}

// awgLayout reports whether outbound packets need a buffer of their own: the
// transport padding (S4) goes in front of the header, or an AWG 3.x tail
// behind the plaintext.
func (device *Device) awgLayout() bool {
	return device.paddings.transport.Load() > 0 ||
		!device.contentPaddingAddition.Load().IsZero() ||
		device.randomTrailers.Load()
}

// awgPlaintextOffset is where the plaintext of an element starts under the
// transport padding: behind the encapsulation headroom, the padding and the
// transport header, all of which RoutineEncryption fills in place.
func awgPlaintextOffset(padding uint32) int {
	return MessageEncapsulatingTransportSize + int(padding) + MessageTransportHeaderSize
}

// outboundTailroom is the room kept after a plaintext ending at datagramSize
// for what RoutineEncryption appends before sealing: the WireGuard
// multiple-of-16 pad, or under AWG 3.x the content padding addition / random
// trailer. Both are clamped to the buffer when they would not fit, so this
// decides how much of the obfuscation a packet can carry, never whether it is
// safe.
func (device *Device) outboundTailroom(datagramSize int) int {
	room := PaddingMultiple
	if addition := device.contentPaddingAddition.Load(); !addition.IsZero() {
		room = max(room, int(min(addition.Hi(), MaxMessageSize)))
	} else if device.randomTrailers.Load() {
		room = max(room, DefaultUdpWindow-datagramSize)
	}
	return room
}

// outboundLayout sizes an element for a plaintext of totalLength bytes under
// the current transport padding. allocLength is 0 when the packet cannot fit a
// MaxMessageSize datagram.
func (device *Device) outboundLayout(totalLength int) (padding uint32, offset, allocLength int) {
	padding = device.paddings.transport.Load()
	offset = awgPlaintextOffset(padding)
	base := offset + totalLength + chacha20poly1305.Overhead
	if base+PaddingMultiple > MaxMessageSize {
		return padding, offset, 0
	}
	allocLength = min(base+device.outboundTailroom(offset+totalLength), MaxMessageSize)
	return padding, offset, allocLength
}

// ownPacketBuf returns a buffer of at least size bytes that holds one packet
// only: a small buffer when it fits, a sized one otherwise.
func (device *Device) ownPacketBuf(size int) *packetBuf {
	if size <= smallPacketBufSize && device.hasDistinctSmallPacketBufPool() {
		return device.getSmallPacketBuf()
	}
	return device.getInputPacketBuf(size)
}

// placeOutbound puts the plaintext of elem into a buffer of its own laid out
// for the current transport padding. It reports false when the packet fits no
// datagram; elem is then left as it was.
func (device *Device) placeOutbound(elem *QueueOutboundElement, plaintext []byte) bool {
	padding, offset, allocLength := device.outboundLayout(len(plaintext))
	if allocLength == 0 {
		return false
	}
	buffer := device.ownPacketBuf(allocLength)
	n := copy(buffer.slab[offset:], plaintext)
	if elem.buffer != nil {
		elem.buffer.decRef()
	}
	elem.buffer = buffer
	elem.packet = buffer.slab[offset : offset+n]
	elem.plaintextOffset = offset
	elem.padding = padding
	elem.ownsBuffer = true
	return true
}

// tunReadByMTU reports whether this read goes into a buffer of the packet's
// own: send_by_mtu is on and the TUN hands over one packet per read.
func (device *Device) tunReadByMTU(batchSize int) bool {
	return batchSize == 1 && device.lxBuffers.tunByMTU.Load()
}

// mtuReadBuf returns a buffer the TUN reads one packet into: read spacing in
// front, then room for the MTU, the AWG layout and the tail.
func (device *Device) mtuReadBuf() *packetBuf {
	padding := device.paddings.transport.Load()
	mtu := int(device.tun.mtu.Load())
	front := max(tun.ReadPacketSpacing, awgPlaintextOffset(padding))
	size := front + mtu + chacha20poly1305.Overhead + device.outboundTailroom(awgPlaintextOffset(padding)+mtu)
	if size > MaxMessageSize+tun.ReadPacketSpacing {
		size = MaxMessageSize + tun.ReadPacketSpacing
	}
	if int(device.lxBuffers.mtuSize.Load()) != size {
		device.lxBuffers.mtuSize.Store(int32(size))
	}
	if b, ok := device.lxBuffers.mtuBufs.Get().(*packetBuf); ok && len(b.slab) == size {
		b.incRef()
		return b
	}
	b := newPacketBuf(size, func(b *packetBuf) {
		if len(b.slab) == int(device.lxBuffers.mtuSize.Load()) {
			device.lxBuffers.mtuBufs.Put(b)
		}
	})
	b.incRef()
	return b
}

// regrowOutbound moves elem into a buffer of its own laid out for the current
// transport padding: an element read under another padding (reconfigured while
// in flight) or sitting in a shared slab. False when it fits no datagram.
func (device *Device) regrowOutbound(elem *QueueOutboundElement) bool {
	plaintext := make([]byte, len(elem.packet))
	copy(plaintext, elem.packet)
	return device.placeOutbound(elem, plaintext)
}
