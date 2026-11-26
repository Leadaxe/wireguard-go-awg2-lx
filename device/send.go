/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer *packetBuf // shared packet buffer that contains packet
	packet []byte     // packet is always a slice of buffer.slab
	// plaintextOffset describes the pre-encryption offset of packet within
	// buffer.slab. The encryption process grows packet on both ends to make
	// room for any potential encapsulating transport, WireGuard header, and
	// tail padding.
	plaintextOffset int
	nonce           uint64   // nonce for encryption
	keypair         *Keypair // keypair for encryption
	peer            *Peer    // related peer
	// lx: AmneziaWG — the transport padding (uapi s4) the element was laid out
	// for; its first 12 bytes double as the AWG 3.x header-protection nonce.
	padding uint32
	// lx: AmneziaWG 3.x — with content padding / random trailers a keepalive
	// is no longer the only 32-byte transport message, so it is flagged.
	isKeepalive bool
	// lx: the buffer holds this packet only (not a shared read slab), so the
	// element may lay out the AWG datagram around it (lx_buffers.go).
	ownsBuffer bool
}

type QueueOutboundElementsContainer struct {
	// filling is a one-shot barrier signaling encryption→send handoff.
	// SendStagedPackets calls Add(1) before sending the container down
	// the encryption and outbound queues; RoutineEncryption calls Done
	// after encrypting; RoutineSequentialSender calls Wait before
	// reading the encrypted packets.
	filling sync.WaitGroup
	elems   []*QueueOutboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
	elem.padding = 0         // lx
	elem.isKeepalive = false // lx
	elem.ownsBuffer = false  // lx
}

// SendKeepalive queues a keepalive if no packets are queued for
// peer.
func (peer *Peer) SendKeepalive() {
	var stagedDelta int
	if len(peer.queue.staged) == 0 {
		elem := peer.device.GetOutboundElement()
		elem.isKeepalive = true                    // lx
		if !peer.device.placeOutbound(elem, nil) { // lx: AWG layout, lx_buffers.go
			elem.buffer = peer.device.getSmallPacketBuf()
			elem.plaintextOffset = MessageEncapsulatingTransportSize + MessageTransportHeaderSize
		}
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		if queued := peer.doIfRunning(func() {
			select {
			case peer.queue.staged <- elemsContainer:
				peer.stagedPackets.Add(1)
				stagedDelta++
				peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
			default:
				peer.device.PutOutboundElement(elem)
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}
		}); !queued {
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets(stagedDelta)
}

// SendPriorityMessage invokes the [PeerPriorityMessageFunc] callback if one is
// set, and queues the returned message for encryption and transmission if the
// current keypair is valid.
func (peer *Peer) SendPriorityMessage() {
	f := peer.device.priorityMsgFn.Load()
	if f == nil {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || sinceIncludingSleep(keypair.created) >= peer.device.keychainExpireTime() {
		// SendStagedPackets initializes a handshake when the keypair is invalid,
		// but we explicitly avoid that here. A priority message is only intended
		// to flow around symmetric session establishment, but it should never
		// trigger a new session. Reaching this branch due to nonce exhaustion
		// or keypair expiration is highly unlikely considering where
		// SendPriorityMessage is called (at current keypair establishment).
		return
	}

	// get plaintext message to send
	msg := (*f)(peer.handshake.remoteStatic)
	if len(msg) == 0 {
		return
	}
	if len(msg) > MaxPriorityMessageContentSize {
		peer.device.log.Verbosef("%v - Failed to queue priority message due to size", peer)
		return
	}

	// get pooled elements
	elem := peer.device.GetOutboundElement()
	elemsContainer := peer.device.GetOutboundElementsContainer()
	elemsContainer.elems = append(elemsContainer.elems, elem)

	// initialize outbound element; lx: laid out for the AWG transport padding
	// and tail, in a buffer of its own (lx_buffers.go)
	if !peer.device.placeOutbound(elem, msg) {
		peer.device.PutOutboundElement(elem)
		peer.device.PutOutboundElementsContainer(elemsContainer)
		return
	}
	elem.peer = peer
	peer.queue.nonceMu.Lock()
	defer peer.queue.nonceMu.Unlock()
	elem.nonce = keypair.sendNonce.Add(1) - 1
	if elem.nonce >= RejectAfterMessages {
		keypair.sendNonce.Store(RejectAfterMessages)
		peer.device.PutOutboundElement(elem)
		peer.device.PutOutboundElementsContainer(elemsContainer)
		return
	}
	elem.keypair = keypair

	// add to parallel and sequential queue
	peer.queuedOutboundPackets.Add(1)
	peer.queueOutboundIfRunning(elemsContainer)
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.maxHandshakeAttempts.Store(peer.device.maxHandshakeAttempts()) // lx
	}

	timeout := peer.device.rekeyMinTimeout() // lx

	peer.handshake.mutex.RLock()
	if sinceIncludingSleep(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if sinceIncludingSleep(peer.handshake.lastSentHandshake) < timeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	// handshakeOnUserSend is flipped false after lastSentHandshake checks,
	// enabling eventual transmission at a future call of this method, while
	// still honoring [RekeyTimeout].
	peer.handshakeOnUserSend.Store(false)
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	candidates := peer.resolveEndpoints()

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		if err != errPeerStopped {
			peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		}
		return err
	}
	handshakeType := ""
	if msg.HasKEM {
		if isRetry {
			handshakeType = " (hybrid, retry)"
		} else {
			handshakeType = " (hybrid)"
		}
		msg.IsRetry = isRetry
	}
	peer.device.log.Verbosef("%v - Sending handshake initiation%s", peer, handshakeType)

	sz := MessageInitiationSize
	if msg.HasKEM {
		sz = MessageHybridInitiationSize
	}

	var sendBuffer [][]byte

	// lx: AmneziaWG — the masquerade burst: per-handshake decoys (sing-box-lx
	// SPEC 009), then the static CPS decoys (i1..i5), then Jc junk datagrams
	// precede the initiation, each its own datagram. The burst is assembled as
	// bare payloads, offered to the HandshakeBurstFunc (sing-box-lx SPEC 153),
	// and only then given its transport headroom.
	var burst [][]byte
	if f := peer.device.decoyPackets.Load(); f != nil {
		for _, decoy := range (*f)() {
			if len(decoy) == 0 {
				continue
			}
			burst = append(burst, decoy)
		}
	}
	for i := range peer.device.ipackets {
		if ipacket := peer.device.ipackets[i].Load(); ipacket != nil {
			buf := make([]byte, ipacket.ObfuscatedLen(0))
			ipacket.Obfuscate(buf, nil)
			burst = append(burst, buf)
		}
	}
	for _, junk := range peer.device.JunkPackets() {
		burst = append(burst, junk[MessageEncapsulatingTransportSize:])
	}
	if f := peer.device.handshakeBurst.Load(); f != nil {
		burst = (*f)(burst)
	}
	for _, payload := range burst {
		if len(payload) == 0 {
			continue
		}
		buf := make([]byte, MessageEncapsulatingTransportSize+len(payload))
		copy(buf[MessageEncapsulatingTransportSize:], payload)
		sendBuffer = append(sendBuffer, buf)
	}

	// lx: AmneziaWG datagram layout: [S1 random padding][initiation][random
	// trailer]. The padding's first 12 bytes are the header-protection nonce.
	padding := int(peer.device.paddings.init.Load())
	trailerLen := max(peer.randomTrailer(padding+sz), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+sz+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+sz]
	if err := msg.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal initiation message: %v", peer, err)
		return err
	}
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to protect initiation message: %v", peer, err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+sz:])

	sendBuffer = append(sendBuffer, sendBuf)

	if isRetry {
		if msg.HasKEM {
			peer.device.config.metrics.MessageHybridInitiationTXAttemptRetry.Add(1)
		} else {
			peer.device.config.metrics.MessageInitiationTXAttemptRetry.Add(1)
		}
	} else {
		if msg.HasKEM {
			peer.device.config.metrics.MessageHybridInitiationTXAttemptInitial.Add(1)
		} else {
			peer.device.config.metrics.MessageInitiationTXAttemptInitial.Add(1)
		}
	}
	err = peer.sendHandshakeDatagrams(sendBuffer, candidates) // lx: SPEC 101
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse(isRetry bool) error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		if err != errPeerStopped {
			peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		}
		return err
	}
	handshakeType := ""
	if response.HasKEM {
		if isRetry {
			handshakeType = " (hybrid, retry)"
		} else {
			handshakeType = " (hybrid)"
		}
		response.IsRetry = isRetry
	}
	peer.device.log.Verbosef("%v - Sending handshake response%s", peer, handshakeType)

	sz := MessageResponseSize
	if response.HasKEM {
		sz = MessageHybridResponseSize
	}
	// lx: AmneziaWG datagram layout: [S2 random padding][response][random trailer].
	padding := int(peer.device.paddings.response.Load())
	trailerLen := max(peer.randomTrailer(padding+sz), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+sz+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+sz]
	if err := response.marshal(packet); err != nil {
		peer.device.log.Errorf("%v - Failed to marshal response message: %v", peer, err)
		return err
	}
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	if response.HasKEM {
		peer.device.config.metrics.MessageHybridResponseTXAttempt.Add(1)
	} else {
		peer.device.config.metrics.MessageResponseTXAttempt.Add(1)
	}

	cip, err := peer.device.HeaderProtectionCipher(crypt)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to protect response message: %v", peer, err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+sz:])

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{sendBuf})
	err = unwrapGSODisabled(peer.device.log, err) // lx: SPEC 101
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.packetMeta.Endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	msgType := device.headers.cookie.Load().PickOne() // lx: AmneziaWG H3
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.packetMeta.Endpoint.DstToBytes(), msgType)
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	// lx: AmneziaWG datagram layout: [S3 random padding][cookie reply][random trailer].
	padding := int(device.paddings.cookie.Load())
	trailerLen := max(device.randomTrailer(padding+MessageCookieReplySize), 0)

	sendBuf := make([]byte, MessageEncapsulatingTransportSize+padding+MessageCookieReplySize+trailerLen)
	buf := sendBuf[MessageEncapsulatingTransportSize:]

	crypt := buf[:padding]
	rand.Read(crypt)

	packet := buf[padding : padding+MessageCookieReplySize]
	if err := reply.marshal(packet); err != nil {
		device.log.Errorf("Failed to marshal cookie reply: %v", err)
		return err
	}

	cip, err := device.HeaderProtectionCipher(crypt)
	if err != nil {
		device.log.Errorf("Failed to protect cookie reply: %v", err)
		return err
	}
	if cip != nil {
		cip.XORKeyStream(packet, packet)
	}

	rand.Read(buf[padding+MessageCookieReplySize:])

	device.config.metrics.MessageCookieReplyTXAttempt.Add(1)
	// TODO: allocation could be avoided
	device.net.sendTo(0, [][]byte{sendBuf}, initiatingElem.packetMeta.Endpoint, MessageEncapsulatingTransportSize)

	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	txHandshake := peer.handshakeOnUserSend.Load()
	nonce := keypair.sendNonce.Load()
	if txHandshake || nonce > RekeyAfterMessages || (keypair.isInitiator && sinceIncludingSleep(keypair.created) > peer.device.keyRefreshTimeoutSending()) {
		peer.SendHandshakeInitiation(false)
	}
}

// copyPacketBufIfFits copies the prefix of src.slab ending at the final packet
// into dst.slab if that prefix+[outboundPlaintextTailroom] fits. It reports
// whether the copy occurred. Packet descriptors must be in offset ascending order.
func copyPacketBufIfFits(dst, src *packetBuf, packets []tun.ReadPacket) bool {
	if dst == nil || len(packets) < 1 {
		return false
	}
	// validate tail descriptor as it relates to src
	tailPkt := packets[len(packets)-1]
	if tailPkt.Offset < 0 || tailPkt.Size < 1 {
		return false
	}
	end := tailPkt.Offset + tailPkt.Size
	if end < tailPkt.Offset || end > len(src.slab) ||
		outboundPlaintextTailroom > len(src.slab)-end {
		return false
	}
	// validate src fits in dst
	if end+outboundPlaintextTailroom > len(dst.slab) {
		return false
	}
	copy(dst.slab, src.slab[:end])
	return true
}

func (device *Device) RoutineReadFromTUN(id int, queue tun.Reader) {
	defer func() {
		device.log.Verbosef("Routine: TUN reader %d - stopped", id)
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader %d - started", id)

	var (
		batchSize   = device.BatchSize()
		packets     = make([]tun.ReadPacket, batchSize)
		fullSizeBuf = device.getPacketBuf()
		smallBuf    *packetBuf
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
	)

	if device.hasDistinctSmallPacketBufPool() {
		smallBuf = device.getSmallPacketBuf()
	}

	defer func() {
		fullSizeBuf.decRef()
		if smallBuf != nil {
			smallBuf.decRef()
		}
	}()

	for i := range elems {
		elems[i] = device.GetOutboundElement()
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutOutboundElement(elem)
			}
		}
	}()

	var (
		buf          *packetBuf // either fullSizeBuf or smallBuf
		bufHandedOff bool
	)

	for {
		if bufHandedOff {
			if buf == smallBuf {
				smallBuf.decRef()
				smallBuf = device.getSmallPacketBuf()
			} else {
				fullSizeBuf.decRef()
				fullSizeBuf = device.getPacketBuf()
			}
		}
		buf = fullSizeBuf
		bufHandedOff = false

		// lx: send_by_mtu — a TUN that hands over one packet per read reads it
		// straight into a buffer of its own (lx_buffers.go)
		byMTU := device.tunReadByMTU(batchSize)
		var mtuBuf *packetBuf
		if byMTU {
			mtuBuf = device.mtuReadBuf()
			buf = mtuBuf
		}

		// read packets
		count, readErr = queue.Read(buf.slab, packets)
		if !byMTU && copyPacketBufIfFits(smallBuf, fullSizeBuf, packets[:count]) {
			buf = smallBuf
		}
		awg := device.awgLayout() // lx

		for i, meta := range packets[:count] {
			if meta.Size < 1 || meta.Size > MaxContentSize {
				continue
			}

			// explicitly pin slice capacity, so downstream expansion of length
			// never leak into an adjacent packet
			packet := buf.slab[meta.Offset : meta.Offset+meta.Size : meta.Offset+meta.Size+outboundPlaintextTailroom]

			// lookup peer
			var peer *Peer
			switch packet[0] >> 4 {
			case 4:
				if len(packet) < ipv4.HeaderLen {
					continue
				}
				src := netip.AddrFrom4([4]byte(packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]))
				dst := netip.AddrFrom4([4]byte(packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]))
				peer = device.allowedips.LookupFromPacket(src, dst, packet)

			case 6:
				if len(packet) < ipv6.HeaderLen {
					continue
				}
				src := netip.AddrFrom16([16]byte(packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]))
				dst := netip.AddrFrom16([16]byte(packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]))
				peer = device.allowedips.LookupFromPacket(src, dst, packet)

			default:
				device.log.Verbosef("Received packet with unknown IP version")
			}

			if peer == nil {
				continue
			}

			elem := elems[i]
			switch {
			case byMTU:
				// lx: the packet's own buffer, with room behind it up to the slab
				buf.incRef()
				elem.buffer = buf
				elem.packet = buf.slab[meta.Offset : meta.Offset+meta.Size]
				elem.plaintextOffset = meta.Offset
				elem.padding = device.paddings.transport.Load()
				elem.ownsBuffer = true
			case awg:
				// lx: AmneziaWG — the packet is copied into a buffer of its own laid
				// out behind the transport padding, with room for the 3.x tail; a
				// shared slab has 64 bytes between packets
				if !device.placeOutbound(elem, packet) {
					continue
				}
			default:
				buf.incRef()
				bufHandedOff = true
				elem.buffer = buf
				elem.packet = packet
				elem.plaintextOffset = meta.Offset
			}

			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.GetOutboundElement()
		}
		if byMTU {
			mtuBuf.decRef() // lx: each element holds its own reference
		}

		for peer, elemsForPeer := range elemsByPeer {
			stagedDelta := peer.StagePackets(elemsForPeer)
			peer.SendStagedPackets(stagedDelta)
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

const (
	maxStagedPackets         = 128
	maxQueuedOutboundPackets = 1024
)

type InputPacketRef struct {
	Destination  []byte
	PacketSlices [][]byte
}

func (device *Device) inputPacketPeer(destination []byte, packetSlices [][]byte) *Peer {
	var src, dst netip.Addr
	switch len(destination) {
	case net.IPv4len:
		dst = netip.AddrFrom4([4]byte(destination))
		var srcBytes [net.IPv4len]byte
		if !gatherPacketBytes(packetSlices, IPv4offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom4(srcBytes)
	case net.IPv6len:
		dst = netip.AddrFrom16([16]byte(destination))
		var srcBytes [net.IPv6len]byte
		if !gatherPacketBytes(packetSlices, IPv6offsetSrc, srcBytes[:]) {
			return nil
		}
		src = netip.AddrFrom16(srcBytes)
	default:
		return nil
	}
	var ipPkt []byte
	if len(packetSlices) == 1 {
		ipPkt = packetSlices[0]
	}
	return device.allowedips.LookupFromPacket(src, dst, ipPkt)
}

func gatherPacketBytes(packetSlices [][]byte, offset int, destination []byte) bool {
	for _, packetSlice := range packetSlices {
		if offset >= len(packetSlice) {
			offset -= len(packetSlice)
			continue
		}
		n := copy(destination, packetSlice[offset:])
		destination = destination[n:]
		offset = 0
		if len(destination) == 0 {
			return true
		}
	}
	return false
}

func (device *Device) newInputElement(packetSlices ...[]byte) *QueueOutboundElement {
	var totalLength int
	for _, packetSlice := range packetSlices {
		totalLength += len(packetSlice)
	}
	// lx: laid out behind the AWG transport padding, with room for the 3.x tail
	// (lx_buffers.go); without AWG it is upstream's layout
	padding, offset, allocLength := device.outboundLayout(totalLength)
	if allocLength == 0 {
		return nil
	}
	elem := device.GetOutboundElement()
	elem.buffer = device.getInputPacketBuf(allocLength)
	elem.plaintextOffset = offset
	elem.padding = padding
	elem.ownsBuffer = true
	packet := elem.buffer.slab[elem.plaintextOffset:]
	var n int
	for _, packetSlice := range packetSlices {
		n += copy(packet[n:], packetSlice)
	}
	elem.packet = packet[:n]
	return elem
}

// InputPackets injects whole IP packets without waiting: packets for a peer
// whose pipeline is full are dropped. Packets matching no peer are returned.
func (device *Device) InputPackets(packets []*InputPacketRef) []*InputPacketRef {
	var unmatched []*InputPacketRef
	elemsByPeer := make(map[*Peer][]*QueueOutboundElementsContainer)
	for _, packetRef := range packets {
		peer := device.inputPacketPeer(packetRef.Destination, packetRef.PacketSlices)
		if peer == nil {
			unmatched = append(unmatched, packetRef)
			continue
		}
		containers := elemsByPeer[peer]
		var collected int
		if len(containers) > 0 {
			collected = (len(containers)-1)*conn.IdealBatchSize + len(containers[len(containers)-1].elems)
		}
		if peer.stagedFull(collected) || peer.queuedOutboundPackets.Load()+int32(collected) >= maxQueuedOutboundPackets {
			continue
		}
		elem := device.newInputElement(packetRef.PacketSlices...)
		if elem == nil {
			continue
		}
		if len(containers) == 0 || len(containers[len(containers)-1].elems) >= conn.IdealBatchSize {
			containers = append(containers, device.GetOutboundElementsContainer())
			elemsByPeer[peer] = containers
		}
		elemsForPeer := containers[len(containers)-1]
		elemsForPeer.elems = append(elemsForPeer.elems, elem)
	}
	for peer, containers := range elemsByPeer {
		var stagedDelta int
		for _, elemsForPeer := range containers {
			stagedDelta += peer.StagePackets(elemsForPeer)
		}
		peer.SendStagedPackets(stagedDelta)
	}
	return unmatched
}

// WritePackets injects whole IP packets routed to this peer, waiting while the
// peer's encryption and transmission pipeline is full. Packets are dropped if
// the peer stops or is still waiting for a handshake with a full staged queue.
func (peer *Peer) WritePackets(packets [][]byte) {
	device := peer.device
	for len(packets) > 0 {
		if !peer.waitOutboundSpace() {
			return
		}
		batch := packets[:min(len(packets), conn.IdealBatchSize)]
		packets = packets[len(batch):]
		if peer.stagedFull(0) {
			continue
		}
		elemsForPeer := device.GetOutboundElementsContainer()
		for _, packet := range batch {
			elem := device.newInputElement(packet)
			if elem != nil {
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
			}
		}
		if len(elemsForPeer.elems) == 0 {
			device.PutOutboundElementsContainer(elemsForPeer)
			continue
		}
		peer.SendStagedPackets(peer.StagePackets(elemsForPeer))
	}
}

func (peer *Peer) stagedFull(pending int) bool {
	if peer.stagedPackets.Load()+int32(pending) < maxStagedPackets {
		return false
	}
	keypair := peer.keypairs.Current()
	return keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || sinceIncludingSleep(keypair.created) >= peer.device.keychainExpireTime()
}

func (peer *Peer) waitOutboundSpace() bool {
	for {
		if !peer.runningState.isRunning.Load() {
			return false
		}
		if peer.queuedOutboundPackets.Load() < maxQueuedOutboundPackets {
			return true
		}
		peer.outboundSpace.Lock()
		if peer.outboundSpace.ready == nil {
			peer.outboundSpace.ready = make(chan struct{})
		}
		ready := peer.outboundSpace.ready
		peer.outboundSpace.Unlock()
		if !peer.runningState.isRunning.Load() {
			return false
		}
		if peer.queuedOutboundPackets.Load() < maxQueuedOutboundPackets {
			return true
		}
		<-ready
	}
}

func (peer *Peer) releaseOutboundPackets(count int) {
	remaining := peer.queuedOutboundPackets.Add(-int32(count))
	if remaining < maxQueuedOutboundPackets && remaining+int32(count) >= maxQueuedOutboundPackets {
		peer.wakeOutboundWaiters()
	}
}

func (peer *Peer) wakeOutboundWaiters() {
	peer.outboundSpace.Lock()
	if peer.outboundSpace.ready != nil {
		close(peer.outboundSpace.ready)
		peer.outboundSpace.ready = nil
	}
	peer.outboundSpace.Unlock()
}

// StagePackets attempts to enqueue elements into the peer's staging queue.
// If the queue is full, its oldest member is dropped to make room.
// If the peer is not running, the data is quietly dropped.
//
// It returns a delta for len(peer.queue.staged) operations, which must be
// passed in a subsequent call to [Peer.SendStagedPackets], where global stage
// queue accounting changes are committed.
//
// [Peer.nonceMu] relies on this function being non-blocking.
func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) (stagedDelta int) {
	if running := peer.doIfRunning(func() {
		peer.stagedPackets.Add(int32(len(elems.elems)))
		for {
			select {
			case peer.queue.staged <- elems:
				stagedDelta++
				return
			default:
			}
			select {
			case tooOld := <-peer.queue.staged:
				peer.stagedPackets.Add(-int32(len(tooOld.elems)))
				stagedDelta--
				for _, elem := range tooOld.elems {
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(tooOld)
			default:
			}
		}
	}); !running {
		for _, elem := range elems.elems {
			peer.device.PutOutboundElement(elem)
		}
		peer.device.PutOutboundElementsContainer(elems)
	}
	return stagedDelta
}

// SendStagedPackets sends any staged packets to Peer, if a valid keypair and
// nonce are available.
//
// It accepts a delta for preceding len(peer.queue.staged) operations. Said
// delta gets combined with what it performs, and committed to device-wide stage
// queue accounting, if a global staged queue limit is configured.
//
// SendStagedPackets accepts stagedDelta in order to intentionally delay
// device-wide stage queue accounting commit until the end of this func. This
// strategy limits staged queue accounting to long-lived elements, i.e. those
// awaiting a future handshake, and does not include elements that stage and are
// immediately transmitted.
func (peer *Peer) SendStagedPackets(stagedDelta int) {
	defer func() {
		if peer.device.config.queueStagedGlobalLimit > 0 {
			stagedCount := peer.device.queue.stagedCount.Add(int64(stagedDelta))
			if stagedCount > peer.device.config.queueStagedGlobalLimit {
				// TODO(jwhited): count when this happens
				peer.FlushStagedPackets(int(stagedCount - peer.device.config.queueStagedGlobalLimit))
			}
		}
	}()

	// SendStagedPackets may be called concurrently. Serialize nonce assignment
	// with outbound enqueue so packets are transmitted in nonce order; excessive
	// reordering can cause the receiver's replay filter to drop packets.
	//
	// Unlock explicitly before each return to avoid holding nonceMu across
	// SendHandshakeInitiation, whose expensive work would stall TUN readers.
	peer.queue.nonceMu.Lock()
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		peer.queue.nonceMu.Unlock()
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || sinceIncludingSleep(keypair.created) >= peer.device.keychainExpireTime() {
		peer.queue.nonceMu.Unlock()
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			stagedDelta--
			peer.stagedPackets.Add(-int32(len(elemsContainer.elems)))
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				stagedDelta += peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			peer.queuedOutboundPackets.Add(int32(len(elemsContainer.elems)))
			peer.queueOutboundIfRunning(elemsContainer)

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			peer.queue.nonceMu.Unlock()
			return
		}
	}
}

// FlushStagedPackets drains elements from [Peer.queue.staged] up to limit. If
// limit is zero, FlushStagedPackets drains all elements.
func (peer *Peer) FlushStagedPackets(limit int) {
	var flushed int
	defer func() {
		peer.device.queue.stagedCount.Add(-(int64(flushed)))
	}()
	for {
		if limit > 0 && flushed == limit {
			return
		}
		select {
		case elemsContainer := <-peer.queue.staged:
			peer.stagedPackets.Add(-int32(len(elemsContainer.elems)))
			flushed++
			for _, elem := range elemsContainer.elems {
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

// lx:begin awg3 (AmneziaWG 3.x — ported from amneziawg-go v3 device/send.go)

// randomPaddingAddition picks the AWG 3.x content padding addition for a
// transport datagram of datagramSize bytes (padding + header + content + tag):
// a value from content_padding_addition, clamped so the datagram never grows
// past the peer's UDP window. -1 when the feature is off.
func (peer *Peer) randomPaddingAddition(datagramSize int) int {
	addition := peer.device.contentPaddingAddition.Load()
	if addition.IsZero() {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < datagramSize {
		return 0
	}

	add := int(addition.PickOne())
	if space := udpWindow - datagramSize; add > space {
		add = space
	}
	return add
}

// randomTrailer picks the AWG 3.x random trailer length for a datagram sent
// without a peer context (cookie replies): up to DefaultUdpWindow. -1 when
// random_trailers is off.
func (device *Device) randomTrailer(datagramSize int) int {
	if !device.randomTrailers.Load() {
		return -1
	}

	if DefaultUdpWindow < datagramSize {
		return 0
	}
	return int(fastrandn(uint32(DefaultUdpWindow - datagramSize)))
}

// randomTrailer picks the AWG 3.x random trailer length for a datagram to this
// peer: up to the peer's UDP window. -1 when random_trailers is off.
func (peer *Peer) randomTrailer(datagramSize int) int {
	if !peer.device.randomTrailers.Load() {
		return -1
	}

	udpWindow := int(peer.udpWindow.Load())
	if udpWindow < datagramSize {
		return 0
	}
	return int(fastrandn(uint32(udpWindow - datagramSize)))
}

// newPaddingRNG returns the source an encryption worker fills the S4
// transport padding from. The padding's first 12 bytes are the AWG 3.x
// header-protection nonce, so the source must be unpredictable and must not
// repeat; ChaCha8 seeded from crypto/rand is a CSPRNG that gives both, without
// the getrandom syscall per packet that crypto/rand costs on kernels without
// the vDSO (Android before 6.11). One source per worker: ChaCha8 is not safe
// for concurrent use.
func newPaddingRNG() *mrand.ChaCha8 {
	var seed [32]byte
	rand.Read(seed[:])
	return mrand.NewChaCha8(seed)
}

// layOutForEncryption makes sure the plaintext of elem sits where the AWG
// datagram can be built around it in place: behind the current transport
// padding, in a buffer of its own when a padding or a 3.x tail is in use. A
// plain WireGuard element stays where upstream put it, a shared slab included.
// False when the packet fits no datagram under the current layout.
func (device *Device) layOutForEncryption(elem *QueueOutboundElement, padding uint32) bool {
	if !device.awgLayout() && elem.padding == 0 {
		return true
	}
	offset := awgPlaintextOffset(padding)
	if elem.ownsBuffer && elem.padding == padding && elem.plaintextOffset == offset {
		return true
	}
	if elem.ownsBuffer && offset+len(elem.packet)+chacha20poly1305.Overhead <= len(elem.buffer.slab) {
		// an element read under another padding, or a TUN read into its own
		// buffer at the TUN's offset: move it in place (memmove)
		n := copy(elem.buffer.slab[offset:], elem.packet)
		elem.packet = elem.buffer.slab[offset : offset+n]
		elem.plaintextOffset = offset
		elem.padding = padding
		return true
	}
	return device.regrowOutbound(elem)
}

// lx:end awg3

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte
	padRNG := newPaddingRNG() // lx: AmneziaWG — per-worker S4 padding source

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// lx: AmneziaWG datagram layout, built in place in the element's
			// buffer: [encap headroom][s4 random padding][16-byte header][sealed
			// content]. The device's current s4 is authoritative: an element
			// produced under another value is moved (lx_buffers.go).
			padding := device.paddings.transport.Load()
			if !device.layOutForEncryption(elem, padding) {
				device.log.Verbosef("%v - Packet dropped: no room under transport padding %d", elem.peer, padding)
				elem.packet = nil
				continue
			}
			pad := int(elem.padding)
			headerStart := elem.plaintextOffset - MessageTransportHeaderSize
			start := headerStart - pad - MessageEncapsulatingTransportSize

			// The datagram this element becomes is a size this path carries.
			elem.peer.noteUDPWindow(uint32(pad + MessageTransportSize + len(elem.packet)))

			// fill the transport padding; its first 12 bytes are the AWG 3.x
			// header-protection nonce
			crypt := elem.buffer.slab[headerStart-pad : headerStart]
			if len(crypt) > 0 {
				padRNG.Read(crypt)
			}

			// populate header fields
			header := elem.buffer.slab[headerStart:elem.plaintextOffset]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, device.headers.transport.Load().PickOne())
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// trailing plaintext bytes: the AWG 3.x content padding addition,
			// else a random trailer, else the WireGuard multiple-of-16 pad
			datagramSize := pad + MessageTransportSize + len(elem.packet)
			paddingSize := elem.peer.randomPaddingAddition(datagramSize)
			if paddingSize < 0 {
				paddingSize = elem.peer.randomTrailer(datagramSize)
			}
			if paddingSize < 0 {
				paddingSize = calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			}
			// never spill past the room the element has: upstream pins the
			// capacity of a packet in a shared slab, an own buffer ends at its slab
			if room := cap(elem.packet) - len(elem.packet) - chacha20poly1305.Overhead; paddingSize > room {
				paddingSize = max(room, 0)
			}
			oldLen := len(elem.packet)
			elem.packet = elem.packet[:oldLen+paddingSize]
			clear(elem.packet[oldLen:])

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)

			// re-slice packet to include the padding and encapsulating transport space
			end := headerStart + len(elem.packet)
			elem.packet = elem.buffer.slab[start:end]

			// AWG 3.x header protection: the 16-byte header is XORed with a
			// ChaCha20 keystream keyed by the header key and salted with the
			// padding, so type / receiver index / counter carry no structure.
			var cip chacha20.Cipher // on this worker's stack, see headerCipherInto
			protected, err := device.headerCipherInto(&cip, crypt)
			if err != nil {
				device.log.Errorf("%v - Header protection failed, packet dropped: %v", elem.peer, err)
				elem.packet = nil
				continue
			}
			if protected {
				cip.XORKeyStream(header, header)
			}
		}
		elemsContainer.filling.Done()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.runningState.queueReaders.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, max(maxBatchSize, conn.IdealBatchSize))

	for elemsContainer := range peer.queue.outbound {
		peer.processOutboundContainer(elemsContainer, bufs[:0])
	}
}

// processOutboundContainer waits for the encryption routine to finish
// filling elemsContainer, then sends the batch (or drops it, if the peer
// has been stopped) and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to SendBuffers; its backing array is reused across calls.
func (peer *Peer) processOutboundContainer(elemsContainer *QueueOutboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialSender; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processOutboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processOutboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutOutboundElementsContainer(elemsContainer)

	// Wait for RoutineEncryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()

	if !peer.runningState.isRunning.Load() {
		// peer has been stopped; return re-usable elems to the shared pool.
		// This is an optimization only. It is possible for the peer to be stopped
		// immediately after this check, in which case, elem will get processed.
		// The timers and SendBuffers code are resilient to a few stragglers.
		// TODO: rework peer shutdown order to ensure
		// that we never accidentally keep timers alive longer than necessary.
		peer.releaseOutboundPackets(len(elemsContainer.elems))
		for _, elem := range elemsContainer.elems {
			device.PutOutboundElement(elem)
		}
		return
	}

	dataSent := false
	for _, elem := range elemsContainer.elems {
		if elem.packet == nil {
			// lx: dropped by RoutineEncryption (no room, header protection failure)
			continue
		}
		if !elem.isKeepalive { // lx: AWG 3.x pads keepalives too
			dataSent = true
		}
		scratch = append(scratch, elem.packet)
	}

	var err error
	if len(scratch) > 0 {
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err = peer.SendBuffers(scratch)
		if dataSent {
			peer.timersDataSent()
		}
	}
	peer.releaseOutboundPackets(len(elemsContainer.elems))
	for _, elem := range elemsContainer.elems {
		device.PutOutboundElement(elem)
	}
	err = unwrapGSODisabled(device.log, err) // lx: SPEC 101
	if err != nil {
		device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
		return
	}

	peer.keepKeyFreshSending()
}
