/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/wireguard-go/conn"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType    uint32
	packet     []byte
	packetMeta conn.ReceivedPacket
	buffer     *packetBuf
}

type QueueInboundElement struct {
	buffer     *packetBuf
	packet     []byte
	packetMeta conn.ReceivedPacket
	counter    uint64
	keypair    *Keypair
	// lx: AmneziaWG — the transport padding (s4) this datagram arrived with.
	// packetMeta describes the transport message behind it, so the padding
	// is left where it arrived.
	padding uint32
}

type QueueInboundElementsContainer struct {
	// filling is a one-shot barrier signaling decryption→receive
	// handoff. RoutineReceiveIncoming calls Add(1) before sending the
	// container down the decryption and inbound queues; RoutineDecryption
	// calls Done after decrypting; RoutineSequentialReceiver calls Wait
	// before reading the decrypted packets.
	filling sync.WaitGroup
	elems   []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.packetMeta = conn.ReceivedPacket{}
	elem.keypair = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && sinceIncludingSleep(keypair.created) > peer.device.keyRefreshTimeoutReceiving() {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

// RoutineReceiveIncoming receives incoming datagrams from one of the bind's
// receive queues. A new routine is started for each queue every time the bind
// is updated.
// recvName identifies the queue in logs; see [conn.NamesOf].
func (device *Device) RoutineReceiveIncoming(recvName string, maxBatchSize int, recv conn.ReceiveFunc) {
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		packets = make([]conn.ReceivedPacket, maxBatchSize)
		buf     = device.getPacketBuf()
		// bufDirty tracks whether the current buf has been pushed downstream to
		// crypto and per-peer/handshake functions, or can be re-used across the
		// next read cycle
		bufDirty    bool
		err         error
		count       int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
		// lx: keystream bytes 0..8 of the header cipher — enough to unmask the
		// type word and the receiver index (SPEC 081) before classification.
		headerHashBuf [8]byte
	)

	defer func() {
		buf.decRef()
	}()

	copyHandshake := device.hasDistinctSmallPacketBufPool()

	for {
		if bufDirty {
			buf.decRef()
			buf = device.getPacketBuf()
			bufDirty = false
		}
		count, err = recv(buf.slab, packets)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if errors.Is(err, conn.ErrRebindRequired) {
				device.scheduleBindUpdate()
				return
			}
			continue // Pacing is the Bind's responsibility; see [conn.ReceiveFunc].
		}

		// handle each packet in the batch
		for _, meta := range packets[:count] {
			if meta.Size < MinMessageSize {
				continue
			}

			// check size of packet

			packet := meta.Bytes(buf.slab)

			// lx: AmneziaWG 3.x header protection — the keystream for this
			// datagram is salted with its first 12 bytes (the S1–S4 padding);
			// its first 8 bytes unmask the type word and the receiver index
			// wherever they sit. The type is read from all 32 bits of the word
			// (an H range may have the top bit set), never via parseTypeField.
			var cipValue chacha20.Cipher
			var cip *chacha20.Cipher
			protected, err := device.headerCipherInto(&cipValue, packet)
			if err != nil {
				device.log.Errorf("Failed to initialize header cipher: %v", err)
				continue
			}
			if protected {
				cip = &cipValue
			}

			headerHash := headerHashBuf[:]
			clear(headerHash)
			if cip != nil {
				cip.XORKeyStream(headerHash, headerHash)
			}

			// lx: SPEC 081 — a datagram that carries one of our live receiver
			// indices behind a transport type word is a data packet, whatever
			// its size; only then fall back to the reference order.
			var msgSize int
			var msgType, padding uint32
			entry, transportPadding, byIndex := device.classifyTransportByIndex(packet, headerHash)
			if byIndex {
				msgSize, msgType, padding = MessageTransportSize, MessageTransportType, transportPadding
			} else {
				msgSize, msgType, padding = device.DeterminePacketTypeAndPadding(packet, headerHash[:4])
			}
			if msgType == MessageUnknownType {
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			// strip the padding (left in place in the buffer) and, for the
			// fixed-size handshake messages, the AWG 3.x random trailer
			packet = packet[padding:]
			meta.Offset += int(padding)
			meta.Size -= int(padding)
			if msgType != MessageTransportType {
				packet = packet[:msgSize]
				meta.Size = msgSize
			}

			// unmask the first 8 bytes (type + sender/receiver index) with the
			// keystream already drawn; the cipher continues from byte 8 below
			if cip != nil {
				applyHash(packet[:8], packet[:8], headerHash)
			}

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:MessageTransportHeaderSize], packet[8:MessageTransportHeaderSize])
				}

				// lookup key pair

				value := entry
				if !byIndex {
					receiver := binary.LittleEndian.Uint32(
						packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
					)
					value = device.indexTable.Lookup(receiver)
				}
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if sinceIncludingSleep(keypair.created) > device.keychainExpireTime() {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.padding = padding
				// lx: lx.wg.buffers.receive_copy decides the copy (lx_buffers.go)
				if device.copyTransport(len(packet)) {
					elem.buffer = device.getSmallPacketBuf()
					elem.packet = elem.buffer.slab[:copy(elem.buffer.slab, packet)]
					elem.packetMeta = conn.ReceivedPacket{Size: len(packet), Endpoint: meta.Endpoint}
				} else {
					bufDirty = true
					buf.incRef()
					elem.buffer = buf
					elem.packet = packet
					elem.packetMeta = meta
				}
				elem.keypair = keypair
				elem.counter = 0

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize && len(packet) != MessageHybridInitiationSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:], packet[8:])
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize && len(packet) != MessageHybridResponseSize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:], packet[8:])
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}
				if cip != nil {
					cip.XORKeyStream(packet[8:], packet[8:])
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			handshakeElem := QueueHandshakeElement{
				msgType:    msgType,
				buffer:     buf,
				packet:     packet,
				packetMeta: meta,
			}
			// lx: a handshake longer than a small buffer is never cut short by the copy
			copyThis := copyHandshake && len(packet) <= smallPacketBufSize
			if copyThis {
				handshakeElem.buffer = device.getSmallPacketBuf()
				handshakeElem.packet = handshakeElem.buffer.slab[:copy(handshakeElem.buffer.slab, packet)]
				handshakeElem.packetMeta = conn.ReceivedPacket{Size: len(packet), Endpoint: meta.Endpoint}
			} else {
				buf.incRef()
			}
			select {
			case device.queue.handshake.c <- handshakeElem:
				if !copyThis {
					bufDirty = true
				}
			default:
				handshakeElem.buffer.decRef()
			}
		}
		for peer, elemsContainer := range elemsByPeer {
			peer.queueInboundIfRunning(elemsContainer)
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.filling.Done()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.runningState.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.packetMeta.Endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			// lx: AmneziaWG 3.x disable_cookies — never answer with a cookie
			// reply, and skip the under-load mac2/ratelimit gate that would
			// demand one (upstream b5928ef).
			if !device.disableCookies.Load() && device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.packetMeta.Endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.packetMeta.Endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// lx: have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg, elem.packetMeta.Endpoint)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.packetMeta.Endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.packetMeta.Endpoint)

			handshakeType := ""
			if msg.HasKEM {
				if msg.IsRetry {
					handshakeType = " (hybrid, retry)"
				} else {
					handshakeType = " (hybrid)"
				}
			}
			device.log.Verbosef("%v - Received handshake initiation%s", peer, handshakeType)

			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse(msg.IsRetry)

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// lx: have to reassign msgType for ranged msgType to work
			msg.Type = elem.msgType

			// consume response

			peer, duplicate := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				// TODO(illotum): is there value in a counter here?
				if !duplicate {
					device.log.Verbosef("Received invalid response message from %s", elem.packetMeta.Endpoint.DstToString())
				}
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.packetMeta.Endpoint)

			handshakeType := ""
			if msg.HasKEM {
				if msg.IsRetry {
					handshakeType = " (hybrid, retry)"
				} else {
					handshakeType = " (hybrid)"
				}
			}
			device.log.Verbosef("%v - Received handshake response%s", peer, handshakeType)

			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()
			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			if msg.HasKEM {
				device.config.metrics.HandshakeHybridInitiatorCompleted.Add(1)
			} else {
				device.config.metrics.HandshakeInitiatorCompleted.Add(1)
			}
			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendPriorityMessage()
			peer.SendKeepalive()
		}
	skip:
		elem.buffer.decRef()
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.runningState.queueReaders.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound {
		peer.processInboundContainer(elemsContainer, bufs[:0])
	}
}

// processInboundContainer waits for the decryption routine to finish
// filling elemsContainer, then writes the valid packets to the TUN
// device and returns the container to the pool.
//
// scratch is a length-0 slice used to assemble the per-packet buffers
// passed to tun.device.Write; its backing array is reused across calls.
func (peer *Peer) processInboundContainer(elemsContainer *QueueInboundElementsContainer, scratch [][]byte) {
	// Invariants from RoutineSequentialReceiver; all should be unreachable.
	if len(scratch) != 0 || cap(scratch) == 0 {
		panic(fmt.Sprintf("processInboundContainer: scratch must be empty with non-zero cap; got len=%d cap=%d",
			len(scratch), cap(scratch)))
	}
	if cap(scratch) < len(elemsContainer.elems) {
		panic(fmt.Sprintf("processInboundContainer: scratch cap %d < elems %d",
			cap(scratch), len(elemsContainer.elems)))
	}

	device := peer.device
	defer device.PutInboundElementsContainer(elemsContainer)

	// Wait for RoutineDecryption to finish filling the container. After
	// Wait returns we have happens-before with that goroutine and are the
	// sole owner of the container until Put hands it back to the pool.
	elemsContainer.filling.Wait()
	elems := elemsContainer.elems

	validTailPacket := -1
	dataPacketReceived := false
	rxBytesLen := uint64(0)
	for i, elem := range elems {
		if elem.packet == nil {
			// decryption failed
			continue
		}

		if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
			device.config.metrics.MessageTransportRXDroppedReplay.Add(1)
			continue
		}

		validTailPacket = i
		if peer.ReceivedWithKeypair(elem.keypair) {
			if elem.keypair.isHybrid {
				peer.device.config.metrics.HandshakeHybridResponderCompleted.Add(1)
			} else {
				peer.device.config.metrics.HandshakeResponderCompleted.Add(1)
			}
			peer.SetEndpointFromPacket(elem.packetMeta.Endpoint)
			peer.timersHandshakeComplete()
			peer.SendPriorityMessage()
			peer.SendStagedPackets(0)
		}
		if ep, ok := elem.packetMeta.Endpoint.(conn.PeerAwareEndpoint); ok {
			ep.FromPeer(peer.handshake.remoteStatic)
		}
		rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

		// lx: AmneziaWG 3.x — a datagram the peer got through to us is a
		// size this path carries; widen the UDP window accordingly.
		peer.noteUDPWindow(elem.padding + MessageTransportSize + uint32(len(elem.packet)))

		// lx: AmneziaWG 3.x — a keepalive may carry content padding / a
		// trailer, all zeros; an IP packet never starts with a zero byte
		// (version nibble), so a leading zero is a padded keepalive.
		if len(elem.packet) == 0 || elem.packet[0] == 0 {
			device.log.Verbosef("%v - Receiving keepalive packet", peer)
			continue
		}
		dataPacketReceived = true

		switch elem.packet[0] >> 4 {
		case 4:
			if len(elem.packet) < ipv4.HeaderLen {
				continue
			}
			field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
			length := binary.BigEndian.Uint16(field)
			if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
				continue
			}
			elem.packet = elem.packet[:length]
			src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
			srcAddr, _ := netip.AddrFromSlice(src)
			if !peer.AllowedPeerSourceIP(srcAddr) {
				device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
				continue
			}

		case 6:
			if len(elem.packet) < ipv6.HeaderLen {
				continue
			}
			field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
			length := uint32(binary.BigEndian.Uint16(field))
			length += ipv6.HeaderLen
			if int(length) > len(elem.packet) {
				continue
			}
			elem.packet = elem.packet[:length]
			src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
			srcAddr, _ := netip.AddrFromSlice(src)
			if !peer.AllowedPeerSourceIP(srcAddr) {
				device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
				continue
			}

		default:
			device.log.Verbosef("Packet with invalid IP version from %v", peer)
			continue
		}

		elem.packetMeta.Size = MessageTransportOffsetContent + len(elem.packet)
		scratch = append(scratch, elem.packetMeta.Bytes(elem.buffer.slab))
	}

	peer.rxBytes.Add(rxBytesLen)
	if validTailPacket >= 0 {
		peer.SetEndpointFromPacket(elems[validTailPacket].packetMeta.Endpoint)
		peer.keepKeyFreshReceiving()
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketReceived()
	}
	if dataPacketReceived {
		peer.timersDataReceived()
	}
	if len(scratch) > 0 {
		_, err := peer.writeTUN(scratch, MessageTransportOffsetContent)
		if err != nil && !device.isClosed() {
			device.log.Errorf("Failed to write packets to TUN device: %v", err)
		}
	}
	for _, elem := range elems {
		device.PutInboundElement(elem)
	}
}

// lx:begin awg3 (AmneziaWG — ported from amneziawg-go v3 device/receive.go)

func applyHash(dst, src, hash []byte) {
	for i := range len(dst) {
		dst[i] = src[i] ^ hash[i]
	}
}

// classifyTransportByIndex is the lx transport-first candidate (SPEC 081). A
// data packet always carries one of our live receiver indices — a 32-bit value
// a foreign datagram cannot hold by accident — so a datagram whose unmasked
// type word is in H4 and whose unmasked receiver index resolves to a live
// keypair is a transport message, whatever its size. The reference order
// (DeterminePacketTypeAndPadding) tries the handshake kinds first, by size and
// type word alone, and with a wide H range claims real data packets: every one
// of exactly S1+148 / S2+92 / S3+64 bytes (AWG2), and under random_trailers
// every one longer than that (AWG 3.1). headerHash is the header-cipher
// keystream for bytes 0..8 (zeros when header protection is off). Returns the
// index-table entry, the transport padding and whether it matched; on a miss
// the caller falls back to the reference order, so nothing it accepted before
// is refused now.
func (device *Device) classifyTransportByIndex(packet []byte, headerHash []byte) (IndexTableEntry, uint32, bool) {
	padding := device.paddings.transport.Load()
	if len(packet) < int(padding)+MessageTransportSize {
		return IndexTableEntry{}, 0, false
	}
	var header [8]byte
	applyHash(header[:], packet[padding:padding+8], headerHash[:8])
	if !device.headers.transport.Load().Contains(binary.LittleEndian.Uint32(header[:4])) {
		return IndexTableEntry{}, 0, false
	}
	entry := device.indexTable.Lookup(binary.LittleEndian.Uint32(header[4:8]))
	if entry.keypair == nil {
		return IndexTableEntry{}, 0, false
	}
	return entry, padding, true
}

// DeterminePacketTypeAndPadding classifies a datagram by the AmneziaWG
// parameters in the reference (amneziawg-go) order: for each message kind, the
// type word is read at that kind's padding offset (S1–S4), unmasked with
// typeHash (the AWG 3.x header protection keystream, all zeros when off) and
// matched against the kind's magic range (H1–H4). Fixed-size messages must
// match their size exactly, or — with random_trailers — exceed it (the trailer
// is discarded by the caller). Returns the message size (without
// padding/trailer), its canonical type and the padding length;
// MessageUnknownType when nothing matched. Runs after classifyTransportByIndex
// missed (SPEC 081).
func (device *Device) DeterminePacketTypeAndPadding(packet []byte, typeHash []byte) (int, uint32, uint32) {
	var headerBytes [4]byte
	var padding uint32
	var header UintRange
	var expectedSize int

	size := len(packet)
	randomTrailers := device.randomTrailers.Load()

	padding = device.paddings.init.Load()
	header = device.headers.init.Load()
	expectedSize = int(padding) + MessageInitiationSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageInitiationSize, MessageInitiationType, padding
		}
	}

	padding = device.paddings.response.Load()
	header = device.headers.response.Load()
	expectedSize = int(padding) + MessageResponseSize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageResponseSize, MessageResponseType, padding
		}
	}

	padding = device.paddings.cookie.Load()
	header = device.headers.cookie.Load()
	expectedSize = int(padding) + MessageCookieReplySize

	if size == expectedSize || randomTrailers && size > expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageCookieReplySize, MessageCookieReplyType, padding
		}
	}

	padding = device.paddings.transport.Load()
	header = device.headers.transport.Load()
	expectedSize = int(padding) + MessageTransportSize

	if size >= expectedSize {
		applyHash(headerBytes[:], packet[padding:padding+4], typeHash)
		if header.Contains(binary.LittleEndian.Uint32(headerBytes[:])) {
			return MessageTransportSize, MessageTransportType, padding
		}
	}

	return 0, MessageUnknownType, 0
}

// lx:end awg3
