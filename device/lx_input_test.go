package device

// inputPacket injects one whole IP packet the way sing-box's stack does since
// upstream replaced InputPacket with the batched InputPackets. Test helper only.
func inputPacket(device *Device, destination []byte, packet []byte) {
	device.InputPackets([]*InputPacketRef{{Destination: destination, PacketSlices: [][]byte{packet}}})
}
