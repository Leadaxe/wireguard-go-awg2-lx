/* SPDX-License-Identifier: MIT
 *
 * lx: sing-box-lx SPEC 101 — the handshake burst leaves one datagram per bind
 * send.
 */

package device

import (
	"github.com/sagernet/wireguard-go/conn"
)

// sendHandshakeDatagrams sends the masquerade burst and the initiation that
// closes it, each datagram in a bind send of its own.
//
// StdNetBind coalesces consecutive datagrams of one send into a single UDP GSO
// message whenever each next one is not longer than the first, and takes the
// first one's length as the segment size. Jc junk is as short as one byte, so
// a burst handed over in one send reaches the NIC as a segmentation request
// with a 1-3 byte segment size. Drivers that offload UDP segmentation set
// their own lower bound, if any: stmmac before its 2026 TSO fixes has none and
// the MAC stalls until the transmit watchdog resets it; on a NIC without TX
// checksum offload the kernel refuses the send and the bind turns UDP GSO off
// for the socket, data path included. A datagram sent alone carries no
// segmentation request. The burst is a few datagrams per handshake, so there
// is nothing for coalescing to gain.
//
// The first failed send ends the burst, as it did when the burst was one send.
//
// lx: SPEC 101
func (peer *Peer) sendHandshakeDatagrams(buffers [][]byte, candidates []conn.Endpoint) error {
	for i := range buffers {
		var err error
		if len(candidates) > 0 {
			err = peer.sendHandshakeBuffers(buffers[i:i+1], candidates)
		} else {
			err = peer.SendBuffers(buffers[i : i+1])
		}
		err = unwrapGSODisabled(peer.device.log, err)
		if err != nil {
			return err
		}
	}
	return nil
}
