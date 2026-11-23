/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160.
 */

package device

import "github.com/sagernet/wireguard-go/conn"

// resetBindPath tells the bind that what it remembers about the path to a
// peer is suspect. It is called where an endpoint's sticky source is cleared,
// for the same reason: the handshake is not being answered, or the routes
// changed, and a stale source address is the first thing to rule out. A bind
// with a connected socket holds one that ClearSrc cannot reach.
//
// The caller holds device.net for reading.
func (device *Device) resetBindPath() {
	if resetter, ok := device.net.bind.(conn.PathResetter); ok {
		resetter.ResetPath()
	}
}
