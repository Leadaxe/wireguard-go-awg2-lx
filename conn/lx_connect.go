/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — a connected socket for a bind that serves one peer.
 */

package conn

// PathResetter is implemented by a Bind that remembers something about the
// path to a peer beyond what the Endpoint carries. The device calls ResetPath
// where it clears an endpoint's sticky source address: a handshake that is
// not answered, a route change. Whatever was remembered may be the reason.
type PathResetter interface {
	ResetPath()
}
