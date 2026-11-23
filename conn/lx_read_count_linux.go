/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 158 part 2.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// disableReceiveOffload undoes the UDP_GRO that controlFns enabled just
// before. A kernel without the option was never asked for it, so a failure
// to clear it is not an error; supportsUDPOffload reads the result back.
func disableReceiveOffload(conn syscall.RawConn) error {
	return conn.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 0)
	})
}
