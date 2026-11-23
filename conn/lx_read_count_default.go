//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 158 part 2.
 */

package conn

import "syscall"

func disableReceiveOffload(syscall.RawConn) error {
	return nil
}
