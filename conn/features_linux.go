/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

const (
	// TODO: upstream to x/sys/unix
	socketOptionLevelUDP   = 17
	socketOptionUDPSegment = 103
	socketOptionUDPGRO     = 104
)

func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPSegment)
		if errSyscall != nil {
			return
		}
		txOffload = true
		// lx(010): never advertise RX offload on android. runtime.GOOS=="android"
		// (not "linux"), so the GRO receive dispatcher in bind_std.go (gated on
		// GOOS=="linux") is dead there — a coalesced GRO super-packet would be read
		// as one datagram and corrupt the WG transport stream, killing download.
		// Confirmed on device (CPH2411/Android-15: rxOffload=true, dispatch=single).
		// TX is left untouched. See SPECS/010-WG_ENDPOINT_GRO_SPLIT_BRAIN.
		if runtime.GOOS == "android" {
			return
		}
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO)
		if errSyscall != nil {
			return
		}
		rxOffload = opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}
