//go:build !linux

/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — see lx_connect_linux.go. On macOS the bind connects in
 * single-peer mode by itself (msgx_darwin.go); elsewhere it never does.
 */

package conn

import (
	"net/netip"

	"golang.org/x/net/ipv6"
)

type connectState struct{}

func (c *connectState) reset() {}

// SetConnectedSocket is a no-op on this platform.
func (s *StdNetBind) SetConnectedSocket() {}

// SetConnectedSocketLog is a no-op on this platform.
func (s *StdNetBind) SetConnectedSocketLog(logf func(format string, args ...any)) {}

// ConnectedPeer always returns the zero value on this platform.
func (s *StdNetBind) ConnectedPeer(is6 bool) netip.AddrPort {
	return netip.AddrPort{}
}

func (s *StdNetBind) pinPort(port int) int {
	return port
}

func (s *StdNetBind) connectedReceive(receiveFuncs []ReceiveFunc, v4, v6 []*stdNetSocket, port int) []ReceiveFunc {
	return receiveFuncs
}

func (s *StdNetBind) sendConnected(sock *stdNetSocket, is6, offload bool, bufs [][]byte, endpoint *StdNetEndpoint, offset int, msgs []ipv6.Message) (bool, error) {
	return false, nil
}
