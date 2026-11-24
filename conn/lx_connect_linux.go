/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — a connected socket for a bind that serves one peer.
 *
 * An unconnected socket takes a destination, and on Linux a source, with
 * every datagram, and the kernel looks the route up each time. A connected
 * one keeps the route. Next to the cleanup of the message set this was the
 * rest of the gap between a tunnel on its own socket and the same tunnel
 * through a connected detour.
 *
 * The connection is an optimisation and nothing depends on it: whenever it
 * is in doubt the socket is disconnected and the datagram goes out the way
 * it always did.
 */

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	// connectRetryInterval is how long a socket stays unconnected after an
	// error made the connection suspect. A path that keeps failing then
	// costs a connect per second, not per datagram.
	connectRetryInterval = time.Second
	// connectListenInterval is how long it stays unconnected after the
	// device reset the path. A connected socket does not hear a peer that
	// answers from a new address; this is the window in which the answer to
	// the handshake being retried can arrive from anywhere, and the device
	// roam to it.
	connectListenInterval = 3 * time.Second
)

type connectState struct {
	enabled atomic.Bool
	// logf, when set, receives a line for every connect and disconnect.
	logf atomic.Pointer[func(format string, args ...any)]
	// gate is held shared by a sender from the moment it finds its socket
	// connected until its datagrams are written, and exclusively to connect
	// or disconnect. A datagram built without a destination therefore never
	// meets a socket that lost its peer. It guards everything below.
	gate sync.RWMutex
	// wantPort is the port pinPort chose for the Open in progress, and
	// pinned is whether the sockets ended up bound to it.
	wantPort int
	pinned   bool
	v4       connectFamily
	v6       connectFamily
}

// connectFamily is the state of one socket.
type connectFamily struct {
	// conn is the socket of the current Open. A sender that still holds the
	// previous one must not act on this state.
	conn *net.UDPConn
	// peer is what the socket is connected to, or the zero value.
	peer netip.AddrPort
	// foreign: a second destination was seen while connected. The bind does
	// not serve a single peer after all, and the socket stays unconnected
	// until reopened.
	foreign bool
	// retryAt is when the next connect may be attempted.
	retryAt time.Time
}

func (c *connectState) family(is6 bool) *connectFamily {
	if is6 {
		return &c.v6
	}
	return &c.v4
}

func (c *connectState) name(f *connectFamily) string {
	if f == &c.v6 {
		return "ipv6"
	}
	return "ipv4"
}

func (c *connectState) log(format string, args ...any) {
	if logf := c.logf.Load(); logf != nil {
		(*logf)("connected socket: "+format, args...)
	}
}

// reset forgets the sockets of the previous Open.
func (c *connectState) reset() {
	c.gate.Lock()
	c.wantPort, c.pinned = 0, false
	c.v4, c.v6 = connectFamily{}, connectFamily{}
	c.gate.Unlock()
}

// SetConnectedSocket lets the bind connect its sockets to the peer. The
// caller promises what SetSinglePeerMode promises: one peer with a fixed
// endpoint. The kernel then drops datagrams from any other source. A peer
// that moves is heard again after the handshake retry that follows: the
// device resets the path, and the socket listens unconnected for
// connectListenInterval.
func (s *StdNetBind) SetConnectedSocket() {
	s.connect.enabled.Store(true)
}

// SetConnectedSocketLog sets where the bind reports each connect and
// disconnect of its sockets, with the reason. It is meant for a debug log:
// a peer that does not answer handshakes produces a disconnect every few
// seconds.
func (s *StdNetBind) SetConnectedSocketLog(logf func(format string, args ...any)) {
	if logf == nil {
		s.connect.logf.Store(nil)
		return
	}
	s.connect.logf.Store(&logf)
}

// ConnectedPeer returns what the socket of the given family is connected to,
// or the zero value.
func (s *StdNetBind) ConnectedPeer(is6 bool) netip.AddrPort {
	s.connect.gate.RLock()
	defer s.connect.gate.RUnlock()
	return s.connect.family(is6).peer
}

// pinPort turns "any port" into a number for a bind that may connect.
//
// Disconnecting a socket whose port the kernel picked gives the port back:
// the socket is unhashed and gets another one on its next send, and whatever
// the peer sends to the old one meanwhile is lost. A port bound by number
// stays. So the port is picked here, from the same ephemeral range, with a
// socket that is closed again; Open retries if someone took it in between.
func (s *StdNetBind) pinPort(port int) int {
	if !s.connect.enabled.Load() {
		return port
	}
	if port == 0 {
		probe, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err == nil {
			port = probe.LocalAddr().(*net.UDPAddr).Port
			probe.Close()
		}
	}
	s.connect.gate.Lock()
	s.connect.wantPort = port
	s.connect.gate.Unlock()
	return port
}

// connectedReceive takes over the sockets Open has just created, bound to
// port, and wraps their receive functions (IPv4 first, where there is one).
//
// The bind may connect only if the port is the one pinPort chose: Open falls
// back to a kernel-picked port when a family is unavailable.
//
// A connected socket reports the ICMP error of an earlier datagram on the
// next read. The device takes such an error for a dead socket and stops
// reading for good, while all it says is what a missing reply already says.
// The read reports no datagrams instead, and the socket is disconnected, so
// that a peer that stays unreachable does not keep producing them.
func (s *StdNetBind) connectedReceive(receiveFuncs []ReceiveFunc, v4conn, v6conn *net.UDPConn, port int) []ReceiveFunc {
	if !s.connect.enabled.Load() {
		return receiveFuncs
	}
	state := &s.connect
	state.gate.Lock()
	state.pinned = state.wantPort != 0 && port == state.wantPort
	state.v4.conn, state.v6.conn = v4conn, v6conn
	wantPort, pinned := state.wantPort, state.pinned
	state.gate.Unlock()
	if !pinned {
		state.log("off: the sockets are bound to port %d, not the chosen %d", port, wantPort)
	}

	wrap := func(receive ReceiveFunc, conn *net.UDPConn, family *connectFamily) ReceiveFunc {
		return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, error) {
			count, err := receive(bufs, sizes, endpoints)
			if err != nil && reportedByICMP(err) {
				state.abandon(conn, family, "read", err)
				return 0, nil
			}
			return count, err
		}
	}
	next := 0
	if v4conn != nil {
		receiveFuncs[next] = wrap(receiveFuncs[next], v4conn, &state.v4)
		next++
	}
	if v6conn != nil {
		receiveFuncs[next] = wrap(receiveFuncs[next], v6conn, &state.v6)
	}
	return receiveFuncs
}

// ResetPath implements PathResetter: a connected socket keeps the source
// address and the route chosen at connect time, which is what goes stale when
// the network changes, and hears no one but the address it is connected to.
func (s *StdNetBind) ResetPath() {
	if !s.connect.enabled.Load() {
		return
	}
	listenUntil := time.Now().Add(connectListenInterval)
	s.connect.gate.Lock()
	v4 := s.connect.v4.release(listenUntil)
	v6 := s.connect.v6.release(listenUntil)
	s.connect.gate.Unlock()
	for _, released := range []struct {
		name string
		peer netip.AddrPort
	}{{"ipv4", v4}, {"ipv6", v6}} {
		if released.peer.IsValid() {
			s.connect.log("%s disconnected from %s: path reset (handshake unanswered or route change), listening to any address for %s",
				released.name, released.peer, connectListenInterval)
		}
	}
}

// release disconnects the socket and returns what it was connected to, or
// the zero value if it was not. The caller holds the gate exclusively.
func (f *connectFamily) release(retryAt time.Time) netip.AddrPort {
	peer := f.peer
	if !peer.IsValid() {
		return peer
	}
	f.peer = netip.AddrPort{}
	f.retryAt = retryAt
	disconnectSocket(f.conn)
	return peer
}

// abandon disconnects conn after an error on the given operation made its
// connection suspect.
func (c *connectState) abandon(conn *net.UDPConn, f *connectFamily, op string, cause error) {
	var peer netip.AddrPort
	c.gate.Lock()
	if f.conn == conn {
		peer = f.release(time.Now().Add(connectRetryInterval))
	}
	c.gate.Unlock()
	if peer.IsValid() {
		c.log("%s disconnected from %s: %s: %v, retry in %s", c.name(f), peer, op, cause, connectRetryInterval)
	}
}

// acquire reports whether conn is connected to peer, connecting it first if
// it may. On true the caller holds the gate shared and must release it.
//
// A bind that gave the connection up comes here on every send, so everything
// that rules a connect out is decided under the shared lock.
func (c *connectState) acquire(conn *net.UDPConn, f *connectFamily, peer netip.AddrPort) bool {
	for attempt := 0; ; attempt++ {
		c.gate.RLock()
		if f.conn == conn && f.peer == peer {
			return true
		}
		ruledOut := attempt > 0 || !c.mayConnect(conn, f, peer)
		c.gate.RUnlock()
		if ruledOut || !c.establish(conn, f, peer) {
			return false
		}
	}
}

// mayConnect reports whether establish has anything to do: connect, or
// disconnect from another peer. The caller holds the gate.
func (c *connectState) mayConnect(conn *net.UDPConn, f *connectFamily, peer netip.AddrPort) bool {
	// a scoped address needs its zone in the connect call; not worth it here
	if !c.pinned || f.conn != conn || f.foreign || !peer.IsValid() || peer.Addr().Zone() != "" {
		return false
	}
	return f.peer.IsValid() || f.retryAt.IsZero() || !time.Now().Before(f.retryAt)
}

func (c *connectState) establish(conn *net.UDPConn, f *connectFamily, peer netip.AddrPort) bool {
	var line string
	c.gate.Lock()
	switch {
	case !c.mayConnect(conn, f, peer):
	case f.peer == peer:
	case f.peer.IsValid():
		previous := f.release(time.Time{})
		f.foreign = true
		line = fmt.Sprintf("%s disconnected from %s: a second destination %s, unconnected until the bind is reopened", c.name(f), previous, peer)
	default:
		if err := connectSocket(conn, peer); err != nil {
			f.retryAt = time.Now().Add(connectRetryInterval)
			line = fmt.Sprintf("%s connect to %s: %v, retry in %s", c.name(f), peer, err, connectRetryInterval)
		} else {
			f.peer = peer
			line = fmt.Sprintf("%s connected to %s", c.name(f), peer)
		}
	}
	connected := f.conn == conn && f.peer == peer
	c.gate.Unlock()
	if line != "" {
		c.log("%s", line)
	}
	return connected
}

func connectSocket(conn *net.UDPConn, peer netip.AddrPort) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var address unix.Sockaddr
	if peer.Addr().Is4() {
		address = &unix.SockaddrInet4{Port: int(peer.Port()), Addr: peer.Addr().As4()}
	} else {
		address = &unix.SockaddrInet6{Port: int(peer.Port()), Addr: peer.Addr().As16()}
	}
	var connectErr error
	err = rawConn.Control(func(fd uintptr) {
		connectErr = unix.Connect(int(fd), address)
	})
	if err != nil {
		return err
	}
	return connectErr
}

// disconnectSocket dissolves the association. The socket keeps its port,
// which was bound by number (pinPort), and having been bound to the wildcard
// address it picks its source per datagram again.
func disconnectSocket(conn *net.UDPConn) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		address := unix.RawSockaddr{Family: unix.AF_UNSPEC}
		//nolint:staticcheck
		_, _, _ = unix.Syscall(unix.SYS_CONNECT, fd, uintptr(unsafe.Pointer(&address)), unsafe.Sizeof(address))
	})
}

// sendConnected sends bufs over the connected socket, without a destination
// or a source per datagram. It reports false when the caller has to send them
// the ordinary way: the socket is not connected to this peer, or the send
// failed for a reason that may lie in the connection. In the second case
// datagrams that did go out are sent twice, which the receiver's replay
// window absorbs; that is cheaper than losing the rest.
func (s *StdNetBind) sendConnected(conn *net.UDPConn, writer batchWriter, is6, offload bool, bufs [][]byte, endpoint *StdNetEndpoint, offset int, msgs []ipv6.Message) (bool, error) {
	if !s.connect.enabled.Load() {
		return false, nil
	}
	family := s.connect.family(is6)
	if !s.connect.acquire(conn, family, endpoint.AddrPort) {
		return false, nil
	}
	var filled int
	if offload {
		// the caller's endpoint carries a sticky source, which a connected
		// socket must not be given
		bare := StdNetEndpoint{AddrPort: endpoint.AddrPort}
		filled = coalesceMessages(nil, &bare, bufs, offset, msgs, setGSOSize)
	} else {
		filled = len(bufs)
		for i := range bufs {
			setMessageBuffer(&msgs[i], bufs[i][offset:])
		}
	}
	// coalesceMessages stores its *net.UDPAddr, and a nil one is still an
	// address to the socket layer
	for i := 0; i < filled; i++ {
		msgs[i].Addr = nil
	}
	err := s.send(conn, writer, msgs[:filled])
	s.connect.gate.RUnlock()
	if err == nil {
		return true, nil
	}
	if offload && errShouldDisableUDPGSO(err) {
		// the ordinary path owns turning offload off and reporting it
		return false, nil
	}
	if !connectionSuspect(err) {
		return true, err
	}
	s.connect.abandon(conn, family, "send", err)
	return false, nil
}

// reportedByICMP reports whether err is one the kernel raises on a connected
// socket for an ICMP error received about an earlier datagram (the values of
// icmp_err_convert and icmpv6_err_convert, and EMSGSIZE). Each is raised
// once, so a read that returns one is not a broken socket.
func reportedByICMP(err error) bool {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EHOSTDOWN, unix.ENONET,
		unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EPROTO, unix.EACCES, unix.EMSGSIZE:
		return true
	}
	return false
}

// connectionSuspect reports whether a failed send may be the connection's
// fault rather than the datagram's: an ICMP error for an earlier one, a
// source address or a route that is gone, or a socket that is not connected
// after all.
func connectionSuspect(err error) bool {
	if reportedByICMP(err) {
		return true
	}
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case unix.EADDRNOTAVAIL, unix.EINVAL, unix.ENETDOWN, unix.EDESTADDRREQ, unix.ENOTCONN:
		return true
	}
	return false
}
