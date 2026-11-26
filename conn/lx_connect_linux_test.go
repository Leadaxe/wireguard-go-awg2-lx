/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — the connected socket.
 */

package conn

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const connectTestOffset = 16

type connectedFixture struct {
	t        *testing.T
	bind     *StdNetBind
	receive  []ReceiveFunc
	port     uint16
	bufs     [][]byte
	sizes    []int
	eps      []Endpoint
	received chan []byte
	failed   chan error
	stopped  chan struct{}
}

// stop closes the bind and waits for the reader, so that no message set is
// in use any more.
func (f *connectedFixture) stop() {
	f.t.Helper()
	f.bind.Close()
	select {
	case <-f.stopped:
	case <-time.After(5 * time.Second):
		f.t.Fatal("the reader did not stop")
	}
}

func newConnectedFixture(t *testing.T, connect bool) *connectedFixture {
	t.Helper()
	bind := NewStdNetBind(nil).(*StdNetBind)
	bind.SetSinglePeerMode()
	if connect {
		bind.SetConnectedSocket()
	}
	f := &connectedFixture{t: t, bind: bind}
	f.open()
	t.Cleanup(func() { bind.Close() })
	return f
}

func (f *connectedFixture) open() {
	f.t.Helper()
	receive, port, err := f.bind.Open(0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.receive, f.port = receive, port
	batch := f.bind.BatchSize()
	f.bufs = make([][]byte, batch)
	for i := range f.bufs {
		f.bufs[i] = make([]byte, 65535)
	}
	f.sizes = make([]int, batch)
	f.eps = make([]Endpoint, batch)
	f.received = make(chan []byte, 64)
	f.failed = make(chan error, 1)
	stopped := make(chan struct{})
	f.stopped = stopped
	receiveV4 := receive[0]
	go func() {
		defer close(stopped)
		for {
			n, err := receiveV4(f.bufs, f.sizes, f.eps)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					f.failed <- err
				}
				return
			}
			for i := 0; i < n; i++ {
				if f.sizes[i] > 0 {
					f.received <- bytes.Clone(f.bufs[i][:f.sizes[i]])
				}
			}
		}
	}()
}

func (f *connectedFixture) send(to *net.UDPConn, payloads ...[]byte) {
	f.t.Helper()
	bufs := make([][]byte, len(payloads))
	for i, payload := range payloads {
		bufs[i] = append(make([]byte, connectTestOffset), payload...)
	}
	endpoint := &StdNetEndpoint{AddrPort: loopbackAddrPort(to)}
	err := f.bind.Send(bufs, endpoint, connectTestOffset)
	var gsoDisabled ErrUDPGSODisabled
	if err != nil && (!errors.As(err, &gsoDisabled) || gsoDisabled.RetryErr != nil) {
		f.t.Fatal(err)
	}
}

func (f *connectedFixture) peerName() (netip.AddrPort, bool) {
	f.t.Helper()
	rawConn, err := f.bind.ipv4.SyscallConn()
	if err != nil {
		f.t.Fatal(err)
	}
	var (
		name    unix.Sockaddr
		nameErr error
	)
	rawConn.Control(func(fd uintptr) {
		name, nameErr = unix.Getpeername(int(fd))
	})
	if nameErr != nil {
		if !errors.Is(nameErr, unix.ENOTCONN) {
			f.t.Fatal(nameErr)
		}
		return netip.AddrPort{}, false
	}
	inet4 := name.(*unix.SockaddrInet4)
	return netip.AddrPortFrom(netip.AddrFrom4(inet4.Addr), uint16(inet4.Port)), true
}

// boundPort asks the kernel, not the address net.UDPConn remembers.
func (f *connectedFixture) boundPort() int {
	f.t.Helper()
	rawConn, err := f.bind.ipv4.SyscallConn()
	if err != nil {
		f.t.Fatal(err)
	}
	var (
		name    unix.Sockaddr
		nameErr error
	)
	rawConn.Control(func(fd uintptr) {
		name, nameErr = unix.Getsockname(int(fd))
	})
	if nameErr != nil {
		f.t.Fatal(nameErr)
	}
	return name.(*unix.SockaddrInet4).Port
}

// allowConnect ends whatever wait keeps the socket unconnected.
func (f *connectedFixture) allowConnect() {
	f.bind.connect.gate.Lock()
	f.bind.connect.v4.retryAt = time.Time{}
	f.bind.connect.gate.Unlock()
}

func (f *connectedFixture) requireConnected(to *net.UDPConn) {
	f.t.Helper()
	name, connected := f.peerName()
	if !connected || name != loopbackAddrPort(to) {
		f.t.Fatalf("socket is connected to %v (%v), want %v", name, connected, loopbackAddrPort(to))
	}
}

func (f *connectedFixture) requireUnconnected() {
	f.t.Helper()
	if name, connected := f.peerName(); connected {
		f.t.Fatalf("socket is connected to %v", name)
	}
}

func (f *connectedFixture) requireNoReceiveError() {
	f.t.Helper()
	select {
	case err := <-f.failed:
		f.t.Fatalf("the receive function returned %v", err)
	default:
	}
}

func loopbackSink(t *testing.T) *net.UDPConn {
	t.Helper()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	return sink
}

func loopbackAddrPort(conn *net.UDPConn) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(conn.LocalAddr().(*net.UDPAddr).Port))
}

func requireArrives(t *testing.T, sink *net.UDPConn, payloads ...[]byte) {
	t.Helper()
	sink.SetReadDeadline(time.Now().Add(5 * time.Second))
	packet := make([]byte, 65535)
	for i, payload := range payloads {
		n, err := sink.Read(packet)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		if !bytes.Equal(packet[:n], payload) {
			t.Fatalf("datagram %d arrived changed or out of order (%d bytes, want %d)", i, n, len(payload))
		}
	}
}

func requireReceived(t *testing.T, f *connectedFixture, payload []byte) {
	t.Helper()
	select {
	case got := <-f.received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("received %d bytes, want %d", len(got), len(payload))
		}
	case err := <-f.failed:
		t.Fatalf("the receive function returned %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was received")
	}
}

func TestConnectedSocketOffByDefault(t *testing.T) {
	f := newConnectedFixture(t, false)
	sink := loopbackSink(t)
	payload := bytes.Repeat([]byte{1}, 500)
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireUnconnected()
}

func TestConnectedSocketSend(t *testing.T) {
	f := newConnectedFixture(t, true)
	sets := trackMessageSets(f.bind)
	sink := loopbackSink(t)

	single := bytes.Repeat([]byte{1}, 500)
	f.send(sink, single)
	requireArrives(t, sink, single)
	f.requireConnected(sink)

	// a burst that segmentation offload coalesces where the kernel has it
	burst := make([][]byte, 20)
	for i := range burst {
		burst[i] = bytes.Repeat([]byte{byte(i + 2)}, 300+(i/5)*50)
	}
	f.send(sink, burst...)
	requireArrives(t, sink, burst...)
	f.requireConnected(sink)
	f.stop()
	requireSetsPristine(t, sets())
}

// The peer's replies are delivered with its address; a datagram from anyone
// else is not, which is the price of the connection.
func TestConnectedSocketReceive(t *testing.T) {
	f := newConnectedFixture(t, true)
	sink := loopbackSink(t)
	stranger := loopbackSink(t)
	f.send(sink, []byte("hello, peer"))
	requireArrives(t, sink, []byte("hello, peer"))

	bindAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.port)}
	if _, err := stranger.WriteToUDP(bytes.Repeat([]byte{9}, 100), bindAddr); err != nil {
		t.Fatal(err)
	}
	reply := bytes.Repeat([]byte{7}, 700)
	if _, err := sink.WriteToUDP(reply, bindAddr); err != nil {
		t.Fatal(err)
	}
	requireReceived(t, f, reply)
	if got := f.eps[0].(*StdNetEndpoint).AddrPort; got != loopbackAddrPort(sink) {
		t.Fatalf("reply is attributed to %v", got)
	}

	// the endpoint of a received datagram carries a sticky source; sending to
	// it must still go over the connection
	again := bytes.Repeat([]byte{3}, 400)
	f.send(sink, again)
	requireArrives(t, sink, again)
	f.requireConnected(sink)
}

func TestConnectedSocketSecondDestination(t *testing.T) {
	f := newConnectedFixture(t, true)
	first, second := loopbackSink(t), loopbackSink(t)
	a, b := bytes.Repeat([]byte{1}, 300), bytes.Repeat([]byte{2}, 300)

	f.send(first, a)
	requireArrives(t, first, a)
	f.requireConnected(first)

	f.send(second, b)
	requireArrives(t, second, b)
	f.requireUnconnected()

	// the bind serves two destinations: it stays unconnected for both
	f.send(first, a)
	requireArrives(t, first, a)
	f.send(second, b)
	requireArrives(t, second, b)
	f.requireUnconnected()

	// a datagram from the second one is heard again
	reply := bytes.Repeat([]byte{5}, 200)
	if _, err := second.WriteToUDP(reply, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.port)}); err != nil {
		t.Fatal(err)
	}
	requireReceived(t, f, reply)

	// new sockets start over
	f.stop()
	f.open()
	f.send(first, a)
	requireArrives(t, first, a)
	f.requireConnected(first)
}

func TestConnectedSocketResetPath(t *testing.T) {
	f := newConnectedFixture(t, true)
	sink := loopbackSink(t)
	payload := bytes.Repeat([]byte{1}, 300)
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireConnected(sink)

	f.bind.ResetPath()
	f.requireUnconnected()

	// the socket kept its port: before it sends anything, it hears a
	// datagram sent there, now from anyone
	if got := f.boundPort(); got != int(f.port) {
		t.Fatalf("the socket moved from port %d to %d", f.port, got)
	}
	stranger := loopbackSink(t)
	knock := bytes.Repeat([]byte{9}, 100)
	if _, err := stranger.WriteToUDP(knock, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.port)}); err != nil {
		t.Fatal(err)
	}
	requireReceived(t, f, knock)

	// it listens that way for a while, then connects again
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireUnconnected()
	f.allowConnect()
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireConnected(sink)
	if got := f.boundPort(); got != int(f.port) {
		t.Fatalf("the socket moved from port %d to %d", f.port, got)
	}
}

// The peer moves to another address. A connected socket does not hear it
// there; after the device reset the path it does, and the next send follows
// the peer without the bind taking it for a second destination.
func TestConnectedSocketPeerMoves(t *testing.T) {
	f := newConnectedFixture(t, true)
	before, after := loopbackSink(t), loopbackSink(t)
	payload := bytes.Repeat([]byte{1}, 300)
	f.send(before, payload)
	requireArrives(t, before, payload)
	f.requireConnected(before)

	f.bind.ResetPath()
	reply := bytes.Repeat([]byte{7}, 200)
	if _, err := after.WriteToUDP(reply, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.port)}); err != nil {
		t.Fatal(err)
	}
	requireReceived(t, f, reply)

	f.allowConnect()
	f.send(after, payload)
	requireArrives(t, after, payload)
	f.requireConnected(after)
}

// Every connect and disconnect reaches the log with what caused it, and
// nothing else does.
func TestConnectedSocketLog(t *testing.T) {
	f := newConnectedFixture(t, true)
	var mu sync.Mutex
	var lines []string
	f.bind.SetConnectedSocketLog(func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	})
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		taken := lines
		lines = nil
		return taken
	}
	sink := loopbackSink(t)
	peer := loopbackAddrPort(sink).String()
	payload := bytes.Repeat([]byte{1}, 300)

	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	requireLines(t, take(), "connected socket: ipv4 connected to "+peer)

	f.bind.ResetPath()
	f.bind.ResetPath()
	requireLines(t, take(), "connected socket: ipv4 disconnected from "+peer+": path reset (handshake unanswered or route change), listening to any address for 3s")

	f.allowConnect()
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	take()
	f.bind.connect.abandon(f.bind.ipv4, &f.bind.connect.v4, "read", unix.ECONNREFUSED)
	requireLines(t, take(), "connected socket: ipv4 disconnected from "+peer+": read: connection refused, retry in 1s")

	f.allowConnect()
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	take()
	other := loopbackSink(t)
	f.send(other, payload)
	requireArrives(t, other, payload)
	requireLines(t, take(), "connected socket: ipv4 disconnected from "+peer+": a second destination "+loopbackAddrPort(other).String()+", unconnected until the bind is reopened")

}

func requireLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("log lines %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("log line %q, want %q", got[i], want[i])
		}
	}
}

// After the connection was given up the socket stays unconnected for a
// while, and sends go the ordinary way.
func TestConnectedSocketRetryInterval(t *testing.T) {
	f := newConnectedFixture(t, true)
	sink := loopbackSink(t)
	payload := bytes.Repeat([]byte{1}, 300)
	f.send(sink, payload)
	requireArrives(t, sink, payload)

	f.bind.connect.abandon(f.bind.ipv4, &f.bind.connect.v4, "send", unix.EHOSTUNREACH)
	f.requireUnconnected()
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireUnconnected()

	f.allowConnect()
	f.send(sink, payload)
	requireArrives(t, sink, payload)
	f.requireConnected(sink)
}

// Nobody listens on the peer's port: the kernel answers with an ICMP error,
// which a connected socket reports on a later call. The device must not see
// it as a dead socket, and the tunnel must work once the peer is there.
func TestConnectedSocketRefused(t *testing.T) {
	f := newConnectedFixture(t, true)
	gone := loopbackSink(t)
	address := gone.LocalAddr().(*net.UDPAddr)
	gone.Close()

	payload := bytes.Repeat([]byte{1}, 300)
	endpoint := &StdNetEndpoint{AddrPort: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(address.Port))}
	// far more of them than any bound on consecutive errors could be: a
	// peer that is down stays down for a while
	var refused int
	for i := 0; i < 60; i++ {
		// each send connects and draws an ICMP error; it surfaces in the
		// reader or in the next send, and either way the socket is
		// disconnected and nothing is reported
		f.allowConnect()
		buf := append(make([]byte, connectTestOffset), payload...)
		if err := f.bind.Send([][]byte{buf}, endpoint, connectTestOffset); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, connected := f.peerName(); !connected {
			refused++
		}
	}
	f.requireNoReceiveError()
	if refused < 30 {
		t.Fatalf("the socket was found disconnected after %d of 60 refused sends", refused)
	}
	f.allowConnect()

	back, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Skipf("the port was taken meanwhile: %v", err)
	}
	defer back.Close()
	// the last ICMP error may still be pending and cost one datagram
	deadline := time.Now().Add(5 * time.Second)
	packet := make([]byte, 65535)
	for {
		buf := append(make([]byte, connectTestOffset), payload...)
		if err = f.bind.Send([][]byte{buf}, endpoint, connectTestOffset); err != nil {
			t.Fatal(err)
		}
		back.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, readErr := back.Read(packet)
		if readErr == nil {
			if !bytes.Equal(packet[:n], payload) {
				t.Fatal("datagram arrived changed")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing arrives after the peer came back")
		}
	}
	reply := bytes.Repeat([]byte{7}, 200)
	if _, err = back.WriteToUDP(reply, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(f.port)}); err != nil {
		t.Fatal(err)
	}
	requireReceived(t, f, reply)
	f.requireNoReceiveError()
}

func TestConnectionSuspect(t *testing.T) {
	wrap := func(errno unix.Errno) error {
		return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmmsg", errno)}
	}
	for _, errno := range []unix.Errno{unix.EADDRNOTAVAIL, unix.EINVAL, unix.ENETUNREACH, unix.EHOSTUNREACH, unix.ECONNREFUSED, unix.EMSGSIZE} {
		if !connectionSuspect(wrap(errno)) {
			t.Errorf("%v is not taken for a connection error", errno)
		}
	}
	// a read must only swallow what an ICMP error can cause: anything that
	// would repeat on the next read has to reach the device
	for _, errno := range []unix.Errno{unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.EACCES, unix.EMSGSIZE} {
		if !reportedByICMP(wrap(errno)) {
			t.Errorf("%v is not taken for an ICMP error", errno)
		}
	}
	for _, errno := range []unix.Errno{unix.EINVAL, unix.EBADF, unix.ENOTCONN, unix.ENOMEM, unix.EADDRNOTAVAIL} {
		if reportedByICMP(wrap(errno)) {
			t.Errorf("%v is taken for an ICMP error", errno)
		}
	}
	for _, err := range []error{wrap(unix.EPERM), wrap(unix.EIO), wrap(unix.ENOMEM), net.ErrClosed, errors.New("other")} {
		if connectionSuspect(err) {
			t.Errorf("%v is taken for a connection error", err)
		}
	}
}
