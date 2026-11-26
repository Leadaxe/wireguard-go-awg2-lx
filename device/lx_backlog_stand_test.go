//go:build linux || darwin

/* SPDX-License-Identifier: MIT
 *
 * lx: backlog stand — what a queued transport packet pins in memory, in each
 * direction, and what the path costs per packet.
 *
 * A datagram and a TUN packet are both read into MaxMessageSize buffers, and
 * that buffer then travels with the packet through the crypto queue and the
 * peer's sequential queue. When the consumer is slower than the producer the
 * queues fill, and what each queued packet keeps alive decides the process
 * footprint.
 *
 * The stand wires two real Devices, A → B. It can hold B's TUN shut (receive
 * backlog) or A's socket shut (send backlog), flood until the pipeline stops
 * accepting, and measure the heap. It then opens the gate and checks that
 * every packet comes out byte-exact and in order.
 *
 * LX_STAND_BIND=udp runs the two devices over real UDP sockets on loopback
 * (StdNetBind: recvmmsg, and GSO/GRO where the kernel has them) instead of the
 * in-memory bind. A socket may drop, so that mode tolerates gaps in the
 * sequence but not reordering or damage.
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"

	"golang.org/x/net/ipv4"
)

// standSeqOffset is where the stand writes a packet's sequence number: the
// first bytes of the payload behind the IPv4 header.
const standSeqOffset = ipv4.HeaderLen

func standEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

func standUDP() bool { return os.Getenv("LX_STAND_BIND") == "udp" }

// standUDPBind is a socket bind for the stand. LX_STAND_CONNECT=1 lets it
// connect its sockets to the peer (sing-box-lx SPEC 160).
func standUDPBind(tb testing.TB) conn.Bind {
	bind := conn.NewStdNetBind(nil).(*conn.StdNetBind)
	if os.Getenv("LX_STAND_CONNECT") == "1" {
		bind.SetSinglePeerMode()
		bind.SetConnectedSocket()
	}
	return bind
}

// standSinkTun is B's TUN. It can be held shut: Write then blocks, so
// everything B has accepted stays queued inside it.
type standSinkTun struct {
	*chanTun
	batch int // BatchSize reported to the device; 0 means 1
	lossy bool

	gate sync.RWMutex // the stand holds the write lock to shut the TUN

	template  []byte // expected packet, sequence field aside
	writes    atomic.Int64
	delivered atomic.Int64
	lost      atomic.Int64
	corrupt   atomic.Int64
	next      uint64       // expected sequence; only Write touches it
	minCap    atomic.Int64 // smallest cap() of a buffer handed to Write
}

func (t *standSinkTun) BatchSize() int {
	if t.batch > 1 {
		return t.batch
	}
	return 1
}

func (t *standSinkTun) Write(bufs [][]byte, offset int) (int, error) {
	t.gate.RLock()
	defer t.gate.RUnlock()
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		t.writes.Add(1)
		if c := int64(cap(b)); c < t.minCap.Load() {
			t.minCap.Store(c)
		}
		pkt := b[offset:]
		if len(pkt) != len(t.template) {
			t.corrupt.Add(1)
			continue
		}
		seq := binary.BigEndian.Uint64(pkt[standSeqOffset:])
		if seq == 0 {
			continue // a warm-up packet, sent until the session is up
		}
		switch {
		case !bytes.Equal(pkt[:standSeqOffset], t.template[:standSeqOffset]),
			!bytes.Equal(pkt[standSeqOffset+8:], t.template[standSeqOffset+8:]),
			seq < t.next:
			t.corrupt.Add(1)
		case seq > t.next:
			if t.lossy {
				t.lost.Add(int64(seq - t.next))
			} else {
				t.corrupt.Add(1)
			}
		}
		t.next = seq + 1
		t.delivered.Add(1)
	}
	return len(bufs), nil
}

// standBind wraps a Bind: Send can be held shut, and both directions count
// datagrams.
type standBind struct {
	conn.Bind
	gate       sync.RWMutex
	sent       atomic.Int64
	received   atomic.Int64
	pathResets atomic.Int64
}

// ResetPath keeps the wrapped bind reachable as a conn.PathResetter.
func (b *standBind) ResetPath() {
	b.pathResets.Add(1)
	if resetter, ok := b.Bind.(conn.PathResetter); ok {
		resetter.ResetPath()
	}
}

func (b *standBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.gate.RLock()
	defer b.gate.RUnlock()
	b.sent.Add(int64(len(bufs)))
	return b.Bind.Send(bufs, ep, offset)
}

func (b *standBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	for i, fn := range fns {
		fns[i] = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
			n, err := fn(slab, packets)
			b.received.Add(int64(n))
			return n, err
		}
	}
	return fns, actual, err
}

type stand struct {
	devA, devB   *Device
	bindA, bindB *standBind
	tunA         *chanTun
	tunB         *standSinkTun
	peerOnA      *Peer // B, as A knows it
	peerOnB      *Peer // A, as B knows it
	template     []byte
	dst          []byte
	window       int64
	sent         atomic.Int64 // sequence numbers handed to A
}

func standFreePort(tb testing.TB) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// newStand builds A → B with transport padding s4 on both ends (0 is plain
// WireGuard). prepare, if set, runs on B before it is brought up.
func newStand(tb testing.TB, s4, payloadLen, tunBatch int, prepare func(devB *Device)) *stand {
	tb.Helper()
	skA, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	pkA, pkB := skA.publicKey(), skB.publicKey()

	template := buildIPv4Packet(testIPA, testIPB, payloadLen)
	s := &stand{
		tunA:     newChanTun(),
		tunB:     &standSinkTun{chanTun: newChanTun(), batch: tunBatch, template: template, next: 1, lossy: standUDP()},
		template: template,
		dst:      testIPB.AsSlice(),
		window:   int64(standEnvInt("LX_STAND_WINDOW", 256)),
	}
	s.tunB.minCap.Store(1 << 62)
	portA, portB := 1, 2
	if standUDP() {
		s.bindA = &standBind{Bind: standUDPBind(tb)}
		s.bindB = &standBind{Bind: standUDPBind(tb)}
		portA, portB = standFreePort(tb), standFreePort(tb)
	} else {
		a, b := newChanBindPair()
		s.bindA, s.bindB = &standBind{Bind: a}, &standBind{Bind: b}
	}
	workers := standEnvInt("LX_STAND_WORKERS", 1)
	s.devA = NewDevice(context.Background(), s.tunA, s.bindA, NewLogger(LogLevelError, "standA: "), workers)
	s.devB = NewDevice(context.Background(), s.tunB, s.bindB, NewLogger(LogLevelError, "standB: "), workers)
	tb.Cleanup(s.devA.Close)
	tb.Cleanup(s.devB.Close)

	cfg := func(sk NoisePrivateKey, pk NoisePublicKey, listen, remote int, allowed fmt.Stringer) string {
		return fmt.Sprintf(
			"private_key=%s\nlisten_port=%d\ns4=%d\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
			hex.EncodeToString(sk[:]), listen, s4, hex.EncodeToString(pk[:]), remote, allowed)
	}
	if err := s.devA.IpcSet(cfg(skA, pkB, portA, portB, testIPB)); err != nil {
		tb.Fatal(err)
	}
	if err := s.devB.IpcSet(cfg(skB, pkA, portB, portA, testIPA)); err != nil {
		tb.Fatal(err)
	}
	if prepare != nil {
		prepare(s.devB)
	}
	if err := s.devA.Up(); err != nil {
		tb.Fatal(err)
	}
	if err := s.devB.Up(); err != nil {
		tb.Fatal(err)
	}
	s.peerOnA, s.peerOnB = s.devA.LookupPeer(pkB), s.devB.LookupPeer(pkA)
	if s.peerOnA == nil || s.peerOnB == nil {
		tb.Fatal("the peers are not configured")
	}
	s.warmUp(tb)
	return s
}

// packet returns the stand's packet carrying seq.
func (s *stand) packet(seq uint64) []byte {
	pkt := bytes.Clone(s.template)
	binary.BigEndian.PutUint64(pkt[standSeqOffset:], seq)
	return pkt
}

// inFlight is what has been handed to A and not yet seen (or seen missing) at
// B's TUN.
func (s *stand) inFlight() int64 {
	return s.sent.Load() - s.tunB.delivered.Load() - s.tunB.lost.Load()
}

// inject hands pkt to A the way a userspace network stack does, in a
// packet-sized buffer. The caller keeps the window.
func (s *stand) inject(pkt []byte) {
	inputPacket(s.devA, s.dst, pkt)
}

// warmUp sends sequence-0 packets until one crosses, so the handshake is done
// and its allocations are behind us before anything is measured.
func (s *stand) warmUp(tb testing.TB) {
	tb.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for s.tunB.writes.Load() == 0 {
		if time.Now().After(deadline) {
			tb.Fatal("no packet crossed the tunnel during warm-up")
		}
		s.inject(s.packet(0))
		time.Sleep(20 * time.Millisecond)
	}
	for s.peerOnA.queuedOutboundPackets.Load() > 0 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	s.tunB.minCap.Store(1 << 62)
}

func standHeap() uint64 {
	runtime.GC()
	runtime.GC() // a second cycle empties the sync.Pool victim caches
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func standHeapNow() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// standBacklog is what one backlog run observed.
type standBacklog struct {
	queued   int64  // packets held inside the device under test at the stall
	retained uint64 // heap growth with the backlog in place
	sent     int64
	lost     int64
}

func (r standBacklog) String() string {
	per := uint64(0)
	if r.queued > 0 {
		per = r.retained / uint64(r.queued)
	}
	return fmt.Sprintf("%d packets queued, heap grew by %.1f MiB = %d bytes per queued packet (sent %d, lost %d)",
		r.queued, float64(r.retained)/(1<<20), per, r.sent, r.lost)
}

// flood feeds A through `feed` until stop is closed; feed reports false when
// it could not take the packet now.
func (s *stand) flood(stop <-chan struct{}, feed func(pkt []byte) bool) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		// a ring: a fed packet is copied by its consumer a little later
		ring := make([][]byte, 4096)
		for i := range ring {
			ring[i] = s.packet(0)
		}
		for seq := s.sent.Load() + 1; ; {
			select {
			case <-stop:
				return
			default:
			}
			pkt := ring[seq%int64(len(ring))]
			binary.BigEndian.PutUint64(pkt[standSeqOffset:], uint64(seq))
			if !feed(pkt) {
				time.Sleep(time.Millisecond)
				continue
			}
			s.sent.Store(seq)
			seq++
		}
	}()
	return done
}

// awaitStall returns once `inside` has not moved for a second, or the heap
// has grown by the ceiling.
func (s *stand) awaitStall(tb testing.TB, idle uint64, inside func() int64) {
	tb.Helper()
	ceiling := uint64(standEnvInt("LX_STAND_HEAP_CEIL_MIB", 400)) << 20
	last, stable := int64(-1), 0
	deadline := time.Now().Add(90 * time.Second)
	for stable < 20 {
		if time.Now().After(deadline) {
			tb.Log("the backlog was still growing after 90 s; measuring what there is")
			return
		}
		time.Sleep(50 * time.Millisecond)
		if h := standHeapNow(); h > idle && h-idle > ceiling {
			tb.Logf("stopped at the heap ceiling of %d MiB", ceiling>>20)
			return
		}
		if now := inside(); now == last && now > 0 {
			stable++
		} else {
			last, stable = now, 0
		}
	}
}

func (s *stand) awaitDelivered(tb testing.TB) {
	tb.Helper()
	progress, since := int64(-1), time.Now()
	for s.inFlight() > 0 {
		if got := s.tunB.delivered.Load(); got != progress {
			progress, since = got, time.Now()
		} else if time.Since(since) > 3*time.Second {
			if s.tunB.lossy {
				break // the tail was dropped by the socket
			}
			tb.Fatalf("delivered %d of %d packets and stopped", got, s.sent.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := s.tunB.corrupt.Load(); n != 0 {
		tb.Fatalf("%d packets arrived damaged or out of order", n)
	}
}

// runRxBacklog shuts B's TUN, floods from A until B stops accepting,
// measures, then opens the TUN and waits for everything to arrive.
func (s *stand) runRxBacklog(tb testing.TB, atStall func()) standBacklog {
	tb.Helper()
	idle := standHeap()
	inside := func() int64 { return s.bindB.received.Load() - s.tunB.writes.Load() }
	base := inside()

	s.tunB.gate.Lock()
	stop := make(chan struct{})
	done := s.flood(stop, func(pkt []byte) bool {
		// keep A's own queues out of the measurement
		if s.peerOnA.queuedOutboundPackets.Load() >= 256 {
			return false
		}
		s.inject(pkt)
		return true
	})
	s.awaitStall(tb, idle, inside)
	close(stop)
	<-done
	time.Sleep(200 * time.Millisecond)
	r := standBacklog{queued: inside() - base, retained: standHeap() - idle}
	if atStall != nil {
		atStall()
	}
	s.tunB.gate.Unlock()

	s.awaitDelivered(tb)
	r.sent, r.lost = s.sent.Load(), s.tunB.lost.Load()
	return r
}

// runTxBacklog shuts A's socket, feeds A's TUN until A stops reading it,
// measures, then opens the socket and waits for everything to arrive.
func (s *stand) runTxBacklog(tb testing.TB) standBacklog {
	tb.Helper()
	idle := standHeap()
	var fed atomic.Int64
	inside := func() int64 { return fed.Load() - int64(len(s.tunA.toDevice)) - s.bindA.sent.Load() }
	sentBefore := s.bindA.sent.Load()

	s.bindA.gate.Lock()
	stop := make(chan struct{})
	done := s.flood(stop, func(pkt []byte) bool {
		select {
		case s.tunA.toDevice <- bytes.Clone(pkt):
			fed.Add(1)
			return true
		default:
			return false
		}
	})
	s.awaitStall(tb, idle, func() int64 { return fed.Load() })
	close(stop)
	<-done
	time.Sleep(200 * time.Millisecond)
	// what waits in the TUN's own channel is the stand's memory, not A's
	channel := uint64(len(s.tunA.toDevice)) * uint64(len(s.template))
	r := standBacklog{queued: inside() + sentBefore, retained: standHeap() - idle - channel}
	s.bindA.gate.Unlock()

	s.awaitDelivered(tb)
	r.sent, r.lost = s.sent.Load(), s.tunB.lost.Load()
	return r
}

func standCPU() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// TestStandBacklog prints what a full backlog pins in each direction. It is a
// measurement, not a check: it runs when LX_STAND is set.
func TestStandBacklog(t *testing.T) {
	if os.Getenv("LX_STAND") == "" {
		t.Skip("set LX_STAND=1 to measure")
	}
	for _, s4 := range []int{0, 60} {
		name := "wireguard"
		if s4 != 0 {
			name = "awg-s4"
		}
		t.Run("rx/"+name, func(t *testing.T) {
			s := newStand(t, s4, 1380, 1, nil)
			t.Logf("STAND rx %s: %v", name, s.runRxBacklog(t, nil))
		})
		t.Run("tx/"+name, func(t *testing.T) {
			s := newStand(t, s4, 1380, 1, nil)
			t.Logf("STAND tx %s: %v", name, s.runTxBacklog(t))
		})
	}
}

// standBench is the per-packet cost of the whole A → B path with a TUN that
// keeps up and the sender holding a window of packets in flight.
func standBench(b *testing.B, s4, length int, viaTun bool) {
	s := newStand(b, s4, length, 1, nil)
	ring := make([][]byte, 4096)
	for i := range ring {
		ring[i] = s.packet(0)
	}
	b.SetBytes(int64(len(s.template)))
	b.ReportAllocs()
	cpu := standCPU()
	b.ResetTimer()
	progress, since := int64(-1), time.Now()
	for i := 1; i <= b.N; i++ {
		for s.inFlight() >= s.window {
			runtime.Gosched()
			if got := s.tunB.delivered.Load(); got != progress {
				progress, since = got, time.Now()
			} else if time.Since(since) > 10*time.Second {
				b.Fatalf("delivered %d of %d packets and stopped; %d in flight", got, b.N, s.inFlight())
			}
		}
		pkt := ring[i%len(ring)]
		binary.BigEndian.PutUint64(pkt[standSeqOffset:], uint64(i))
		if viaTun {
			s.tunA.toDevice <- pkt
		} else {
			s.inject(pkt)
		}
		s.sent.Store(int64(i))
	}
	for s.inFlight() > 0 {
		if got := s.tunB.delivered.Load(); got != progress {
			progress, since = got, time.Now()
		} else if time.Since(since) > 3*time.Second {
			if s.tunB.lossy {
				break
			}
			b.Fatalf("delivered %d of %d packets and stopped", got, b.N)
		}
		runtime.Gosched()
	}
	b.StopTimer()
	b.ReportMetric(float64(standCPU()-cpu)/float64(b.N), "cpu-ns/op")
	b.ReportMetric(float64(s.tunB.lost.Load())/float64(b.N)*100, "lost-%")
	if n := s.tunB.corrupt.Load(); n != 0 {
		b.Fatalf("%d packets arrived damaged or out of order", n)
	}
}

// BenchmarkStandInject feeds A through InputPacket, so A's side is already
// packet-sized everywhere and the receive path is what differs.
func BenchmarkStandInject(b *testing.B) {
	b.Run("wireguard-1380", func(b *testing.B) { standBench(b, 0, 1380, false) })
	b.Run("awg-s4-1380", func(b *testing.B) { standBench(b, 60, 1380, false) })
	b.Run("wireguard-64", func(b *testing.B) { standBench(b, 0, 64, false) })
}

// BenchmarkStandTun feeds A through its TUN read loop, the path a userspace
// network stack behind a TUN device takes.
func BenchmarkStandTun(b *testing.B) {
	b.Run("wireguard-1380", func(b *testing.B) { standBench(b, 0, 1380, true) })
	b.Run("awg-s4-1380", func(b *testing.B) { standBench(b, 60, 1380, true) })
	b.Run("wireguard-64", func(b *testing.B) { standBench(b, 0, 64, true) })
}
