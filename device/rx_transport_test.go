// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
	"golang.org/x/net/ipv4"
)

type chanTun struct {
	toDevice      chan []byte // packets the device Reads (outbound plaintext)
	fromDevice    chan []byte // packets the device Writes (inbound plaintext)
	events        chan tun.Event
	closed        chan struct{}
	closeOnce     sync.Once
	batchSize     int
	writeCapacity atomic.Int32
}

func newChanTun() *chanTun {
	return &chanTun{
		toDevice:   make(chan []byte, 1024),
		fromDevice: make(chan []byte, 1024),
		events:     make(chan tun.Event, 4),
		closed:     make(chan struct{}),
	}
}

func (t *chanTun) File() *os.File { return nil }

func (t *chanTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt, ok := <-t.toDevice:
		if !ok {
			return 0, os.ErrClosed
		}
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *chanTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		t.writeCapacity.Store(int32(cap(buf)))
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case t.fromDevice <- pkt:
		}
	}
	return len(bufs), nil
}

func (t *chanTun) MTU() (int, error)        { return DefaultMTU, nil }
func (t *chanTun) Name() (string, error)    { return "chantun", nil }
func (t *chanTun) Events() <-chan tun.Event { return t.events }
func (t *chanTun) BatchSize() int           { return max(1, t.batchSize) }

func (t *chanTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func buildIPv4Packet(src, dst netip.Addr, payloadLen int) []byte {
	total := ipv4.HeaderLen + payloadLen
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[IPv4offsetTotalLength:IPv4offsetTotalLength+2], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol: UDP
	copy(pkt[IPv4offsetSrc:], src.AsSlice())
	copy(pkt[IPv4offsetDst:], dst.AsSlice())
	for i := ipv4.HeaderLen; i < total; i++ {
		pkt[i] = byte(i) // deterministic payload
	}
	return pkt
}

func awaitPacket(t *testing.T, from *chanTun, want []byte, resend func()) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	retry := time.NewTicker(1 * time.Second)
	defer retry.Stop()
	for {
		select {
		case got := <-from.fromDevice:
			if bytes.Equal(got, want) {
				return
			}
			t.Logf("ignoring unexpected packet, len=%d", len(got))
		case <-retry.C:
			resend()
		case <-deadline:
			t.Fatal("timed out waiting for packet on peer tun")
		}
	}
}

func TestTransportReceiveThroughTUN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		padding int
		batch   int
	}{
		{"wireguard", 0, 1},
		{"awg", 60, 1},
		{"awg-batched-tun", 60, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			makeDevice := func(batch int) (*Device, *chanTun, NoisePublicKey) {
				key, err := newPrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				endpoint := newChanTun()
				endpoint.batchSize = batch
				dev := NewDevice(context.Background(), endpoint, conn.NewStdNetBind(nil), NewLogger(LogLevelError, "rx test: "), 1)
				t.Cleanup(dev.Close)
				if err := dev.IpcSet(fmt.Sprintf("private_key=%s\ns4=%d\n", hex.EncodeToString(key[:]), tc.padding)); err != nil {
					t.Fatal(err)
				}
				if err := dev.Up(); err != nil {
					t.Fatal(err)
				}
				return dev, endpoint, key.publicKey()
			}
			a, tunA, keyA := makeDevice(1)
			b, tunB, keyB := makeDevice(tc.batch)
			addressA, addressB := netip.MustParseAddr("10.28.0.1"), netip.MustParseAddr("10.28.0.2")
			setPeer := func(dev, peer *Device, key NoisePublicKey, address netip.Addr) {
				peer.net.Lock()
				port := peer.net.port
				peer.net.Unlock()
				if err := dev.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n", hex.EncodeToString(key[:]), port, address)); err != nil {
					t.Fatal(err)
				}
			}
			setPeer(a, b, keyB, addressB)
			setPeer(b, a, keyA, addressA)
			for _, size := range []int{8, 1200, 37, 1280} {
				packet := buildIPv4Packet(addressA, addressB, size)
				send := func() { tunA.toDevice <- packet }
				send()
				awaitPacket(t, tunB, packet, send)
				if tc.batch > 1 && tunB.writeCapacity.Load() < MaxMessageSize {
					t.Fatalf("batched TUN received capacity %d, want at least %d for merging", tunB.writeCapacity.Load(), MaxMessageSize)
				}
			}
		})
	}
}
