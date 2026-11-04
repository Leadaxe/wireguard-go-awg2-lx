/* SPDX-License-Identifier: MIT
 *
 * lx: sing-box-lx SPEC 153 — the masquerade burst ahead of a handshake
 * initiation (per-handshake decoys, static i1..i5, Jc junk) is offered to the
 * HandshakeBurstFunc as bare payloads, in order, and what the filter returns
 * is what goes on the wire before the initiation: kept, dropped or extended.
 */

package device

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

// burstTap records every datagram bind A sends up to and including the first
// handshake initiation (148 bytes: s1=0, no trailer), then stops looking.
type burstTap struct {
	mu   sync.Mutex
	sent [][]byte
	done chan struct{}
	once sync.Once
}

func (b *burstTap) tap(pkt []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.done:
		return
	default:
	}
	b.sent = append(b.sent, append([]byte(nil), pkt...))
	if len(pkt) == MessageInitiationSize {
		b.once.Do(func() { close(b.done) })
	}
}

func (b *burstTap) wait(t *testing.T) [][]byte {
	t.Helper()
	select {
	case <-b.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no handshake initiation seen on bind A")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

var (
	burstTestDecoy = []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xde, 0xc0}
	burstTestI1    = []byte{0xc3, 0x00, 0x00, 0x00, 0x01, 0x05, 0x11}
)

// runHandshakeBurst brings up a device pair with jc=2 (10-byte junk), a static
// QUIC-shaped i1 and a per-handshake decoy on A, installs filter on A (nil =
// none) and returns the datagrams A sent up to its first initiation plus the
// bursts the filter was offered.
func runHandshakeBurst(t *testing.T, filter func([][]byte) [][]byte) (sent [][]byte, offered [][][]byte) {
	t.Helper()
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	bindA, bindB := newChanBindPair()
	tap := &burstTap{done: make(chan struct{})}
	bindA.tap = tap.tap
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	devA.SetDecoyPacketsFunc(func() [][]byte { return [][]byte{burstTestDecoy} })
	var mu sync.Mutex
	if filter != nil {
		devA.SetHandshakeBurstFunc(func(burst [][]byte) [][]byte {
			mu.Lock()
			offered = append(offered, burst)
			mu.Unlock()
			return filter(burst)
		})
	}

	awg := "jc=2\njmin=10\njmax=10\ni1=<b 0x" + hex.EncodeToString(burstTestI1) + ">\n"
	cfgA := fmt.Sprintf(
		"private_key=%s\n%sreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), awg, hex.EncodeToString(pkB[:]), testIPB)
	cfgB := fmt.Sprintf(
		"private_key=%s\n%sreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:1\nallowed_ip=%s/32\n",
		hex.EncodeToString(skB[:]), awg, hex.EncodeToString(pkA[:]), testIPA)
	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}
	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	pkt := buildIPv4Packet(testIPA, testIPB, 28)
	inputPacket(devA, testIPB.AsSlice(), pkt)
	sent = tap.wait(t)
	mu.Lock()
	defer mu.Unlock()
	return sent, offered
}

// assertBurstWire checks the datagrams A sent before its first initiation:
// want lists them in order, a nil entry standing for one 10-byte junk datagram.
func assertBurstWire(t *testing.T, sent [][]byte, want [][]byte) {
	t.Helper()
	if len(sent) != len(want)+1 {
		t.Fatalf("A sent %d datagrams before and including the initiation, want %d: %x", len(sent), len(want)+1, sent)
	}
	for i, w := range want {
		if w == nil {
			if len(sent[i]) != 10 {
				t.Fatalf("datagram %d is %d bytes, want 10-byte junk", i, len(sent[i]))
			}
			continue
		}
		if !bytes.Equal(sent[i], w) {
			t.Fatalf("datagram %d = %x, want %x", i, sent[i], w)
		}
	}
	if len(sent[len(sent)-1]) != MessageInitiationSize {
		t.Fatalf("last datagram is not the initiation: %d bytes", len(sent[len(sent)-1]))
	}
}

func TestHandshakeBurstUnfilteredOrder(t *testing.T) {
	sent, _ := runHandshakeBurst(t, nil)
	assertBurstWire(t, sent, [][]byte{burstTestDecoy, burstTestI1, nil, nil})
}

func TestHandshakeBurstFilterSeesPayloadsInOrder(t *testing.T) {
	prefix := []byte{0x00}
	sent, offered := runHandshakeBurst(t, func(burst [][]byte) [][]byte {
		return append([][]byte{prefix}, burst...)
	})
	if len(offered) == 0 {
		t.Fatal("the filter was never called")
	}
	first := offered[0]
	if len(first) != 4 || !bytes.Equal(first[0], burstTestDecoy) || !bytes.Equal(first[1], burstTestI1) || len(first[2]) != 10 || len(first[3]) != 10 {
		t.Fatalf("filter offered %x, want decoy, i1, junk, junk as bare payloads", first)
	}
	assertBurstWire(t, sent, [][]byte{prefix, burstTestDecoy, burstTestI1, nil, nil})
}

func TestHandshakeBurstFilterNilSendsInitiationAlone(t *testing.T) {
	sent, offered := runHandshakeBurst(t, func([][]byte) [][]byte { return nil })
	if len(offered) == 0 {
		t.Fatal("the filter was never called")
	}
	assertBurstWire(t, sent, nil)
}
