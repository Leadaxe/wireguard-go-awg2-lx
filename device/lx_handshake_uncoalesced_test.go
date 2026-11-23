/* SPDX-License-Identifier: MIT
 *
 * lx: sing-box-lx SPEC 101 — the masquerade burst and its initiation reach the
 * bind one datagram per send, so StdNetBind has nothing to coalesce into a UDP
 * GSO message with a junk-sized segment.
 */

package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/sagernet/wireguard-go/conn"
)

// sendCountBind records how many datagrams each Send was handed.
type sendCountBind struct {
	*chanBind
	mu    sync.Mutex
	sends [][]int
}

func (b *sendCountBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	sizes := make([]int, len(bufs))
	for i, buf := range bufs {
		sizes[i] = len(buf) - offset
	}
	b.mu.Lock()
	b.sends = append(b.sends, sizes)
	b.mu.Unlock()
	return b.chanBind.Send(bufs, ep, offset)
}

func TestLXHandshakeBurstOneDatagramPerSend(t *testing.T) {
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkB := skB.publicKey()

	inner, _ := newChanBindPair()
	bind := &sendCountBind{chanBind: inner}
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	// Proton's junk: three datagrams of 1-3 bytes, the sizes the kernel would
	// otherwise be asked to segment by.
	cfg := fmt.Sprintf(
		"private_key=%s\njc=3\njmin=1\njmax=3\ni1=<b 0x%s>\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
		hex.EncodeToString(skA[:]), hex.EncodeToString(burstTestI1), hex.EncodeToString(pkB[:]), testIPB)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	peer := dev.LookupPeer(pkB)
	if peer == nil {
		t.Fatal("peer not found")
	}
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation: %v", err)
	}

	bind.mu.Lock()
	defer bind.mu.Unlock()
	// i1, three junk datagrams, the initiation
	if len(bind.sends) != 5 {
		t.Fatalf("bind saw %d sends, want 5: %v", len(bind.sends), bind.sends)
	}
	for i, sizes := range bind.sends {
		if len(sizes) != 1 {
			t.Fatalf("send %d carried %d datagrams, want 1: %v", i, len(sizes), bind.sends)
		}
	}
	if got := bind.sends[0][0]; got != len(burstTestI1) {
		t.Fatalf("first datagram is %d bytes, want the %d-byte i1", got, len(burstTestI1))
	}
	for i := 1; i <= 3; i++ {
		if got := bind.sends[i][0]; got < 1 || got > 3 {
			t.Fatalf("datagram %d is %d bytes, want 1-3 byte junk", i, got)
		}
	}
	if got := bind.sends[4][0]; got != MessageInitiationSize {
		t.Fatalf("last datagram is %d bytes, want the %d-byte initiation", got, MessageInitiationSize)
	}
}
