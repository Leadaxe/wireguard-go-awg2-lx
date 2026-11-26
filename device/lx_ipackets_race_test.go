/* SPDX-License-Identifier: MIT
 *
 * lx: I1-I5 are read by every handshake initiation without a lock, so an
 * IpcSet that changes them on a running device must store them atomically
 * (amneziawg-go 735cffbcb). Run with -race.
 */

package device

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLXSignaturePacketsChangeDuringHandshake(t *testing.T) {
	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkB := skB.publicKey()

	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	cfg := fmt.Sprintf(
		"private_key=%s\ni1=<b 0x%s>\nreplace_peers=true\npublic_key=%s\nendpoint=127.0.0.1:2\nallowed_ip=%s/32\n",
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

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			peer.handshake.mutex.Lock()
			peer.handshake.lastSentHandshake = time.Time{}
			peer.handshake.mutex.Unlock()
			peer.SendHandshakeInitiation(false)
		}
	}()

	for _, spec := range []string{"<r 16>", "<b 0xabcd>", "<r 32>", "<b 0x01>"} {
		if err := dev.IpcSet("i1=" + spec + "\n"); err != nil {
			t.Fatalf("IpcSet i1=%s: %v", spec, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(done)
	wg.Wait()

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "i1=<b 0x01>") {
		t.Fatalf("i1 not updated:\n%s", got)
	}
}
