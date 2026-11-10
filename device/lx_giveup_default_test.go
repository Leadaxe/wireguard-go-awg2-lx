/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 — the self-heal rebind is opt-in. A device built with
 * NewDevice defaults must never reopen its bind on any trigger: consumers
 * whose bind does not survive a Close/Open cycle (the Tailscale engine on
 * magicsock) build devices without calling SetGiveUpRebind, and a rebind
 * there permanently stops direct UDP receive.
 */

package device

import (
	"testing"
	"time"
)

func TestSelfHealOffByDefaultGiveUp(t *testing.T) {
	pair := newDefaultGiveUpPair(t, false)

	triggerGiveUp(t, pair.devA, pair.pkB)
	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 1 {
		t.Fatalf("give-up rebound a device that never opted in: %d opens, want 1", got)
	}
}

func TestSelfHealOffByDefaultEarly(t *testing.T) {
	pair := newDefaultGiveUpPair(t, false)
	peer := peerOf(t, pair.devA, pair.pkB)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(earlyGiveUpMinAttempts)
	expiredRetransmitHandshake(peer)

	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 1 {
		t.Fatalf("early trigger rebound a device that never opted in: %d opens, want 1", got)
	}
}

func TestSelfHealOffByDefaultNudge(t *testing.T) {
	pair := newDefaultGiveUpPair(t, false)

	if pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge rebound a device that never opted in")
	}
	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 1 {
		t.Fatalf("nudge reopened the bind: %d opens, want 1", got)
	}
}
