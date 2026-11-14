/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 041 v2 — unit tests for the stale predicate, the wake nudge
 * (RebindIfSessionStale) and the shared debounce across triggers, on top of
 * the v1 harness (lx_giveup_selfheal_test.go). These use the post-fix API and
 * are NOT expected to compile on the pre-fix base.
 */

package device

import (
	"sync"
	"testing"
	"time"
)

// establishTunnel completes a real handshake over a healthy pair so the peer
// holds a live keypair and a fresh lastHandshakeNano.
func establishTunnel(t *testing.T, pair *giveUpPair) {
	t.Helper()
	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	send := func() { pair.tunA.toDevice <- pkt }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

func peerOf(t *testing.T, dev *Device, pk NoisePublicKey) *Peer {
	t.Helper()
	dev.peers.RLock()
	peer := dev.peers.keyMap[pk]
	dev.peers.RUnlock()
	if peer == nil {
		t.Fatal("peer not found")
	}
	return peer
}

// A cold peer (no keypair yet, nothing to lose): the nudge must rebind and
// immediately initiate — the tunnel comes up without any traffic demand.
func TestNudgeRebindsStaleSession(t *testing.T) {
	pair := newGiveUpPair(t, true)

	if !pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge on a cold (keypair-less) session must rebind")
	}
	waitOpens(t, pair.bindA, 2)

	// The immediate initiation must bring the tunnel up: traffic sent only
	// AFTER the nudge flows end to end.
	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	send := func() { pair.tunA.toDevice <- pkt }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

// awaitInitiationSent waits until traffic demand made the peer send its first
// initiation, so a test that then moves the handshake clock does not race it.
func awaitInitiationSent(t *testing.T, peer *Peer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		peer.handshake.mutex.RLock()
		sent := !peer.handshake.lastSentHandshake.IsZero() && time.Since(peer.handshake.lastSentHandshake) < time.Second
		peer.handshake.mutex.RUnlock()
		if sent {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("traffic did not trigger an initiation")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The wake case: an app already sent traffic, so an initiation left on the
// dead socket moments before the nudge. The rebind voids that initiation, so
// the re-initiation must not wait out the rekeyMinTimeout rate limit: the
// tunnel comes up at once, not on the ~RekeyTimeout retransmit.
func TestNudgeAfterInflightInitiationReinitiatesAtOnce(t *testing.T) {
	pair := newGiveUpPair(t, true)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	send := func() { pair.tunA.toDevice <- pkt }
	start := time.Now()
	send()
	peer := peerOf(t, pair.devA, pair.pkB)
	awaitInitiationSent(t, peer)

	if !pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge on a cold session must rebind")
	}
	waitOpens(t, pair.bindA, 2)
	send()
	awaitPacket(t, pair.tunB, pkt, send)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("tunnel came up after %v: the re-initiation waited for the retransmit timer", elapsed.Round(10*time.Millisecond))
	}
}

// A healthy session (live keypair, fresh handshake) must be a strict no-op.
func TestNudgeHealthySessionNoop(t *testing.T) {
	pair := newGiveUpPair(t, false)
	establishTunnel(t, pair)

	opens := pair.bindA.openCount()
	if pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge on a healthy session must not rebind")
	}
	time.Sleep(100 * time.Millisecond)
	if got := pair.bindA.openCount(); got != opens {
		t.Fatalf("healthy nudge reopened the bind: %d opens, want %d", got, opens)
	}
}

// A live keypair whose last handshake is older than RejectAfterTime is
// provably dead (the keys are invalid): the nudge must rebind.
func TestNudgeExpiredHandshakeIsStale(t *testing.T) {
	pair := newGiveUpPair(t, false)
	establishTunnel(t, pair)

	peer := peerOf(t, pair.devA, pair.pkB)
	peer.lastHandshakeNano.Store(time.Now().Add(-RejectAfterTime - time.Second).UnixNano())

	if !pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge on an expired session must rebind")
	}
	waitOpens(t, pair.bindA, 2)
}

// A down device (how SPEC 020 idle-suspend leaves it) must be a no-op — the
// nudge never wakes sleepers.
func TestNudgeDownDeviceNoop(t *testing.T) {
	pair := newGiveUpPair(t, true)

	if err := pair.devA.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge on a down device must be a no-op")
	}
}

// Pinned listen_port survives the nudge rebind.
func TestNudgePinnedPortPreserved(t *testing.T) {
	pair := newGiveUpPair(t, true)
	pair.devA.SetGiveUpRebind(true, false)

	if !pair.devA.RebindIfSessionStale() {
		t.Fatal("nudge must rebind a cold session")
	}
	waitOpens(t, pair.bindA, 2)

	ports := pair.bindA.portsSnapshot()
	if ports[1] != 1 {
		t.Fatalf("nudge rebind requested port %d, want 1 (pinned)", ports[1])
	}
}

// driveToEarlyTrigger puts the peer where ~15s of unanswered retries leave it
// (two retries counted, the last initiation older than the retransmit
// timeout) and fires the third retry expiry.
func driveToEarlyTrigger(peer *Peer) {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(earlyGiveUpMinAttempts - 1)
	expiredRetransmitHandshake(peer)
}

// The early trigger fires from the retry branch, which sends an initiation of
// its own. Exactly one initiation must follow the rebind: two back to back
// share a whitened timestamp, the responder drops the second as a replay
// while the initiator holds its state, and the tunnel waits out another
// retransmit instead of coming up at once.
func TestEarlyRebindReinitiatesOnce(t *testing.T) {
	pair := newGiveUpPair(t, true)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	pair.tunA.toDevice <- pkt
	peer := peerOf(t, pair.devA, pair.pkB)
	awaitInitiationSent(t, peer)

	start := time.Now()
	driveToEarlyTrigger(peer)
	awaitPacket(t, pair.tunB, pkt, func() {})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("tunnel came up after %v: the rebind and the retry both initiated", elapsed.Round(10*time.Millisecond))
	}
}

// A rebind that fails to reopen the socket must not swallow the retry it took
// over: the initiation still goes out as a retry, so the retransmit timer is
// re-armed and the attempt counter keeps walking towards the give-up trigger.
func TestEarlyRebindFailureKeepsRetryCycle(t *testing.T) {
	pair := newGiveUpPair(t, true)

	pair.tunA.toDevice <- buildIPv4Packet(testIPA, testIPB, 8)
	peer := peerOf(t, pair.devA, pair.pkB)
	awaitInitiationSent(t, peer)

	pair.bindA.mu.Lock()
	pair.bindA.failOpen = true
	pair.bindA.mu.Unlock()
	driveToEarlyTrigger(peer)

	deadline := time.Now().Add(2 * time.Second)
	for {
		peer.handshake.mutex.RLock()
		sent := time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout
		peer.handshake.mutex.RUnlock()
		if sent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed rebind left the retry unsent: the handshake cycle stalled")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := peer.timers.handshakeAttempts.Load(); got != earlyGiveUpMinAttempts {
		t.Fatalf("handshake attempts = %d after a failed rebind, want %d (retry cycle continues)", got, earlyGiveUpMinAttempts)
	}
}

// The debounce window is SHARED across triggers: an early/nudge rebind
// suppresses the give-up rebind of the same failed series, and a later series
// (window elapsed) heals again — sliding window, not a latch.
func TestSharedDebounceAcrossTriggers(t *testing.T) {
	pair := newGiveUpPair(t, false)

	// First trigger of the series: nudge.
	if !pair.devA.RebindIfSessionStale() {
		t.Fatal("first nudge must rebind")
	}
	waitOpens(t, pair.bindA, 2)

	// The give-up of the same series lands inside the window: suppressed.
	triggerGiveUp(t, pair.devA, pair.pkB)
	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 2 {
		t.Fatalf("give-up inside the shared window rebound: %d opens, want 2", got)
	}

	// Next series: age the window as wall clocks would — heals again.
	pair.devA.giveUpRebind.last.Store(time.Now().Add(-RekeyAttemptTime - time.Second).Unix())
	triggerGiveUp(t, pair.devA, pair.pkB)
	waitOpens(t, pair.bindA, 3)
}

// The early trigger must NOT fire before enough initiations went unanswered,
// even against a provably dead session.
func TestEarlyRebindNeedsMinAttempts(t *testing.T) {
	pair := newGiveUpPair(t, true)
	peer := peerOf(t, pair.devA, pair.pkB)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(0) // this expiry brings it to 1 (< min)
	expiredRetransmitHandshake(peer)

	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != 1 {
		t.Fatalf("early rebind fired below the attempt floor: %d opens, want 1", got)
	}
}

// A fresh session (live keypair, recent handshake) must keep the retry branch
// byte-for-byte upstream even past the attempt floor: no rebind.
func TestEarlyRebindFreshSessionNoop(t *testing.T) {
	pair := newGiveUpPair(t, false)
	establishTunnel(t, pair)
	peer := peerOf(t, pair.devA, pair.pkB)

	opens := pair.bindA.openCount()
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-2 * RekeyTimeout)
	peer.handshake.mutex.Unlock()
	peer.timers.handshakeAttempts.Store(earlyGiveUpMinAttempts)
	expiredRetransmitHandshake(peer)

	time.Sleep(300 * time.Millisecond)
	if got := pair.bindA.openCount(); got != opens {
		t.Fatalf("early rebind fired on a fresh session: %d opens, want %d", got, opens)
	}
}

// Nudge racing Close: no panic, no deadlock, no race-detector report.
func TestNudgeRacesClose(t *testing.T) {
	for i := 0; i < 25; i++ {
		pair := newGiveUpPair(t, false)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			pair.devA.RebindIfSessionStale()
		}()
		go func() {
			defer wg.Done()
			pair.devA.Close()
		}()
		wg.Wait()
	}
}

// Nudge racing Down/Up (the SPEC 020 suspend/resume shape): the device must
// end consistent — up, with a live bind.
func TestNudgeRacesSuspend(t *testing.T) {
	for i := 0; i < 25; i++ {
		pair := newGiveUpPair(t, false)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			pair.devA.RebindIfSessionStale()
		}()
		go func() {
			defer wg.Done()
			if err := pair.devA.Down(); err != nil {
				t.Errorf("Down: %v", err)
			}
			if err := pair.devA.Up(); err != nil {
				t.Errorf("Up: %v", err)
			}
		}()
		wg.Wait()

		pair.devA.net.RLock()
		bindAlive := pair.devA.net.bind != nil
		pair.devA.net.RUnlock()
		if !bindAlive || !pair.devA.isUp() {
			t.Fatalf("iteration %d: device inconsistent after nudge/suspend race (bind=%v up=%v)",
				i, bindAlive, pair.devA.isUp())
		}
		pair.devA.Close()
		pair.devB.Close()
	}
}
