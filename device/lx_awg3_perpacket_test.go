/* SPDX-License-Identifier: MIT
 *
 * lx: AmneziaWG 3.x — the per-packet header-protection and S4-padding paths
 * must not allocate or syscall per packet, and must keep the wire bytes of
 * HeaderProtectionCipher exactly.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func newHeaderKeyDevice(t testing.TB) *Device {
	t.Helper()
	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	device := new(Device)
	device.headerProtection.key.Store(&key)
	return device
}

// The keystream from headerCipherInto is the one HeaderProtectionCipher
// produces, including the continuation the receive path relies on (the first
// 8 bytes, then the rest of the header from byte 8).
func TestHeaderCipherIntoMatchesHeaderProtectionCipher(t *testing.T) {
	device := newHeaderKeyDevice(t)
	for i := 0; i < 64; i++ {
		datagram := make([]byte, 64)
		rand.Read(datagram)

		want := make([]byte, 32)
		reference, err := device.HeaderProtectionCipher(datagram)
		if err != nil || reference == nil {
			t.Fatalf("HeaderProtectionCipher: %v, %v", reference, err)
		}
		reference.XORKeyStream(want[:8], want[:8])
		reference.XORKeyStream(want[8:], want[8:])

		got := make([]byte, 32)
		var cip chacha20.Cipher
		protected, err := device.headerCipherInto(&cip, datagram)
		if err != nil || !protected {
			t.Fatalf("headerCipherInto: %v, %v", protected, err)
		}
		cip.XORKeyStream(got[:8], got[:8])
		cip.XORKeyStream(got[8:], got[8:])

		if !bytes.Equal(got, want) {
			t.Fatalf("keystream mismatch:\n got %x\nwant %x", got, want)
		}
	}
}

func TestHeaderCipherIntoOffAndShort(t *testing.T) {
	var cip chacha20.Cipher
	if protected, err := new(Device).headerCipherInto(&cip, make([]byte, 32)); protected || err != nil {
		t.Fatalf("no key: protected=%v err=%v, want false, nil", protected, err)
	}
	device := newHeaderKeyDevice(t)
	if _, err := device.headerCipherInto(&cip, make([]byte, HeaderCipherNonceSize-1)); err != errHeaderNonceShort {
		t.Fatalf("short datagram: err=%v, want errHeaderNonceShort", err)
	}
}

func TestHeaderCipherIntoDoesNotAllocate(t *testing.T) {
	device := newHeaderKeyDevice(t)
	datagram := make([]byte, 64)
	header := make([]byte, MessageTransportHeaderSize)
	allocs := testing.AllocsPerRun(1000, func() {
		var cip chacha20.Cipher
		if protected, _ := device.headerCipherInto(&cip, datagram); protected {
			cip.XORKeyStream(header, header)
		}
	})
	if allocs != 0 {
		t.Fatalf("headerCipherInto allocates %v times per packet, want 0", allocs)
	}
}

func BenchmarkHeaderProtectionPerPacket(b *testing.B) {
	device := newHeaderKeyDevice(b)
	datagram := make([]byte, 64)
	header := make([]byte, MessageTransportHeaderSize)
	b.Run("HeaderProtectionCipher", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cip, _ := device.HeaderProtectionCipher(datagram)
			cip.XORKeyStream(header, header)
		}
	})
	b.Run("headerCipherInto", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var cip chacha20.Cipher
			device.headerCipherInto(&cip, datagram)
			cip.XORKeyStream(header, header)
		}
	})
}

func BenchmarkTransportPaddingPerPacket(b *testing.B) {
	padding := make([]byte, 32)
	b.Run("crypto/rand", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rand.Read(padding)
		}
	})
	b.Run("ChaCha8", func(b *testing.B) {
		rng := newPaddingRNG()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			rng.Read(padding)
		}
	})
}
