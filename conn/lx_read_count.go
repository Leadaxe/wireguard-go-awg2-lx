/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 158 part 2 — how many datagrams one read from the socket takes.
 */

package conn

import (
	"errors"
	"runtime"
	"syscall"

	"github.com/sagernet/sing/common/control"
)

// A receive routine holds one MaxMessageSize buffer per datagram it may read
// at once, for as long as the device is up: IdealBatchSize of them, 8 MiB per
// routine. The buffers cannot be smaller, since the length of a datagram is
// not known before it is read; there can only be fewer of them. On a
// Cortex-A55 between 100 and 150 Mbit/s the batch made no difference to speed
// or CPU, so a small machine may trade it for memory.
//
// Only the receive side is configured here. The message set stays at
// IdealBatchSize whatever the count is: Send takes more datagrams per call
// than a read does, a whole handshake burst or a batch of injected packets.

// SetReadDatagramCount makes each read take at most count datagrams, from 1
// to IdealBatchSize. It applies where the bind reads in batches, on Linux and
// Android, and is accepted and ignored elsewhere.
//
// Call it before the first Open and never again: the device sizes per-peer
// state from BatchSize once, so the count has to stay the same over every
// reopen of the bind.
func (s *StdNetBind) SetReadDatagramCount(count int) error {
	if count < 1 || count > IdealBatchSize {
		return errors.New("read datagram count out of range")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.v4) > 0 || len(s.v6) > 0 {
		return ErrBindAlreadyOpen
	}
	s.readDatagrams.Store(int32(count))
	return nil
}

// readBatchSize is the batch size of a bind that reads in batches.
func (s *StdNetBind) readBatchSize() int {
	if count := int(s.readDatagrams.Load()); count > 0 {
		return count
	}
	return IdealBatchSize
}

// listenControl is the control function the sockets are created with. Below
// a full batch it also turns receive offload off: the kernel hands a
// coalesced datagram over as one, and splitting it back needs the full set of
// buffers. It does so in the same pass that sets the other socket options,
// before the socket is bound, so no datagram can arrive coalesced.
//
// Segmentation offload on send does not depend on the read batch and stays.
func (s *StdNetBind) listenControl() control.Func {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" || s.readBatchSize() == IdealBatchSize {
		return s.externalControl
	}
	return func(network, address string, conn syscall.RawConn) error {
		err := disableReceiveOffload(conn)
		if err != nil {
			return err
		}
		if s.externalControl != nil {
			return s.externalControl(network, address, conn)
		}
		return nil
	}
}
