//go:build ios

// SPDX-License-Identifier: MIT

package device

import (
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestInboundBufferReturnAfterDefaultLimitChange(t *testing.T) {
	original := PreallocatedBuffersPerPool
	t.Cleanup(func() { PreallocatedBuffersPerPool = original })

	PreallocatedBuffersPerPool = 1
	bounded := new(Device)
	bounded.PopulatePools()
	large := bounded.GetMessageBuffer()
	boundedElem := bounded.GetInboundElement()
	boundedElem.buffer = large[:]

	PreallocatedBuffersPerPool = 0
	unbounded := new(Device)
	unbounded.PopulatePools()
	smallElem := unbounded.GetInboundElement()
	smallElem.buffer = buf.Get(MessageTransportSize)

	bounded.PutInboundElement(boundedElem)
	if got := bounded.pool.messageBuffers.count; got != 0 {
		t.Fatalf("bounded receive pool still owns %d buffers after return", got)
	}

	PreallocatedBuffersPerPool = 1
	// A packet-sized buffer must not be cast to a full WaitPool array.
	unbounded.PutInboundElement(smallElem)
}
