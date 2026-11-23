/* SPDX-License-Identifier: MIT
 *
 * lx: SPEC 160 — how much of the message set a call has to put back in order.
 */

package conn

import "golang.org/x/net/ipv6"

// The message set holds IdealBatchSize messages because one read or one
// write may carry a full batch. Behind a netstack that hands packets over one
// at a time almost every call fills a single message, and resetting the whole
// set after each of them cost more than encrypting the packet it carried:
// about 7 % of the CPU of a tunnel endpoint on a Cortex-A55.
//
// Every user of the set fills it from the front: a send its first n
// messages, a receive one message per buffer it was given, and a receive
// with offload all of them. So the reset can stop at the first message that
// is still the way putMessages left it.

// messageUntouched reports whether msg is as putMessages leaves a message.
// Whoever uses a message gives it a buffer, so the buffer alone would tell;
// the rest costs nothing and keeps a message with only an address or control
// data from ending the reset early.
func messageUntouched(msg *ipv6.Message) bool {
	return len(msg.Buffers) == 1 && msg.Buffers[0] == nil && msg.Addr == nil && len(msg.OOB) == 0
}

// setMessageBuffer makes buf the only buffer of msg. Assigning Buffers[0]
// is not enough on the retry after a failed attempt with segmentation
// offload: the message still lists the segments that were coalesced into it,
// and they would go out again as the tail of this datagram.
func setMessageBuffer(msg *ipv6.Message, buf []byte) {
	msg.Buffers = append(msg.Buffers[:0], buf)
}
