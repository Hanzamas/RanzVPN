/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// juice-peer.h
// The peer mode of libjuice 1.7.4 for Ranz VPN (CORE-S5-6, #412; juice-peer.c): an agent of libjuice that sends and
// receives on the socket of the peer layer of a node (src/Core/PeerIce.c) in place of a socket of its own. libjuice
// gives its datagrams to the send procedure of the agent and takes the STUN messages that the peer layer hands it
// (juice_peer_input), so its checks run on the one socket that the binds and the records of the node go on, and on
// the network of a test, the NAT simulator of the core tests.
//
// An agent runs in the peer mode when it is made with the concurrency mode JUICE_CONCURRENCY_MODE_THREAD: the build of
// Ranz VPN puts juice-peer.c in the place of conn_thread.c (src/Core/3rdparty/CMakeLists.txt), which is the one change
// to libjuice. Its user_ptr points at a struct whose first member is a juice_peer_io_t, which the mode reads its
// send procedure and its host addresses from.

#ifndef JUICE_PEER_H
#define JUICE_PEER_H

#include <juice/juice.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sockaddr;
struct sockaddr_storage;

// The concurrency mode of an agent in the peer mode
#define JUICE_CONCURRENCY_MODE_PEER JUICE_CONCURRENCY_MODE_THREAD

// The host addresses that the peer mode takes from an agent at most
#define JUICE_PEER_MAX_ADDRS 8

// The I/O of an agent in the peer mode, the first member of the struct at its user_ptr
typedef struct juice_peer_io {
	// Sends one datagram of the agent to dst, dst_len bytes of a socket address; returns size, or a negative number
	// when the datagram could not be sent
	int (*send)(void *user_ptr, const struct sockaddr *dst, int dst_len, const char *data, size_t size);
	// Writes the host addresses of the socket into addrs, at most max, with its port; returns their number
	int (*get_addrs)(void *user_ptr, struct sockaddr_storage *addrs, int max);
} juice_peer_io_t;

// Whether data is a STUN message (RFC 8489): its first two bits zero, the magic cookie and a length that matches
bool juice_peer_is_stun(const char *data, size_t size);

// Hands the agent a STUN message that came to the socket from src, src_len bytes of a socket address. The agent takes
// a request that names its username fragment and an answer to one of its own requests, and nothing once it failed;
// returns whether it took the message.
bool juice_peer_input(juice_agent_t *agent, const char *data, size_t size, const struct sockaddr *src, int src_len);

// The address of the peer on the pair that the agent selected, into addr; returns its length, -1 for no pair
int juice_peer_selected(juice_agent_t *agent, struct sockaddr_storage *addr);

#ifdef __cplusplus
}
#endif

#endif // JUICE_PEER_H
