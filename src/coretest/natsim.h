// natsim.h
// The NAT simulator of the core tests (natsim.c), in a header of its own: coretest's peer tests and the tests of vpntest
// whose Nodes reach each other through NATs run their worlds on it.

#ifndef NATSIM_H
#define NATSIM_H

#include "Core/Peer.h"

// The NAT simulator (natsim.c): an in-process datagram network of hosts, each on the public side or behind a
// simulated NAT, that carries the datagrams of the peer layer in place of UDP sockets
typedef struct NATSIM NATSIM;
typedef struct NATSIM_NAT NATSIM_NAT;
typedef struct NATSIM_HOST NATSIM_HOST;

#define NATSIM_MAP_ENDPOINT_INDEPENDENT      1 // One public port for every destination (RFC 4787 section 4.1)
#define NATSIM_MAP_ADDRESS_PORT_DEPENDENT    2 // One public port per destination address and port: a symmetric NAT
#define NATSIM_FILTER_ENDPOINT_INDEPENDENT   1 // In from anywhere to a mapping (RFC 4787 section 5)
#define NATSIM_FILTER_ADDRESS_PORT_DEPENDENT 2 // In only from an address and port that the mapping sent to

// How a NAT picks the public port of a new mapping, which the port prediction of CORE-S5-4 (#266) learns
#define NATSIM_ALLOC_SEQUENTIAL 1 // The next port after the last, so a peer can predict it
#define NATSIM_ALLOC_PRESERVING 2 // The private source port, where it is free, else sequential
#define NATSIM_ALLOC_RANDOM     3 // A port a seeded generator picks, which no peer can predict

NATSIM *NatSimNew();
void NatSimFree(NATSIM *s);
NATSIM_NAT *NatSimAddNat(NATSIM *s, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, UINT mapping, UINT filtering);
void NatSimSetAllocation(NATSIM_NAT *n, UINT allocation, UINT32 seed);
NATSIM_HOST *NatSimAddHost(NATSIM *s, NATSIM_NAT *nat, const PEER_ADDR *addr);
void NatSimAttach(NATSIM_HOST *h, PEER_AGENT *a);
bool NatSimSend(void *param, const PEER_ADDR *dst, const void *data, UINT size);
bool NatSimWaitIdle(NATSIM *s, UINT timeout);
UINT NatSimFiltered(NATSIM_NAT *n);
UINT NatSimUnroutable(NATSIM *s);
bool NatSimMapped(NATSIM_NAT *n, const PEER_ADDR *inside, PEER_ADDR *pub);

// A tap of the network (natsim.c): sees every datagram that a host sends, on whatever link, before the network routes
// it, and drops it by returning false, as an attacker on the path would; it runs on the sending thread. Hold stops the
// delivery until it is released, so that datagrams sent meanwhile cross on the way.
typedef bool(NATSIM_TAP)(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size);
void NatSimSetTap(NATSIM *s, NATSIM_TAP *tap, void *param);
void NatSimHold(NATSIM *s, bool hold);

#endif // NATSIM_H
