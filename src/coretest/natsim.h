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

// The ageing of the mappings of a NAT (CORE-S5-5, #411): a mapping that carried no datagram out for the timeout of its
// NAT is gone, as on a real NAT, so only a keepalive keeps a path open through it
void NatSimSetTimeout(NATSIM *s, NATSIM_NAT *n, UINT timeout);
UINT NatSimExpired(NATSIM_NAT *n);

// The port forward of a home gateway and the loss of the mappings of a NAT (CORE-S5-6, #412): a public port of a NAT
// that leads to the host behind it with that port, in from anywhere and out to anywhere, never aged; and the drop of
// every other mapping of a host, after which its next datagram out gets a new public port
void NatSimPublic(NATSIM_NAT *n, PEER_ADDR *pub);
bool NatSimForward(NATSIM *s, NATSIM_NAT *n, USHORT port, USHORT inside_port);
bool NatSimUnforward(NATSIM *s, NATSIM_NAT *n, USHORT port);
UINT NatSimDrop(NATSIM *s, NATSIM_NAT *n, const PEER_ADDR *inside);

// The simulated home gateway of a NAT (homegw.c): a UPnP Internet Gateway Device that libplum finds with SSDP on the
// loopback interfaces of the host and asks for a port mapping over HTTP on 127.0.0.1, which it grants as a port forward
// of its NAT on the network of the simulator, with the public address of the NAT as its external address. It answers the
// sockets of its own process only, where the nodes of a test run, and counts what they asked, so a test sees that a node
// with port mapping off asked nothing.
typedef struct HOMEGW HOMEGW;

HOMEGW *HomeGwNew(NATSIM *s, NATSIM_NAT *nat);
void HomeGwFree(HOMEGW *g);
bool HomeGwMapped(HOMEGW *g, USHORT *external, USHORT *internal);
bool HomeGwDrop(HOMEGW *g);
UINT HomeGwSearches(HOMEGW *g);
UINT HomeGwRequests(HOMEGW *g);

// A tap of the network (natsim.c): sees every datagram that a host sends, on whatever link, before the network routes
// it, and drops it by returning false, as an attacker on the path would; it runs on the sending thread. Hold stops the
// delivery until it is released, so that datagrams sent meanwhile cross on the way.
typedef bool(NATSIM_TAP)(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size);
void NatSimSetTap(NATSIM *s, NATSIM_TAP *tap, void *param);
void NatSimHold(NATSIM *s, bool hold);

// The symmetric-NAT punch in the world of a carrier-grade NAT (CORE-S5-7, #413): the other subscribers of a NAT take
// public ports between two mappings of a host, as many as a seeded draw of the NAT's generator gives, so a test is
// reproducible for its seed; a cut loses every datagram between the public address of a NAT and that of another NAT on
// the way, after the NAT that sent it mapped it, while the datagrams to and from the public hosts pass; and an attacker
// on the link of a host hands it a datagram from any address, past its NAT.
UINT NatSimTake(NATSIM *s, NATSIM_NAT *n, UINT max);
void NatSimCut(NATSIM *s, NATSIM_NAT *n, bool cut);
UINT NatSimCutCount(NATSIM *s);
bool NatSimInject(NATSIM_HOST *to, const PEER_ADDR *from, const void *data, UINT size);

#endif // NATSIM_H
