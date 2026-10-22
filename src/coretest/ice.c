// ice.c
// Named tests of ICE in the peer layer and of the port mapping of home gateways (src/Core/PeerIce.c, PeerPortMap.c;
// CORE-S5-3 #79). The relay path runs on the NAT simulator of natsim.c, as in relay.c. ICE runs on the UDP sockets
// of libjuice, which the NAT simulator cannot carry, on the loopback interfaces: the IPv4 loopback stands for the
// public side, and the IPv6 loopback for the home network behind the simulated gateway of homegw.c. A socket on one
// cannot send to the other, so only the gateway joins them.
// iceupgrade: A, a node behind a home gateway, gets a public port from it through libplum (UPnP) and offers it as a
//   candidate. A and B come up through the relay R, and ICE then validates the direct path through that port in the
//   background: a stream of datagrams from B to A goes on through the move, with none missing. The gateway's link
//   goes down; consent freshness fails the direct path, the pair is on the relay again, and its traffic flows there.
// icesymmetric: A and B, each behind a symmetric NAT, come up through R. Neither end has a candidate that the other
//   can reach, nor a mapping that lets the other in, so every check fails, as between two symmetric NATs: the pair
//   stays on the relay, and its traffic flows there throughout. The port prediction and birthday punching that a
//   direct path would take are CORE-S5-4 (#266).

#include <winsock2.h>
#include <ws2tcpip.h>

#include "coretest.h"

#include <stdio.h>
#include <string.h>

#define ICE_WAIT      10000 // ms: a bounded wait for the networks to carry everything sent
#define ICE_MAP_WAIT  30000 // ms: for the gateway to grant a public port through libplum
#define ICE_UP_WAIT   30000 // ms: for ICE to validate the direct path once the gateway forwards
#define ICE_FAIL_WAIT 60000 // ms: for a session to fail, 30 s without consent or the 39.5 s of its checks
#define ICE_GAP       10    // ms between two datagrams of a stream
#define ICE_SETTLED   20    // Datagrams of the stream on the direct path before it ends

// One node of a test and what it received
typedef struct ICE_NODE {
	const char *Name;             // Its name
	PEER_KEY Key;                 // Its static key
	PEER_ADDR Addr;               // Its address on the harness network: private behind a NAT
	NATSIM_HOST *Host;            // Its host there
	PEER_AGENT *Agent;            // Its peer layer
	USHORT IcePort;               // The port of its ICE socket
	volatile LONG Received;       // Data datagrams delivered to it
	volatile LONG ReceivedDirect; // ... of them on the direct path
	volatile LONG Echo;           // Answer each "ping" with a "pong"
} ICE_NODE;

// The networks of a test: the relay R on the public side, A and B
typedef struct ICE_WORLD {
	NATSIM *Sim;      // The harness network of the relay path
	NATSIM_NAT *NatA; // A's NAT
	NATSIM_NAT *NatB; // B's NAT, NULL when B is on the public side
	ICE_NODE R, A, B; // The nodes
	bool WsaStarted;  // WSAStartup succeeded
} ICE_WORLD;

// The receive procedure of every node: count the datagram; with Echo, answer "ping ..." with "pong ..."
static void ice_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	ICE_NODE *n = (ICE_NODE *)param;
	char pong[64];

	if (path == PEER_PATH_DIRECT)
		InterlockedIncrement(&n->ReceivedDirect);
	InterlockedIncrement(&n->Received);

	if (InterlockedCompareExchange(&n->Echo, 0, 0) != 0 && size >= 4 && size < sizeof(pong) && memcmp(data, "ping", 4) == 0) {
		CopyMemory(pong, data, size);
		CopyMemory(pong, "pong", 4);
		PeerSend(a, src, pong, size);
	}
}

// A free UDP port on the loopback address of family, for an ICE socket; 0 when there is none
static USHORT ice_free_port(int family) {
	SOCKADDR_STORAGE sa;
	int len = (int)(family == AF_INET ? sizeof(SOCKADDR_IN) : sizeof(SOCKADDR_IN6));
	USHORT port = 0;

	SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
		return 0;

	ZeroMemory(&sa, sizeof(sa));
	sa.ss_family = (ADDRESS_FAMILY)family;
	if (family == AF_INET)
		((SOCKADDR_IN *)&sa)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		((SOCKADDR_IN6 *)&sa)->sin6_addr.s6_addr[15] = 1;

	if (bind(s, (const SOCKADDR *)&sa, len) == 0 && getsockname(s, (SOCKADDR *)&sa, &len) == 0)
		port = ntohs(family == AF_INET ? ((SOCKADDR_IN *)&sa)->sin_port : ((SOCKADDR_IN6 *)&sa)->sin6_port);

	closesocket(s);
	return port;
}

// A node of the world: its key from the fixed scalar first, its host behind nat (NULL: public) at addr, its peer
// layer with the configuration c
static bool ice_node(ICE_WORLD *w, ICE_NODE *n, const char *name, UCHAR first, NATSIM_NAT *nat, const PEER_ADDR *addr, PEER_CONFIG *c) {
	n->Name = name;
	n->Addr = *addr;
	n->IcePort = c->IcePort;
	coretest_fixed_key(&n->Key, first);
	n->Host = NatSimAddHost(w->Sim, nat, addr);
	if (n->Host == NULL)
		return false;

	n->Agent = PeerNew(&n->Key, c, NatSimSend, n->Host, ice_recv, n);
	NatSimAttach(n->Host, n->Agent);

	return n->Agent != NULL;
}

// A peer of the peer table: a node with the key key in one VRF
static void ice_peer(PEER_INFO *p, const char *name, const UCHAR *key, UINT vrf) {
	ZeroMemory(p, sizeof(PEER_INFO));
	strcpy_s(p->Name, sizeof(p->Name), name);
	CopyMemory(p->Key, key, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = vrf;
}

// Build the world: R on the public side; A behind a NAT of its home, or with symmetric behind a symmetric NAT; B
// on the public side, or with symmetric behind a symmetric NAT of its own. A's ICE socket is on ::1, B's on
// 127.0.0.1; with port_map, A asks its home gateway for a public port. Then the peers and the relays of every node,
// and the binds to R.
static bool ice_world_start(ICE_WORLD *w, bool symmetric, bool port_map) {
	PEER_CONFIG rc, ac, bc;
	PEER_ADDR addr;
	PEER_INFO p[2];
	PEER_RELAY_INFO ri;
	WSADATA wsa;
	bool ok = true;

	ZeroMemory(w, sizeof(ICE_WORLD));
	w->WsaStarted = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	w->Sim = NatSimNew();
	if (w->Sim == NULL)
		return false;

	UINT mapping = (symmetric ? NATSIM_MAP_ADDRESS_PORT_DEPENDENT : NATSIM_MAP_ENDPOINT_INDEPENDENT);
	UINT filtering = (symmetric ? NATSIM_FILTER_ADDRESS_PORT_DEPENDENT : NATSIM_FILTER_ENDPOINT_INDEPENDENT);
	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, mapping, filtering);
	w->NatB = (symmetric ? NatSimAddNat(w->Sim, 203, 0, 113, 20, mapping, filtering) : NULL);

	PeerDefaultConfig(&rc);
	rc.Relay = true;

	PeerDefaultConfig(&ac);
	ac.Ice = true;
	strcpy_s(ac.IceBind, sizeof(ac.IceBind), "::1");
	ac.IcePort = ice_free_port(AF_INET6);
	ac.PortMap = port_map;
	ac.PortMapTimeout = 2000;

	// libjuice tells the ICE sockets of one process apart by their port
	PeerDefaultConfig(&bc);
	bc.Ice = true;
	strcpy_s(bc.IceBind, sizeof(bc.IceBind), "127.0.0.1");
	bc.IcePort = ice_free_port(AF_INET);
	for (UINT i = 0; i < 16 && bc.IcePort == ac.IcePort; i++)
		bc.IcePort = ice_free_port(AF_INET);

	if (ac.IcePort == 0 || bc.IcePort == 0 || ac.IcePort == bc.IcePort)
		return false;

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = ice_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 192, 168, 1, 2, 5000);
	ok = ice_node(w, &w->A, "a", 1, w->NatA, &addr, &ac) && ok;
	if (symmetric)
		PeerAddrSetV4(&addr, 10, 0, 0, 2, 5000);
	else
		PeerAddrSetV4(&addr, 198, 51, 100, 8, 5000);
	ok = ice_node(w, &w->B, "b", 33, w->NatB, &addr, &bc) && ok;

	if (ok == false)
		return false;

	// The Peer objects of each node: A and B in VRF 10
	ice_peer(&p[0], "a", w->A.Key.Public, 10);
	ice_peer(&p[1], "b", w->B.Key.Public, 10);
	PeerSetPeers(w->R.Agent, p, 2);

	ice_peer(&p[0], "b", w->B.Key.Public, 10);
	ice_peer(&p[1], "r", w->R.Key.Public, 10);
	PeerSetPeers(w->A.Agent, p, 2);

	ice_peer(&p[0], "a", w->A.Key.Public, 10);
	ice_peer(&p[1], "r", w->R.Key.Public, 10);
	PeerSetPeers(w->B.Agent, p, 2);

	// The Relay objects: R is the home relay of A and B
	ZeroMemory(&ri, sizeof(ri));
	strcpy_s(ri.Name, sizeof(ri.Name), "r");
	CopyMemory(ri.Key, w->R.Key.Public, PEER_KEY_SIZE);
	ri.Addr = w->R.Addr;
	PeerSetRelays(w->A.Agent, &ri, 1);
	PeerSetRelays(w->B.Agent, &ri, 1);

	return NatSimWaitIdle(w->Sim, ICE_WAIT);
}

// Stop the world: the hosts take no more datagrams, then the peer layers end with their ICE sessions, whose
// callbacks may still send meanwhile, and the network last
static void ice_world_stop(ICE_WORLD *w) {
	ICE_NODE *nodes[] = {&w->R, &w->A, &w->B};

	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		InterlockedExchange(&nodes[i]->Echo, 0);
		if (nodes[i]->Host != NULL)
			NatSimAttach(nodes[i]->Host, NULL);
	}

	if (w->Sim != NULL)
		NatSimWaitIdle(w->Sim, ICE_WAIT);

	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		PeerFree(nodes[i]->Agent);
		nodes[i]->Agent = NULL;
		PeerKeyClose(&nodes[i]->Key);
	}

	NatSimFree(w->Sim);
	w->Sim = NULL;

	if (w->WsaStarted)
		WSACleanup();
}

// The stand-in of the control plane: from seals a signal of type for to, and to takes it. Returns what
// PeerOpenSignal returned, PEER_DROP_MALFORMED when nothing was sealed.
static UINT ice_signal(ICE_NODE *from, ICE_NODE *to, UINT type, PEER_SIGNAL *sig) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(from->Agent, to->Key.Public, type, env, sizeof(env));
	if (size == 0)
		return PEER_DROP_MALFORMED;

	return PeerOpenSignal(to->Agent, env, size, sig);
}

// Send one datagram from from to to with the text text
static bool ice_send(ICE_NODE *from, ICE_NODE *to, const char *text) {
	return PeerSend(from->Agent, to->Key.Public, text, (UINT)strlen(text));
}

// The path from from to to now, and its status into ps
static UINT ice_path(ICE_NODE *from, ICE_NODE *to, PEER_STATUS *ps) {
	PeerGetStatus(from->Agent, to->Key.Public, ps);

	return ps->Path;
}

// Wait until n has taken count datagrams, at most timeout ms: the networks carry the rest of a stream
static bool ice_wait_received(ICE_WORLD *w, ICE_NODE *n, LONG count, UINT timeout) {
	ULONGLONG end = GetTickCount64() + timeout;

	NatSimWaitIdle(w->Sim, timeout);
	while (InterlockedCompareExchange(&n->Received, 0, 0) < count) {
		if (GetTickCount64() >= end)
			return false;
		Sleep(5);
	}

	return true;
}

// Wait until the node offers a public port of its home gateway, at most timeout ms; its address into mapped
static bool ice_wait_mapped(ICE_NODE *n, PEER_ADDR *mapped, UINT timeout) {
	PEER_CANDIDATE c[PEER_MAX_CANDIDATES];
	ULONGLONG end = GetTickCount64() + timeout;

	while (GetTickCount64() < end) {
		UINT num = PeerGetCandidates(n->Agent, c, PEER_MAX_CANDIDATES);

		for (UINT i = 0; i < num; i++) {
			if (c[i].Type == PEER_CANDIDATE_MAPPED) {
				*mapped = c[i].Addr;
				return true;
			}
		}

		Sleep(50);
	}

	return false;
}

static UINT64 ice_forwarded(ICE_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Forwarded;
}

// The relay path first, the move to the direct path through the public port of the gateway with none of the stream
// missing, and the move back when the direct path dies
static void ice_upgrade(ICE_WORLD *w, HOMEGW *gw) {
	PEER_SIGNAL offer, answer;
	PEER_STATUS ps_a, ps_b;
	PEER_STATS st_a, st_b;
	PEER_ADDR mapped, public_port;
	USHORT external = 0;
	USHORT internal = 0;
	char text[64];
	char addr_text[64];
	LONG sent = 0;

	// The port mapping: libplum tries PCP and NAT-PMP at the default gateway of the host first, then UPnP
	ULONGLONG t0 = GetTickCount64();
	bool has_mapped = ice_wait_mapped(&w->A, &mapped, ICE_MAP_WAIT);
	coretest_info("the gateway answered %u M-SEARCH; A had its public port after %llu ms", HomeGwSearches(gw), GetTickCount64() - t0);
	coretest_check(has_mapped && HomeGwMapped(gw, &external, &internal) && internal == w->A.IcePort, "libplum found the gateway with UPnP, and it mapped a public port to A's ICE socket");
	PeerAddrSetV4(&public_port, 127, 0, 0, 1, external);
	PeerAddrToStr(addr_text, sizeof(addr_text), &mapped);
	coretest_info("A's public port: %s, forwarded to [::1]:%u", addr_text, w->A.IcePort);
	if (coretest_check(has_mapped && PeerAddrEqual(&mapped, &public_port), "A's candidates offer that public port on the gateway's WAN side") == false)
		return;

	// The checks of ICE meet a gateway whose link is down until the stream is under way on the relay
	HomeGwSetLink(gw, false);

	UINT r = ice_signal(&w->A, &w->B, PEER_SIGNAL_OFFER, &offer);
	bool first = (offer.NumCandidates >= 2 && offer.Candidates[0].Type == PEER_CANDIDATE_MAPPED && PeerAddrEqual(&offer.Candidates[0].Addr, &public_port));
	coretest_check(r == PEER_OK && offer.IceUfrag[0] != 0 && offer.IcePwd[0] != 0 && first && memcmp(offer.RelayKey, w->R.Key.Public, PEER_KEY_SIZE) == 0, "B takes A's offer: the relay assignment R, the credentials of A's ICE session, the public port first, then the host candidate");
	r = ice_signal(&w->B, &w->A, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(r == PEER_OK && answer.IceUfrag[0] != 0 && strcmp(answer.IceUfrag, offer.IceUfrag) != 0, "A takes B's answer, with the credentials of B's session");
	NatSimWaitIdle(w->Sim, ICE_WAIT);

	ice_path(&w->A, &w->B, &ps_a);
	ice_path(&w->B, &w->A, &ps_b);
	coretest_check(ps_a.Path == PEER_PATH_RELAY && ps_b.Path == PEER_PATH_RELAY && ps_a.Ice == PEER_ICE_CHECKING && ps_b.Ice == PEER_ICE_CHECKING, "The pair is on the relay at once, while ICE checks the candidate pairs in the background");

	// A stream from B to A: through R first
	for (UINT i = 0; i < ICE_SETTLED; i++) {
		snprintf(text, sizeof(text), "stream %ld", sent);
		if (ice_send(&w->B, &w->A, text))
			sent++;
		Sleep(ICE_GAP);
	}
	ice_wait_received(w, &w->A, sent, ICE_WAIT);
	coretest_check(sent == ICE_SETTLED && w->A.Received == sent && w->A.ReceivedDirect == 0, "The first datagrams of the stream reach A through R");

	// The link comes up: B's checks reach A through the public port, and the stream goes on through the move
	HomeGwSetLink(gw, true);
	t0 = GetTickCount64();
	UINT settled = 0;
	ULONGLONG moved = 0;
	while (settled < ICE_SETTLED && GetTickCount64() - t0 < ICE_UP_WAIT) {
		snprintf(text, sizeof(text), "stream %ld", sent);
		if (ice_send(&w->B, &w->A, text))
			sent++;

		bool direct = (ice_path(&w->A, &w->B, &ps_a) == PEER_PATH_DIRECT && ice_path(&w->B, &w->A, &ps_b) == PEER_PATH_DIRECT);
		if (direct && moved == 0)
			moved = GetTickCount64() - t0;
		settled = (direct ? settled + 1 : 0);
		Sleep(ICE_GAP);
	}

	bool all = ice_wait_received(w, &w->A, sent, ICE_WAIT);
	LONG direct = w->A.ReceivedDirect;
	coretest_info("ICE moved both ends to the direct path %llu ms after the link came up; of %ld datagrams of the stream, %ld came through R and %ld directly", moved, sent, w->A.Received - direct, direct);
	bool up = (ps_a.Ice == PEER_ICE_CONNECTED || ps_a.Ice == PEER_ICE_COMPLETED) && (ps_b.Ice == PEER_ICE_CONNECTED || ps_b.Ice == PEER_ICE_COMPLETED);
	coretest_check(settled == ICE_SETTLED && up, "ICE validated the direct path in the background, and both ends moved to it");
	coretest_check(all && w->A.Received == sent && direct >= ICE_SETTLED && w->A.Received - direct >= ICE_SETTLED, "Not one datagram of the stream went missing through the move from the relay to the direct path");

	PeerAddrToStr(addr_text, sizeof(addr_text), &ps_b.Direct);
	coretest_info("B reaches A at %s", addr_text);
	coretest_check(PeerAddrEqual(&ps_b.Direct, &public_port) && HomeGwForwarded(gw) != 0, "B reaches A at the public port that libplum got from the gateway: A became directly reachable there");

	// Both ways on the direct path, without R
	InterlockedExchange(&w->B.Echo, 1);
	UINT64 forwarded = ice_forwarded(&w->R);
	LONG a_direct = w->A.ReceivedDirect;
	bool ping = ice_send(&w->A, &w->B, "ping direct");
	ice_wait_received(w, &w->A, sent + 1, ICE_WAIT);
	coretest_check(ping && w->A.Received == sent + 1 && w->A.ReceivedDirect == a_direct + 1 && ice_forwarded(&w->R) == forwarded, "A's ping and B's pong both go on the direct path; R forwards neither");
	sent++;

	PeerGetStats(w->A.Agent, &st_a);
	PeerGetStats(w->B.Agent, &st_b);
	coretest_check(st_a.Upgrades == 1 && st_b.Upgrades == 1 && st_a.Fallbacks == 0 && st_a.NumIce == 1 && st_b.NumIce == 1, "Each end counts one ICE session, which moved its peer off the relay");

	// The gateway's link goes down: consent freshness fails the direct path, and the pair moves back to R
	HomeGwSetLink(gw, false);
	t0 = GetTickCount64();
	ULONGLONG back = 0;
	while (back == 0 && GetTickCount64() - t0 < ICE_FAIL_WAIT) {
		if (ice_path(&w->A, &w->B, &ps_a) == PEER_PATH_RELAY && ice_path(&w->B, &w->A, &ps_b) == PEER_PATH_RELAY)
			back = GetTickCount64() - t0;
		Sleep(100);
	}
	coretest_info("both ends were back on the relay %llu ms after the link went down", back);
	coretest_check(back != 0 && ps_a.Ice == PEER_ICE_FAILED && ps_b.Ice == PEER_ICE_FAILED, "Consent freshness failed the direct path, and both ends fell back to the relay");

	forwarded = ice_forwarded(&w->R);
	LONG received = w->A.Received;
	direct = w->A.ReceivedDirect;
	for (UINT i = 0; i < ICE_SETTLED; i++) {
		snprintf(text, sizeof(text), "after %u", i);
		ice_send(&w->B, &w->A, text);
	}
	ping = ice_send(&w->A, &w->B, "ping relayed");
	ice_wait_received(w, &w->A, received + ICE_SETTLED + 1, ICE_WAIT);
	coretest_check(ping && w->A.Received == received + ICE_SETTLED + 1 && w->A.ReceivedDirect == direct && ice_forwarded(&w->R) == forwarded + ICE_SETTLED + 2, "On the relay again the pair's traffic flows: B's datagrams, A's ping and B's pong all through R");

	PeerGetStats(w->A.Agent, &st_a);
	PeerGetStats(w->B.Agent, &st_b);
	coretest_check(st_a.Fallbacks == 1 && st_b.Fallbacks == 1, "Each end counts one fallback from the direct path to the relay");
}

void iceupgrade_test() {
	ICE_WORLD w;

	HOMEGW *gw = HomeGwNew();
	if (coretest_check(gw != NULL, "The simulated home gateway runs: SSDP on UDP 1900, its description and control URL over HTTP on 127.0.0.1") == false)
		return;

	bool started = ice_world_start(&w, false, true);
	coretest_check(started, "The networks start: R and B on the public side, A behind the NAT of its home; A's ICE socket on ::1 behind the gateway, B's on 127.0.0.1");
	if (started)
		ice_upgrade(&w, gw);

	ice_world_stop(&w);
	HomeGwFree(gw);
}

void icesymmetric_test() {
	ICE_WORLD w;
	PEER_SIGNAL offer, answer;
	PEER_STATUS ps_a, ps_b;
	PEER_STATS st_a, st_b;
	char text[64];
	LONG pings = 0;
	UINT off_relay = 0;

	bool started = ice_world_start(&w, true, false);
	coretest_check(started, "The networks start: R on the public side, A and B each behind a symmetric NAT of its own; A's ICE socket on ::1, B's on 127.0.0.1");
	if (started == false) {
		ice_world_stop(&w);
		return;
	}

	UINT r = ice_signal(&w.A, &w.B, PEER_SIGNAL_OFFER, &offer);
	coretest_check(r == PEER_OK && offer.IceUfrag[0] != 0, "B takes A's offer, with the credentials of A's ICE session");
	r = ice_signal(&w.B, &w.A, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(r == PEER_OK && answer.IceUfrag[0] != 0, "A takes B's answer, with the credentials of B's session");
	NatSimWaitIdle(w.Sim, ICE_WAIT);

	// Pings through R until ICE gives up, and the path at each of them
	InterlockedExchange(&w.B.Echo, 1);
	ULONGLONG t0 = GetTickCount64();
	while (GetTickCount64() - t0 < ICE_FAIL_WAIT) {
		snprintf(text, sizeof(text), "ping %ld", pings);
		if (ice_send(&w.A, &w.B, text))
			pings++;

		if (ice_path(&w.A, &w.B, &ps_a) != PEER_PATH_RELAY || ice_path(&w.B, &w.A, &ps_b) != PEER_PATH_RELAY)
			off_relay++;
		if (ps_a.Ice == PEER_ICE_FAILED && ps_b.Ice == PEER_ICE_FAILED)
			break;
		Sleep(200);
	}

	bool all = ice_wait_received(&w, &w.A, pings, ICE_WAIT);
	coretest_info("ICE gave up after %llu ms; A sent %ld pings meanwhile", GetTickCount64() - t0, pings);
	coretest_check(ps_a.Ice == PEER_ICE_FAILED && ps_b.Ice == PEER_ICE_FAILED, "ICE checked and gave up: neither end has a candidate that the other can reach, nor a mapping that lets the other in");
	coretest_check(pings != 0 && off_relay == 0 && all && w.B.Received == pings && w.A.Received == pings && w.A.ReceivedDirect == 0 && w.B.ReceivedDirect == 0, "The pair stayed on the relay throughout, and every ping had its pong through R");

	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st_a.Upgrades == 0 && st_b.Upgrades == 0 && st_a.Fallbacks == 0 && st_b.Fallbacks == 0, "No session moved the pair off the relay");
	coretest_info("a direct path for such a pair is the port prediction and birthday punching of CORE-S5-4 (#266)");

	ice_world_stop(&w);
}
