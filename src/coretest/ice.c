// ice.c
// Named tests of ICE in the peer layer and of the port mapping of home gateways (src/Core/PeerIce.c, PeerPortMap.c;
// CORE-S5-3 #79, CORE-S5-6 #412), on the NAT simulator of natsim.c. ICE runs on the socket of each peer layer, in the
// peer mode of libjuice (src/Core/3rdparty/juice-peer.c), so the simulator carries its checks and their answers as it
// carries the binds and the records, through the same NATs. The home gateway of a NAT is the simulated one of homegw.c,
// which libplum finds on the loopback interfaces of the host and whose port mapping is a port forward of the NAT.
// iceupgrade: A, a node behind the symmetric NAT of its home gateway, gets a public port from the gateway through
//   libplum (UPnP) and offers it as its first candidate. A and B, behind a cone NAT, come up through the relay R, and
//   ICE then validates the direct path through that port in the background: a stream of datagrams from B to A goes on
//   through the move, with none missing. The gateway loses the mapping; consent freshness fails the direct path at
//   both ends, the pair is on the relay again, and its traffic flows there.
// icesymmetric: A and B, each behind a symmetric NAT, come up through R. Neither end has a candidate that the other
//   can reach, nor a mapping that lets the other in, so every check fails, as between two symmetric NATs: the pair
//   stays on the relay, and its traffic flows there throughout. The port prediction and birthday punching that a
//   direct path would take are CORE-S5-4 (#266).

#include <winsock2.h>
#include <ws2tcpip.h>

#include "coretest.h"

#include <stdio.h>
#include <string.h>

#define ICE_WAIT         10000 // ms: a bounded wait for the network to carry everything sent
#define ICE_MAP_WAIT     30000 // ms: for the gateway to grant a public port through libplum
#define ICE_UP_WAIT      30000 // ms: for ICE to validate and nominate the direct path once the checks pass
#define ICE_FAIL_WAIT    90000 // ms: for a session to fail, 30 s without consent or the 39.5 s of its checks
#define ICE_GAP          10    // ms between two datagrams of a stream
#define ICE_SETTLED      20    // Datagrams of the stream on the direct path before it ends
#define ICE_TICK         100   // ms between two ticks of the peer layers: their binds and session timers
#define ICE_BIND         400   // The keepalive of the bindings of A and B (ms) ...
#define ICE_BIND_RETRY   200   // ... and their retry (ms)
#define ICE_PORT         5000  // The port of the socket of A and B on their home networks
#define ICE_MAP_TIMEOUT  2000  // ms that libplum waits for a gateway per protocol

// One node of a test and what it received
typedef struct ICE_NODE {
	const char *Name;             // Its name
	PEER_KEY Key;                 // Its static key
	PEER_ADDR Addr;               // Its address on the network: private behind a NAT
	NATSIM_HOST *Host;            // Its host there
	PEER_AGENT *Agent;            // Its peer layer
	volatile LONG Received;       // Data datagrams delivered to it
	volatile LONG ReceivedDirect; // ... of them on the direct path
	volatile LONG Echo;           // Answer each "ping" with a "pong"
} ICE_NODE;

// The network of a test: the relay R on the public side, A and B behind NATs of their own
typedef struct ICE_WORLD {
	NATSIM *Sim;              // The network
	NATSIM_NAT *NatA;         // A's NAT
	NATSIM_NAT *NatB;         // B's NAT
	HOMEGW *Gateway;          // The home gateway of A's NAT, NULL without the port mapping
	ICE_NODE R, A, B;         // The nodes
	volatile LONG BlockIce;   // The network drops every STUN message while it is set
	volatile LONG Halt;       // Ends the ticker
	HANDLE Ticker;            // The thread that ticks the peer layers
	bool WsaStarted;          // WSAStartup succeeded
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

// Whether a datagram is a STUN message: the magic cookie of RFC 8489 where a STUN message has it, and a length that
// matches. No datagram of the peer layer has it there.
static bool ice_is_stun(const UCHAR *data, UINT size) {
	return size >= 20 && (data[0] & 0xC0) == 0 && data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42 &&
		   (UINT)((data[2] << 8) | data[3]) + 20 == size;
}

// The tap of the network: it drops every STUN message while BlockIce is set
static bool ice_tap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size) {
	ICE_WORLD *w = (ICE_WORLD *)param;

	return InterlockedCompareExchange(&w->BlockIce, 0, 0) == 0 || ice_is_stun(data, size) == false;
}

// The ticker: the timers of the peer layers, which renew the binds and run the sessions, as the receive thread of a UDP
// socket runs them on a node
static DWORD WINAPI ice_ticker(LPVOID param) {
	ICE_WORLD *w = (ICE_WORLD *)param;

	while (InterlockedCompareExchange(&w->Halt, 0, 0) == 0) {
		PeerTick(w->R.Agent);
		PeerTick(w->A.Agent);
		PeerTick(w->B.Agent);
		Sleep(ICE_TICK);
	}

	return 0;
}

// A node of the world: its key from the fixed scalar first, its host behind nat (NULL: public) at addr, its peer
// layer with the configuration c
static bool ice_node(ICE_WORLD *w, ICE_NODE *n, const char *name, UCHAR first, NATSIM_NAT *nat, const PEER_ADDR *addr, PEER_CONFIG *c) {
	n->Name = name;
	n->Addr = *addr;
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

// Build the world: R on the public side; A behind a NAT of its home, B behind a NAT of its own. Without symmetric, A's
// NAT is symmetric and has a home gateway that A asks for a public port, and B's is a port-restricted cone; with it,
// both are symmetric and no one asks a gateway. ICE runs on the socket of every node but R; the host candidates of A
// and B are their private addresses. Then the peers and the relays of every node, the binds to R and the ticker.
static bool ice_world_start(ICE_WORLD *w, bool symmetric) {
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
	NatSimSetTap(w->Sim, ice_tap, w);

	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	w->NatB = NatSimAddNat(w->Sim, 203, 0, 113, 20, (symmetric ? NATSIM_MAP_ADDRESS_PORT_DEPENDENT : NATSIM_MAP_ENDPOINT_INDEPENDENT), NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);

	PeerDefaultConfig(&rc);
	rc.Relay = true;

	PeerDefaultConfig(&ac);
	ac.Ice = true;
	ac.PortMap = (symmetric == false);
	ac.PortMapTimeout = ICE_MAP_TIMEOUT;
	ac.BindInterval = ICE_BIND;
	ac.BindRetry = ICE_BIND_RETRY;

	PeerDefaultConfig(&bc);
	bc.Ice = true;
	bc.BindInterval = ICE_BIND;
	bc.BindRetry = ICE_BIND_RETRY;

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = ice_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 192, 168, 1, 2, ICE_PORT);
	ok = ice_node(w, &w->A, "a", 1, w->NatA, &addr, &ac) && ok;
	PeerAddrSetV4(&addr, 10, 0, 0, 2, ICE_PORT);
	ok = ice_node(w, &w->B, "b", 33, w->NatB, &addr, &bc) && ok;

	if (ok == false)
		return false;

	// The gateway of A's home answers before A asks it, which A does once its host candidates name its port
	if (symmetric == false) {
		w->Gateway = HomeGwNew(w->Sim, w->NatA);
		if (w->Gateway == NULL)
			return false;
	}

	PeerSetHostCandidates(w->A.Agent, &w->A.Addr, 1);
	PeerSetHostCandidates(w->B.Agent, &w->B.Addr, 1);

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

	w->Ticker = CreateThread(NULL, 0, ice_ticker, w, 0, NULL);

	return w->Ticker != NULL && NatSimWaitIdle(w->Sim, ICE_WAIT);
}

// Stop the world: the ticker, then the hosts take no more datagrams, then the peer layers end with their ICE sessions,
// whose threads may still send meanwhile, then the gateway and the network last
static void ice_world_stop(ICE_WORLD *w) {
	ICE_NODE *nodes[] = {&w->R, &w->A, &w->B};

	InterlockedExchange(&w->Halt, 1);
	if (w->Ticker != NULL) {
		WaitForSingleObject(w->Ticker, INFINITE);
		CloseHandle(w->Ticker);
	}

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

	HomeGwFree(w->Gateway);
	w->Gateway = NULL;

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

// Wait until n has taken count datagrams, at most timeout ms: the network carries the rest of a stream
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

// Whether the node has a candidate of type, its address into addr
static bool ice_candidate(ICE_NODE *n, UINT type, PEER_ADDR *addr) {
	PEER_CANDIDATE c[PEER_MAX_CANDIDATES];
	UINT num = PeerGetCandidates(n->Agent, c, PEER_MAX_CANDIDATES);

	for (UINT i = 0; i < num; i++) {
		if (c[i].Type == type) {
			*addr = c[i].Addr;
			return true;
		}
	}

	return false;
}

// Wait until the node offers a public port of its home gateway, at most timeout ms; its address into mapped
static bool ice_wait_mapped(ICE_NODE *n, PEER_ADDR *mapped, UINT timeout) {
	ULONGLONG end = GetTickCount64() + timeout;

	while (GetTickCount64() < end) {
		if (ice_candidate(n, PEER_CANDIDATE_MAPPED, mapped))
			return true;

		Sleep(50);
	}

	return false;
}

// Wait until the home relay saw the node at its public port, at most timeout ms: the node's next bind went out
// through the port forward, which carries every datagram of the node, and its server reflexive candidate is the
// public port, which the candidates name once
static bool ice_wait_rebound(ICE_NODE *n, UINT timeout) {
	ULONGLONG end = GetTickCount64() + timeout;
	PEER_ADDR srflx;

	while (GetTickCount64() < end) {
		if (PeerHomeBound(n->Agent) && ice_candidate(n, PEER_CANDIDATE_SRFLX, &srflx) == false)
			return true;

		Sleep(50);
	}

	return false;
}

static UINT64 ice_forwarded(ICE_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Forwarded;
}

// Whether both ends are on the relay path with their ICE sessions failed, within timeout ms; the time it took into took
static bool ice_wait_fallback(ICE_WORLD *w, PEER_STATUS *ps_a, PEER_STATUS *ps_b, UINT timeout, ULONGLONG *took) {
	ULONGLONG t0 = GetTickCount64();

	while (GetTickCount64() - t0 < timeout) {
		if (ice_path(&w->A, &w->B, ps_a) == PEER_PATH_RELAY && ice_path(&w->B, &w->A, ps_b) == PEER_PATH_RELAY && ps_a->Ice == PEER_ICE_FAILED && ps_b->Ice == PEER_ICE_FAILED) {
			*took = GetTickCount64() - t0;
			return true;
		}
		Sleep(100);
	}

	return false;
}

// The relay path first, the move to the direct path through the public port of the gateway with none of the stream
// missing, and the move back when the direct path dies
static void ice_upgrade(ICE_WORLD *w) {
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
	coretest_info("the gateway answered %u M-SEARCH and %u HTTP requests; A had its public port after %llu ms", HomeGwSearches(w->Gateway), HomeGwRequests(w->Gateway), GetTickCount64() - t0);
	coretest_check(has_mapped && HomeGwMapped(w->Gateway, &external, &internal) && internal == ICE_PORT, "libplum found the gateway with UPnP, and it mapped a public port of A's NAT to the socket of A's peer layer");
	NatSimPublic(w->NatA, &public_port);
	public_port.Port = external;
	PeerAddrToStr(addr_text, sizeof(addr_text), &mapped);
	coretest_info("A's public port: %s, forwarded to its socket on port %u", addr_text, ICE_PORT);
	if (coretest_check(has_mapped && PeerAddrEqual(&mapped, &public_port), "A's candidates offer that public port on the external address of the gateway") == false)
		return;

	// The forward carries every datagram of A out, so the next bind of A reaches R from the public port
	bool rebound = ice_wait_rebound(&w->A, ICE_WAIT);
	coretest_check(rebound, "A's next bind went out through the port forward: R saw A at the public port, which A's candidates name once");

	// The checks of ICE are lost on the way until the stream is under way on the relay
	InterlockedExchange(&w->BlockIce, 1);

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

	// The checks pass: B's reach A through the public port, and the stream goes on through the move
	InterlockedExchange(&w->BlockIce, 0);
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
	coretest_info("ICE moved both ends to the direct path %llu ms after the checks passed; of %ld datagrams of the stream, %ld came through R and %ld directly", moved, sent, w->A.Received - direct, direct);
	coretest_check(settled == ICE_SETTLED && ps_a.Ice == PEER_ICE_COMPLETED && ps_b.Ice == PEER_ICE_COMPLETED, "ICE validated and nominated the direct path in the background, and both ends moved to it");
	coretest_check(all && w->A.Received == sent && direct >= ICE_SETTLED && w->A.Received - direct >= ICE_SETTLED, "Not one datagram of the stream went missing through the move from the relay to the direct path");

	PeerAddrToStr(addr_text, sizeof(addr_text), &ps_b.Direct);
	coretest_info("B reaches A at %s", addr_text);
	coretest_check(PeerAddrEqual(&ps_b.Direct, &public_port), "B reaches A at the public port that libplum got from the gateway: A became directly reachable there");

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
	coretest_check(st_a.Upgrades == 1 && st_b.Upgrades == 1 && st_a.Fallbacks == 0 && st_a.NumIce == 1 && st_b.NumIce == 1 && st_a.PortMap == PEER_PORTMAP_MAPPED && st_b.PortMap == PEER_PORTMAP_OFF,
		"Each end counts one Upgrade of its ICE session; A's port mapping is mapped, B asked no gateway");

	// The gateway loses the mapping: the checks of consent freshness fail both ways, and the pair moves back to R
	coretest_check(HomeGwDrop(w->Gateway), "The gateway loses its mapping, as a gateway that restarts does");
	ULONGLONG back = 0;
	bool fell = ice_wait_fallback(w, &ps_a, &ps_b, ICE_FAIL_WAIT, &back);
	coretest_info("both ends were back on the relay %llu ms after the gateway lost the mapping", back);
	coretest_check(fell, "Consent freshness failed the direct path, and both ends fell back to the relay");

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
	coretest_check(st_a.Fallbacks == 1 && st_b.Fallbacks == 1, "Each end counts one Fallback from the direct path to the relay");
}

void iceupgrade_test() {
	ICE_WORLD w;

	bool started = ice_world_start(&w, false);
	coretest_check(started, "The network starts: R on the public side, A behind the symmetric NAT of its home gateway, B behind a port-restricted cone NAT; the gateway answers SSDP and HTTP on the loopback interfaces");
	if (started)
		ice_upgrade(&w);

	ice_world_stop(&w);
}

void icesymmetric_test() {
	ICE_WORLD w;
	PEER_SIGNAL offer, answer;
	PEER_STATUS ps_a, ps_b;
	PEER_STATS st_a, st_b;
	char text[64];
	LONG pings = 0;
	UINT off_relay = 0;

	bool started = ice_world_start(&w, true);
	coretest_check(started, "The network starts: R on the public side, A and B each behind a symmetric NAT of its own, ICE on the socket of each");
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
