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
// iceanswer (CORE-S5-6-R1, #537): A and B, each behind a port-restricted cone NAT, offer at once, as when the dial of the
//   end of the higher key failed, and both keep the offer of the higher key; the answer to it is lost on the way. The
//   session of that offer waits for its answer, and libjuice runs no timer before it has one: it fails after
//   PEER_ICE_ANSWER_TIMEOUT, about 40 s, while the pair stays on the relay with its traffic flowing, and not before, even
//   at a tick whose clock is earlier than the start of the session (CORE-S5-6-R2, #557). ICE then runs again for the
//   pair: the end of the lower key offers again, the other takes the offer, as its failed session waits for no answer,
//   and the new sessions move the pair to the direct path.
// iceinput (CORE-S5-6-R1, #537): B holds an ICE session with A, and later ICE_MANY more. A STUN message that any sender
//   sends to B's socket is read once, whatever the number of B's sessions, as the count of the reads that juice_peer_read
//   makes shows, and nothing reads it again later (CORE-S5-6-R2, #557): a check that names the username fragment of the
//   session with A goes to that session, as does an answer to the last check of that session, and a check that names no
//   session, an answer to no check and a message that does not read are dropped.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "coretest.h"

#include <stdio.h>
#include <string.h>

#define ICE_WAIT        10000 // ms: a bounded wait for the network to carry everything sent
#define ICE_MAP_WAIT    30000 // ms: for the gateway to grant a public port through libplum
#define ICE_UP_WAIT     30000 // ms: for ICE to validate and nominate the direct path once the checks pass
#define ICE_FAIL_WAIT   90000 // ms: for a session to fail, 30 s without consent or the 39.5 s of its checks
#define ICE_GAP         10    // ms between two datagrams of a stream
#define ICE_SETTLED     20    // Datagrams of the stream on the direct path before it ends
#define ICE_TICK        100   // ms between two ticks of the peer layers: their binds and session timers
#define ICE_BIND        400   // The keepalive of the bindings of A and B (ms) ...
#define ICE_BIND_RETRY  200   // ... and their retry (ms)
#define ICE_PORT        5000  // The port of the socket of A and B on their home networks
#define ICE_MAP_TIMEOUT 2000  // ms that libplum waits for a gateway per protocol
#define ICE_ANSWER_LATE 10000 // ms past PEER_ICE_ANSWER_TIMEOUT within which a session without its answer fails
#define ICE_MANY        48    // The sessions of B besides the one with A in the second round of iceinput
#define ICE_ID_SIZE     12    // The transaction id of a STUN message (RFC 8489 section 5)

// The world of a test: A behind the symmetric NAT of its home gateway, which grants it a public port, and B behind a
// port-restricted cone (iceupgrade); A and B each behind a symmetric NAT (icesymmetric); or each behind a
// port-restricted cone (iceanswer, iceinput)
#define ICE_WORLD_GATEWAY   1
#define ICE_WORLD_SYMMETRIC 2
#define ICE_WORLD_CONES     3

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
	NATSIM *Sim;                // The network
	NATSIM_NAT *NatA;           // A's NAT
	NATSIM_NAT *NatB;           // B's NAT
	HOMEGW *Gateway;            // The home gateway of A's NAT, NULL without the port mapping
	ICE_NODE R, A, B;           // The nodes
	volatile LONG BlockIce;     // The network drops every STUN message while it is set
	volatile LONG Halt;         // Ends the ticker
	HANDLE Ticker;              // The thread that ticks the peer layers
	bool WsaStarted;            // WSAStartup succeeded
	SRWLOCK CheckLock;          // The last check that B sent, which the tap keeps: ...
	bool HasCheck;              // ... once B sent one
	UCHAR CheckId[ICE_ID_SIZE]; // ... its transaction id
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

// The tap of the network: it keeps the transaction id of the last check that B sends, a binding request, and drops every
// STUN message while BlockIce is set
static bool ice_tap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size) {
	ICE_WORLD *w = (ICE_WORLD *)param;
	bool stun = ice_is_stun(data, size);

	if (stun && from == w->B.Host && data[0] == 0x00 && data[1] == 0x01) {
		AcquireSRWLockExclusive(&w->CheckLock);
		CopyMemory(w->CheckId, data + 8, ICE_ID_SIZE);
		w->HasCheck = true;
		ReleaseSRWLockExclusive(&w->CheckLock);
	}

	return InterlockedCompareExchange(&w->BlockIce, 0, 0) == 0 || stun == false;
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

// Build the world of kind (ICE_WORLD_*): R on the public side; A behind a NAT of its home, B behind a NAT of its own.
// With ICE_WORLD_GATEWAY, A's NAT is symmetric and has a home gateway that A asks for a public port, and B's is a
// port-restricted cone; with ICE_WORLD_SYMMETRIC both are symmetric, and with ICE_WORLD_CONES both are port-restricted
// cones, and no one asks a gateway. ICE runs on the socket of every node but R; the host candidates of A and B are their
// private addresses. Then the peers and the relays of every node, the binds to R and the ticker.
static bool ice_world_start(ICE_WORLD *w, UINT kind) {
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

	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, (kind == ICE_WORLD_CONES ? NATSIM_MAP_ENDPOINT_INDEPENDENT : NATSIM_MAP_ADDRESS_PORT_DEPENDENT), NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	w->NatB = NatSimAddNat(w->Sim, 203, 0, 113, 20, (kind == ICE_WORLD_SYMMETRIC ? NATSIM_MAP_ADDRESS_PORT_DEPENDENT : NATSIM_MAP_ENDPOINT_INDEPENDENT), NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);

	PeerDefaultConfig(&rc);
	rc.Relay = true;

	PeerDefaultConfig(&ac);
	ac.Ice = true;
	ac.PortMap = (kind == ICE_WORLD_GATEWAY);
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
	if (kind == ICE_WORLD_GATEWAY) {
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

	bool started = ice_world_start(&w, ICE_WORLD_GATEWAY);
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

	bool started = ice_world_start(&w, ICE_WORLD_SYMMETRIC);
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

// Whether both ends are on the direct path with their sessions completed within timeout ms
static bool ice_wait_direct(ICE_NODE *x, ICE_NODE *y, PEER_STATUS *ps_x, PEER_STATUS *ps_y, UINT timeout) {
	ULONGLONG t0 = GetTickCount64();

	while (GetTickCount64() - t0 < timeout) {
		if (ice_path(x, y, ps_x) == PEER_PATH_DIRECT && ice_path(y, x, ps_y) == PEER_PATH_DIRECT && ps_x->Ice == PEER_ICE_COMPLETED && ps_y->Ice == PEER_ICE_COMPLETED)
			return true;
		Sleep(50);
	}

	return false;
}

void iceanswer_test() {
	ICE_WORLD w;
	PEER_SIGNAL offer_hi, offer_lo, offer, answer;
	PEER_STATUS ps_lo, ps_hi;
	PEER_STATS st_lo, st_hi;
	UCHAR env_hi[PEER_MAX_ENVELOPE];
	UCHAR env_lo[PEER_MAX_ENVELOPE];
	UCHAR env[PEER_MAX_ENVELOPE];
	char text[64];
	LONG pings = 0;
	UINT off_relay = 0;

	bool started = ice_world_start(&w, ICE_WORLD_CONES);
	coretest_check(started, "The network starts: R on the public side, A and B each behind a port-restricted cone NAT of its own, ICE on the socket of each");
	if (started == false) {
		ice_world_stop(&w);
		return;
	}

	// The end of the lower key and the end of the higher key
	ICE_NODE *lo = (memcmp(w.A.Key.Public, w.B.Key.Public, PEER_KEY_SIZE) < 0 ? &w.A : &w.B);
	ICE_NODE *hi = (lo == &w.A ? &w.B : &w.A);
	coretest_info("%s has the lower key and %s the higher", lo->Name, hi->Name);

	// Both offer at once, as when the dial of the end of the higher key failed, and the session of each is its own offer.
	// The lower end takes the offer of the higher one in place of its own, and the higher end keeps its own (PeerIceRemote).
	ULONGLONG t0 = GetTickCount64();
	UINT size_hi = PeerSealSignal(hi->Agent, lo->Key.Public, PEER_SIGNAL_OFFER, env_hi, sizeof(env_hi));
	UINT size_lo = PeerSealSignal(lo->Agent, hi->Key.Public, PEER_SIGNAL_OFFER, env_lo, sizeof(env_lo));
	UINT r_lo = (size_hi != 0 ? PeerOpenSignal(lo->Agent, env_hi, size_hi, &offer_hi) : PEER_DROP_MALFORMED);
	UINT r_hi = (size_lo != 0 ? PeerOpenSignal(hi->Agent, env_lo, size_lo, &offer_lo) : PEER_DROP_MALFORMED);
	coretest_check(r_lo == PEER_OK && r_hi == PEER_OK && offer_hi.IceUfrag[0] != 0 && offer_lo.IceUfrag[0] != 0, "Both ends offer at once, each with the credentials of its own session, and each takes the offer of the other");

	// The answer of the lower end to the offer that both keep is lost on the way: sealed, and never carried. The answer of
	// the higher end carries no credentials, as its session is its own offer, which waits for the lost answer.
	UINT lost = PeerSealSignal(lo->Agent, hi->Key.Public, PEER_SIGNAL_ANSWER, env, sizeof(env));
	UINT r = ice_signal(hi, lo, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(lost != 0 && r == PEER_OK && answer.IceUfrag[0] == 0, "The answer of the lower end to the offer of the higher end is lost on the way; the answer of the higher end carries no credentials, as its session waits for the lost one");
	NatSimWaitIdle(w.Sim, ICE_WAIT);

	ice_path(lo, hi, &ps_lo);
	ice_path(hi, lo, &ps_hi);
	coretest_check(ps_lo.Path == PEER_PATH_RELAY && ps_hi.Path == PEER_PATH_RELAY && ps_lo.Ice == PEER_ICE_CHECKING && ps_hi.Ice == PEER_ICE_CHECKING, "The pair is on the relay at once, and the session of each end checks, the one of the higher end with no answer");

	// The higher end ticks at a clock that its session started after, as a tick that read its clock before the offer made
	// the session would, then at the clock 1 ms short of PEER_ICE_ANSWER_TIMEOUT after the offers: the session is younger
	// than 40 s at both, and neither fails it (CORE-S5-6-R2, #557)
	PeerIceTickAt(hi->Agent, t0 - 1);
	ice_path(hi, lo, &ps_hi);
	UINT before = ps_hi.Ice;
	PeerIceTickAt(hi->Agent, t0 + PEER_ICE_ANSWER_TIMEOUT - 1);
	ice_path(hi, lo, &ps_hi);
	coretest_check(before == PEER_ICE_CHECKING && ps_hi.Ice == PEER_ICE_CHECKING, "A tick at a clock that the session of the higher end started after, as when the tick read its clock before the offer made the session, does not fail the session, nor does one 1 ms short of 40 s after the offers");

	// Pings through R while the session of the higher end waits for its answer, until it fails
	InterlockedExchange(&hi->Echo, 1);
	ULONGLONG failed = 0;
	while (GetTickCount64() - t0 < PEER_ICE_ANSWER_TIMEOUT + ICE_ANSWER_LATE) {
		snprintf(text, sizeof(text), "ping %ld", pings);
		if (ice_send(lo, hi, text))
			pings++;

		if (ice_path(lo, hi, &ps_lo) != PEER_PATH_RELAY || ice_path(hi, lo, &ps_hi) != PEER_PATH_RELAY)
			off_relay++;
		if (ps_hi.Ice == PEER_ICE_FAILED) {
			failed = GetTickCount64() - t0;
			break;
		}
		Sleep(200);
	}

	bool all = ice_wait_received(&w, lo, pings, ICE_WAIT);
	coretest_info("the session of %s, whose answer never came, failed %llu ms after its offer; %s sent %ld pings meanwhile", hi->Name, failed, lo->Name, pings);
	coretest_check(failed >= PEER_ICE_ANSWER_TIMEOUT && failed < PEER_ICE_ANSWER_TIMEOUT + ICE_ANSWER_LATE, "The session whose answer never came failed about 40 s after its offer (PEER_ICE_ANSWER_TIMEOUT), and not before");
	coretest_check(pings != 0 && off_relay == 0 && all && lo->Received == pings && hi->ReceivedDirect == 0, "The pair stayed on the relay meanwhile, and every ping had its pong through R");

	// The session of the lower end fails too: the higher end took none of its checks without the answer
	ULONGLONG end = GetTickCount64() + ICE_WAIT;
	while (ice_path(lo, hi, &ps_lo) == PEER_PATH_RELAY && ps_lo.Ice != PEER_ICE_FAILED && GetTickCount64() < end)
		Sleep(100);
	coretest_check(ps_lo.Path == PEER_PATH_RELAY && ps_lo.Ice == PEER_ICE_FAILED, "The session of the lower end failed too: the higher end took none of its checks without the answer");

	// ICE runs again for the pair: the lower end offers again, as its agent does NODE_AGENT_ICE_RETRY ms after its session
	// failed, and the higher end takes the offer, as its failed session waits for no answer, and answers it
	r = ice_signal(lo, hi, PEER_SIGNAL_OFFER, &offer);
	coretest_check(r == PEER_OK && offer.IceUfrag[0] != 0 && strcmp(offer.IceUfrag, offer_lo.IceUfrag) != 0, "The lower end offers again, with the credentials of a new session");
	r = ice_signal(hi, lo, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(r == PEER_OK && answer.IceUfrag[0] != 0 && strcmp(answer.IceUfrag, offer_hi.IceUfrag) != 0, "The higher end takes that offer, as its session that failed waits for no answer any more, and answers it with the credentials of a new session");

	ULONGLONG t1 = GetTickCount64();
	bool up = ice_wait_direct(lo, hi, &ps_lo, &ps_hi, ICE_UP_WAIT);
	coretest_info("both ends were on the direct path %llu ms after the new offer", GetTickCount64() - t1);
	coretest_check(up, "ICE ran again for the pair: the new sessions validated and nominated the direct path, and both ends moved to it");

	LONG received = lo->Received;
	LONG direct = lo->ReceivedDirect;
	bool ping = ice_send(lo, hi, "ping direct");
	ice_wait_received(&w, lo, received + 1, ICE_WAIT);
	coretest_check(ping && lo->Received == received + 1 && lo->ReceivedDirect == direct + 1, "A ping and its pong go on the direct path");

	PeerGetStats(lo->Agent, &st_lo);
	PeerGetStats(hi->Agent, &st_hi);
	coretest_check(st_lo.Upgrades == 1 && st_hi.Upgrades == 1 && st_lo.Fallbacks == 0 && st_hi.Fallbacks == 0, "Each end counts one Upgrade, of its new session, and no Fallback");

	ice_world_stop(&w);
}

// A STUN message of type (RFC 8489 section 5) with the transaction id, into buf of 256 bytes: a USERNAME of user when it is
// not NULL, and a MESSAGE-INTEGRITY with integrity, whose value is no HMAC, so the session that takes the message drops it
// once it checks it. Returns its size.
static UINT ice_stun(UCHAR *buf, USHORT type, const UCHAR *id, const char *user, bool integrity) {
	UINT len = 20;

	if (user != NULL) {
		UINT n = (UINT)strlen(user);

		buf[len] = 0x00;
		buf[len + 1] = 0x06;
		buf[len + 2] = (UCHAR)(n >> 8);
		buf[len + 3] = (UCHAR)n;
		CopyMemory(buf + len + 4, user, n);
		len += 4 + n;
		while (len % 4 != 0)
			buf[len++] = 0;
	}

	if (integrity) {
		buf[len] = 0x00;
		buf[len + 1] = 0x08;
		buf[len + 2] = 0x00;
		buf[len + 3] = 20;
		ZeroMemory(buf + len + 4, 20);
		len += 24;
	}

	buf[0] = (UCHAR)(type >> 8);
	buf[1] = (UCHAR)type;
	buf[2] = (UCHAR)((len - 20) >> 8);
	buf[3] = (UCHAR)(len - 20);
	buf[4] = 0x21;
	buf[5] = 0x12;
	buf[6] = 0xA4;
	buf[7] = 0x42;
	CopyMemory(buf + 8, id, ICE_ID_SIZE);

	return len;
}

// One round of iceinput: five STUN messages from a stranger to B, of which the first two name B's session with A, whose
// username fragment and A's are user: a check of that session and an answer to its last check; then a check that names no
// session, an answer to no check, and a message whose USERNAME runs past its end, which libjuice cannot read. Whether B
// read each once, its session took the first two and B dropped the other three. StunMessages counts the reads that
// juice_peer_read makes, not the messages that PeerIceInput takes, so a message that B read again, as once for each of
// its sessions, would count more than once here (CORE-S5-6-R2, #557).
static bool ice_input_round(ICE_WORLD *w, const char *user, UINT sessions) {
	static const char *what[] = {"a check that names its session with A", "an answer to the last check of that session", "a check that names no session",
	                             "an answer to no check", "a message that does not read"};
	static const UCHAR some[ICE_ID_SIZE] = {'r', 'a', 'n', 'z', ' ', 'c', 'h', 'e', 'c', 'k', ' ', '1'};
	static const UCHAR none[ICE_ID_SIZE] = {'r', 'a', 'n', 'z', ' ', 'n', 'o', ' ', 'o', 'n', 'e', '2'};
	UCHAR msg[5][256];
	UINT size[5];
	UCHAR last[ICE_ID_SIZE];
	PEER_STATS before, after;
	PEER_ADDR stranger;
	bool ok = true;

	AcquireSRWLockShared(&w->CheckLock);
	CopyMemory(last, w->CheckId, ICE_ID_SIZE);
	ReleaseSRWLockShared(&w->CheckLock);

	size[0] = ice_stun(msg[0], 0x0001, some, user, true);
	size[1] = ice_stun(msg[1], 0x0101, last, NULL, false);
	size[2] = ice_stun(msg[2], 0x0001, some, "zzzzzzzz:RanzPeer", true);
	size[3] = ice_stun(msg[3], 0x0101, none, NULL, false);
	size[4] = ice_stun(msg[4], 0x0001, some, "x", false);
	msg[4][23] = 12;

	PeerAddrSetV4(&stranger, 198, 51, 100, 77, 4000);
	for (UINT k = 0; k < 5; k++) {
		PeerGetStats(w->B.Agent, &before);
		PeerInput(w->B.Agent, &stranger, msg[k], size[k]);
		PeerGetStats(w->B.Agent, &after);

		UINT64 read = after.StunMessages - before.StunMessages;
		UINT64 dropped = after.Drops[PEER_DROP_ICE] - before.Drops[PEER_DROP_ICE];
		coretest_info("with %u ICE sessions B read %s %llu time(s), and %s", sessions, what[k], read, dropped == 0 ? "the session took it" : "dropped it");
		ok = ok && read == 1 && dropped == (k < 2 ? 0 : 1);
	}

	return ok;
}

void iceinput_test() {
	ICE_WORLD w;
	PEER_SIGNAL offer, answer;
	PEER_INFO peers[2 + ICE_MANY];
	PEER_KEY many[ICE_MANY];
	PEER_STATS st;
	UCHAR env[PEER_MAX_ENVELOPE];
	char user[2 * PEER_ICE_UFRAG_SIZE];
	UINT offered = 0;

	ZeroMemory(many, sizeof(many));
	bool started = ice_world_start(&w, ICE_WORLD_CONES);
	coretest_check(started, "The network starts: R on the public side, A and B each behind a port-restricted cone NAT of its own, ICE on the socket of each");
	if (started == false) {
		ice_world_stop(&w);
		return;
	}

	// No check and no answer crosses the network, so the only STUN messages that B reads are the ones of the test
	InterlockedExchange(&w.BlockIce, 1);

	// A offers B its session, and B takes it: B's session with A has A's credentials, and its checks go out
	UINT r = ice_signal(&w.A, &w.B, PEER_SIGNAL_OFFER, &offer);
	UINT r2 = ice_signal(&w.B, &w.A, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(r == PEER_OK && r2 == PEER_OK && offer.IceUfrag[0] != 0 && answer.IceUfrag[0] != 0, "A offers B its ICE session, B takes the offer as the controlled end and answers it with the credentials of its own");
	snprintf(user, sizeof(user), "%s:%s", answer.IceUfrag, offer.IceUfrag);

	ULONGLONG end = GetTickCount64() + ICE_WAIT;
	bool checked = false;
	while (checked == false && GetTickCount64() < end) {
		AcquireSRWLockShared(&w.CheckLock);
		checked = w.HasCheck;
		ReleaseSRWLockShared(&w.CheckLock);
		if (checked == false)
			Sleep(20);
	}
	coretest_check(checked, "B's session checks the candidate pairs with A, and the tap keeps the transaction id of its last check");

	PeerGetStats(w.B.Agent, &st);
	UINT64 reads = st.StunMessages;
	bool one = (st.NumIce == 1 && ice_input_round(&w, user, st.NumIce));
	coretest_check(one, "With one ICE session, B reads each of five STUN messages once: the check and the answer that name its session go to it, and the three others are dropped");

	// ICE_MANY more peers, each with a session of B's offer, which waits for its answer
	ice_peer(&peers[0], "a", w.A.Key.Public, 10);
	ice_peer(&peers[1], "r", w.R.Key.Public, 10);
	for (UINT i = 0; i < ICE_MANY; i++) {
		char name[16];

		snprintf(name, sizeof(name), "p%u", i);
		coretest_fixed_key(&many[i], (UCHAR)(65 + i));
		ice_peer(&peers[2 + i], name, many[i].Public, 10);
	}
	PeerSetPeers(w.B.Agent, peers, 2 + ICE_MANY);
	for (UINT i = 0; i < ICE_MANY; i++)
		if (PeerSealSignal(w.B.Agent, many[i].Public, PEER_SIGNAL_OFFER, env, sizeof(env)) != 0)
			offered++;

	PeerGetStats(w.B.Agent, &st);
	coretest_info("B holds %u ICE sessions", st.NumIce);
	bool all = (offered == ICE_MANY && st.NumIce == 1 + ICE_MANY && ice_input_round(&w, user, st.NumIce));
	coretest_check(all, "With 49 ICE sessions, B still reads each of the five STUN messages once: the check and the answer that name its session with A go to it, and the three others are dropped");

	// No STUN message but the ones of the test reaches B, so the reads of B in all are the five of each round: nothing read
	// a message again once PeerInput had returned, on the thread of a session or later
	NatSimWaitIdle(w.Sim, ICE_WAIT);
	PeerGetStats(w.B.Agent, &st);
	coretest_info("B made %llu reads of STUN messages in the two rounds", st.StunMessages - reads);
	coretest_check(st.StunMessages - reads == 2 * 5, "B made one read for each of the ten STUN messages of the two rounds, and none after them");

	ice_world_stop(&w);

	for (UINT i = 0; i < ICE_MANY; i++)
		PeerKeyClose(&many[i]);
}
