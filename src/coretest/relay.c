// relay.c
// Named tests of the relay role and the relay-first bring-up of a peer pair (src/Core/Peer.c, CORE-S5-2 #78), on
// the NAT simulator of natsim.c:
// relay: two nodes, each behind a symmetric NAT of its own, come up through a relay on the public side after one
//   signal each way through the control plane, and their traffic flows at once. The direct path that ICE would try
//   first does not pass the NATs, so the pair stays on the relay.
// relaypolicy: forged, altered, replayed and redirected signals and binds are refused. The relay forwards only from
//   a node bound to it to another one in a VRF of both, at its rate, and follows a change of its peers at once. A
//   direct and a relayed datagram go through the one ingress and the one policy check. A relay that restarts gets
//   its bindings back from the keepalive of its nodes.
// The control plane is stood in for by the test, which hands each signal from one node to the other; the
// controller's conformance test carries the same envelopes through the controller (controller/internal/controller).

#include "coretest.h"

#include <string.h>

#define RELAY_WAIT 10000 // ms: a bounded wait for the network to carry everything sent

// One node of a test and what it received
typedef struct RELAY_NODE {
	const char *Name;             // Its name
	PEER_KEY Key;                 // Its static key
	PEER_ADDR Addr;               // Its address: private behind a NAT
	NATSIM_HOST *Host;            // Its host on the network
	PEER_AGENT *Agent;            // Its peer layer
	volatile LONG Received;       // Data datagrams delivered to it
	volatile LONG ReceivedRelay;  // ... of them through a relay
	volatile LONG Echo;           // Answer each "ping" with a "pong"
	char Last[64];                // The payload of the last one, as text
	UCHAR LastSrc[PEER_KEY_SIZE]; // ... its source
	UINT LastPath;                // ... and its path
} RELAY_NODE;

// The network of a test: the relay R and the nodes A and B, each behind a symmetric NAT of its own, all in VRF 10;
// C on the public side in VRF 20; D, a node that no one knows; E, a node of VRF 10 that never binds; G and H, a pair
// on the public side in VRF 10; and the relay R2 with its nodes X and Y in VRF 30
typedef struct RELAY_WORLD {
	NATSIM *Sim;      // The network
	NATSIM_NAT *NatA; // A's NAT
	NATSIM_NAT *NatB; // B's NAT
	RELAY_NODE R, A, B, C, D, G, H, R2, X, Y;
	PEER_KEY E;    // The key of E, which has no host
	UINT Messages; // Signals carried through the stand-in of the control plane
} RELAY_WORLD;

// The receive procedure of every node: record the datagram; with Echo, answer "ping ..." with "pong ..."
static void relay_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	RELAY_NODE *n = (RELAY_NODE *)param;
	UINT len = (size < sizeof(n->Last) - 1 ? size : (UINT)sizeof(n->Last) - 1);

	CopyMemory(n->Last, data, len);
	n->Last[len] = 0;
	CopyMemory(n->LastSrc, src, PEER_KEY_SIZE);
	n->LastPath = path;

	if (path == PEER_PATH_RELAY)
		InterlockedIncrement(&n->ReceivedRelay);
	InterlockedIncrement(&n->Received);

	if (InterlockedCompareExchange(&n->Echo, 0, 0) != 0 && size >= 4 && size < sizeof(n->Last) && memcmp(data, "ping", 4) == 0) {
		char pong[64];

		CopyMemory(pong, data, size);
		CopyMemory(pong, "pong", 4);
		PeerSend(a, src, pong, size);
	}
}

// A node of the world: its key from the fixed scalar first, its host behind nat (NULL: public) at addr, its peer
// layer with the configuration c (NULL: the defaults)
static bool relay_node(RELAY_WORLD *w, RELAY_NODE *n, const char *name, UCHAR first, NATSIM_NAT *nat, const PEER_ADDR *addr, PEER_CONFIG *c) {
	n->Name = name;
	n->Addr = *addr;
	coretest_fixed_key(&n->Key, first);
	n->Host = NatSimAddHost(w->Sim, nat, addr);
	if (n->Host == NULL)
		return false;

	n->Agent = PeerNew(&n->Key, c, NatSimSend, n->Host, relay_recv, n);
	NatSimAttach(n->Host, n->Agent);

	return n->Agent != NULL;
}

// A peer of the peer table: a node with the key key in one VRF
static void relay_peer(PEER_INFO *p, const char *name, const UCHAR *key, UINT vrf) {
	ZeroMemory(p, sizeof(PEER_INFO));
	strcpy_s(p->Name, sizeof(p->Name), name);
	CopyMemory(p->Key, key, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = vrf;
}

// A relay of the relays of a node
static void relay_info(PEER_RELAY_INFO *r, RELAY_NODE *relay) {
	ZeroMemory(r, sizeof(PEER_RELAY_INFO));
	strcpy_s(r->Name, sizeof(r->Name), relay->Name);
	CopyMemory(r->Key, relay->Key.Public, PEER_KEY_SIZE);
	r->Addr = relay->Addr;
}

// The peer table of R: A, B and E in VRF 10, C in VRF 20, G and H in VRF 10; with b_vrf for the VRF of B
static void relay_set_r_peers(RELAY_WORLD *w, UINT b_vrf) {
	PEER_INFO p[6];

	relay_peer(&p[0], "a", w->A.Key.Public, 10);
	relay_peer(&p[1], "b", w->B.Key.Public, b_vrf);
	relay_peer(&p[2], "c", w->C.Key.Public, 20);
	relay_peer(&p[3], "e", w->E.Public, 10);
	relay_peer(&p[4], "g", w->G.Key.Public, 10);
	relay_peer(&p[5], "h", w->H.Key.Public, 10);
	PeerSetPeers(w->R.Agent, p, 6);
}

// Build the world, set the peers and the relays of every node, and let the binds go through. relay_config is the
// configuration of R; X and Y renew their binds every 100 ms.
static bool relay_world_start(RELAY_WORLD *w, PEER_CONFIG *relay_config) {
	PEER_CONFIG rc, nc;
	PEER_ADDR addr;
	PEER_INFO p[4];
	PEER_RELAY_INFO ri;
	bool ok = true;

	ZeroMemory(w, sizeof(RELAY_WORLD));
	w->Sim = NatSimNew();
	if (w->Sim == NULL)
		return false;

	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	w->NatB = NatSimAddNat(w->Sim, 203, 0, 113, 20, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);

	if (relay_config != NULL)
		rc = *relay_config;
	else
		PeerDefaultConfig(&rc);
	rc.Relay = true;

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = relay_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 10, 0, 0, 2, 5000);
	ok = relay_node(w, &w->A, "a", 1, w->NatA, &addr, NULL) && ok;
	ok = relay_node(w, &w->B, "b", 33, w->NatB, &addr, NULL) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 3, 4000);
	ok = relay_node(w, &w->C, "c", 65, NULL, &addr, NULL) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 4, 4000);
	ok = relay_node(w, &w->D, "d", 161, NULL, &addr, NULL) && ok;
	coretest_fixed_key(&w->E, 193);
	PeerAddrSetV4(&addr, 198, 51, 100, 7, 5000);
	ok = relay_node(w, &w->G, "g", 225, NULL, &addr, NULL) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 8, 5000);
	ok = relay_node(w, &w->H, "h", 17, NULL, &addr, NULL) && ok;

	PeerDefaultConfig(&nc);
	nc.Relay = true;
	PeerAddrSetV4(&addr, 198, 51, 100, 9, 3478);
	ok = relay_node(w, &w->R2, "r2", 49, NULL, &addr, &nc) && ok;
	PeerDefaultConfig(&nc);
	nc.BindInterval = 100;
	PeerAddrSetV4(&addr, 198, 51, 100, 10, 5000);
	ok = relay_node(w, &w->X, "x", 81, NULL, &addr, &nc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 11, 5000);
	ok = relay_node(w, &w->Y, "y", 145, NULL, &addr, &nc) && ok;

	if (ok == false)
		return false;

	// The Peer objects of each node
	relay_set_r_peers(w, 10);

	relay_peer(&p[0], "b", w->B.Key.Public, 10);
	relay_peer(&p[1], "r", w->R.Key.Public, 10);
	relay_peer(&p[2], "e", w->E.Public, 10);
	PeerSetPeers(w->A.Agent, p, 3);

	relay_peer(&p[0], "a", w->A.Key.Public, 10);
	relay_peer(&p[1], "r", w->R.Key.Public, 10);
	PeerSetPeers(w->B.Agent, p, 2);

	relay_peer(&p[0], "r", w->R.Key.Public, 20);
	PeerSetPeers(w->C.Agent, p, 1);

	relay_peer(&p[0], "h", w->H.Key.Public, 10);
	relay_peer(&p[1], "r", w->R.Key.Public, 10);
	PeerSetPeers(w->G.Agent, p, 2);

	relay_peer(&p[0], "g", w->G.Key.Public, 10);
	relay_peer(&p[1], "r", w->R.Key.Public, 10);
	PeerSetPeers(w->H.Agent, p, 2);

	relay_peer(&p[0], "x", w->X.Key.Public, 30);
	relay_peer(&p[1], "y", w->Y.Key.Public, 30);
	PeerSetPeers(w->R2.Agent, p, 2);

	relay_peer(&p[0], "y", w->Y.Key.Public, 30);
	relay_peer(&p[1], "r2", w->R2.Key.Public, 30);
	PeerSetPeers(w->X.Agent, p, 2);

	relay_peer(&p[0], "x", w->X.Key.Public, 30);
	relay_peer(&p[1], "r2", w->R2.Key.Public, 30);
	PeerSetPeers(w->Y.Agent, p, 2);

	// The host candidates, then the Relay objects: every node binds to its home relay
	RELAY_NODE *nodes[] = {&w->A, &w->B, &w->C, &w->D, &w->G, &w->H};
	relay_info(&ri, &w->R);
	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		PeerSetHostCandidates(nodes[i]->Agent, &nodes[i]->Addr, 1);
		PeerSetRelays(nodes[i]->Agent, &ri, 1);
	}

	relay_info(&ri, &w->R2);
	PeerSetRelays(w->X.Agent, &ri, 1);
	PeerSetRelays(w->Y.Agent, &ri, 1);

	return NatSimWaitIdle(w->Sim, RELAY_WAIT);
}

static void relay_node_free(RELAY_NODE *n) {
	PeerFree(n->Agent);
	n->Agent = NULL;
	PeerKeyClose(&n->Key);
}

// Stop the network first, so that no datagram reaches a freed peer layer
static void relay_world_stop(RELAY_WORLD *w) {
	NatSimFree(w->Sim);
	w->Sim = NULL;

	RELAY_NODE *nodes[] = {&w->R, &w->A, &w->B, &w->C, &w->D, &w->G, &w->H, &w->R2, &w->X, &w->Y};
	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++)
		relay_node_free(nodes[i]);
	PeerKeyClose(&w->E);
}

// The stand-in of the control plane: from seals a signal of type for to, and to takes it. Returns what
// PeerOpenSignal returned, PEER_DROP_MALFORMED when nothing was sealed.
static UINT relay_signal(RELAY_WORLD *w, RELAY_NODE *from, RELAY_NODE *to, UINT type, PEER_SIGNAL *sig) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(from->Agent, to->Key.Public, type, env, sizeof(env));
	if (size == 0)
		return PEER_DROP_MALFORMED;

	w->Messages++;

	return PeerOpenSignal(to->Agent, env, size, sig);
}

// A data datagram from src to dst with text as its payload, built by hand as a forger would; returns its size
static UINT relay_datagram(UCHAR *buf, const UCHAR *src, const UCHAR *dst, const char *text) {
	UINT len = (UINT)strlen(text);

	buf[0] = PEER_MSG_DATA;
	CopyMemory(buf + 1, src, PEER_KEY_SIZE);
	CopyMemory(buf + 1 + PEER_KEY_SIZE, dst, PEER_KEY_SIZE);
	CopyMemory(buf + PEER_DATA_HEADER_SIZE, text, len);

	return PEER_DATA_HEADER_SIZE + len;
}

// A drop counter of a node
static UINT64 relay_drops(RELAY_NODE *n, UINT reason) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Drops[reason];
}

static UINT64 relay_forwarded(RELAY_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Forwarded;
}

// The candidate of type in a signal, false when it has none
static bool relay_candidate(PEER_SIGNAL *s, UINT type, PEER_ADDR *addr) {
	for (UINT i = 0; i < s->NumCandidates; i++) {
		if (s->Candidates[i].Type == type) {
			*addr = s->Candidates[i].Addr;
			return true;
		}
	}

	return false;
}

// Bring the pair from and to up: an offer, and the answer
static bool relay_pair(RELAY_WORLD *w, RELAY_NODE *from, RELAY_NODE *to) {
	PEER_SIGNAL sig;

	bool ok = relay_signal(w, from, to, PEER_SIGNAL_OFFER, &sig) == PEER_OK && relay_signal(w, to, from, PEER_SIGNAL_ANSWER, &sig) == PEER_OK;

	return NatSimWaitIdle(w->Sim, RELAY_WAIT) && ok;
}

void relay_test() {
	RELAY_WORLD w;
	PEER_STATS st, st_a, st_b;
	PEER_SIGNAL offer, answer;
	PEER_STATUS ps_a, ps_b;
	PEER_ADDR mapped, srflx, host;
	UCHAR dgram[PEER_MAX_DATAGRAM];
	char text[64];

	bool started = relay_world_start(&w, NULL);
	coretest_check(started, "The harness network starts: the relay R on the public side, A and B each behind a symmetric NAT of its own");
	if (started == false) {
		relay_world_stop(&w);
		return;
	}

	// The binds
	PeerGetStats(w.R.Agent, &st);
	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st.Binds == 5 && st.NumBindings == 5 && st.Drops[PEER_DROP_POLICY] == 1, "R took one bind from each of its five nodes, A and B through their NATs, and refused D, which is no node of its VRFs");
	coretest_check(st_a.NumBound == 1 && st_b.NumBound == 1, "A and B are bound to R: it answered each bind");
	coretest_check(NatSimMapped(w.NatA, &w.A.Addr, &mapped), "NAT A mapped A's address for R");
	PeerAddrToStr(text, sizeof(text), &mapped);
	coretest_info("A is 10.0.0.2:5000 behind NAT A, which maps it to %s towards R", text);

	// One signal each way through the control plane
	UINT r = relay_signal(&w, &w.A, &w.B, PEER_SIGNAL_OFFER, &offer);
	coretest_check(r == PEER_OK && offer.Type == PEER_SIGNAL_OFFER && memcmp(offer.RelayKey, w.R.Key.Public, PEER_KEY_SIZE) == 0 && offer.NumCandidates == 2, "B takes A's offer: the relay assignment R, a host and a server reflexive candidate");
	coretest_check(relay_candidate(&offer, PEER_CANDIDATE_SRFLX, &srflx) && PeerAddrEqual(&srflx, &mapped), "A's server reflexive candidate is the address that NAT A gave it towards R, which R reported in its bound");

	bool sent = PeerSend(w.B.Agent, w.A.Key.Public, "early", 5);
	NatSimWaitIdle(w.Sim, RELAY_WAIT);
	coretest_check(sent && w.A.Received == 1 && w.A.ReceivedRelay == 1 && strcmp(w.A.Last, "early") == 0 && memcmp(w.A.LastSrc, w.B.Key.Public, PEER_KEY_SIZE) == 0, "Right after taking the offer, before A has its answer, B's first datagram reaches A through R");

	r = relay_signal(&w, &w.B, &w.A, PEER_SIGNAL_ANSWER, &answer);
	coretest_check(r == PEER_OK && answer.Type == PEER_SIGNAL_ANSWER && memcmp(answer.RelayKey, w.R.Key.Public, PEER_KEY_SIZE) == 0, "A takes B's answer, which names R");
	coretest_check(w.Messages == 2, "The pair came up after one signal each way through the control plane: one round trip");

	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps_a);
	PeerGetStatus(w.B.Agent, w.A.Key.Public, &ps_b);
	coretest_check(ps_a.Path == PEER_PATH_RELAY && ps_b.Path == PEER_PATH_RELAY && memcmp(ps_a.RelayKey, w.R.Key.Public, PEER_KEY_SIZE) == 0, "Each end reaches the other through R");

	// A ping, which B answers from its receive procedure
	InterlockedExchange(&w.B.Echo, 1);
	PeerGetStats(w.A.Agent, &st_a);
	UINT64 sent_before = st_a.Sent;
	UINT64 forwarded_before = relay_forwarded(&w.R);
	ULONGLONG t0 = GetTickCount64();

	sent = PeerSend(w.A.Agent, w.B.Key.Public, "ping 1", 6);
	bool idle = NatSimWaitIdle(w.Sim, RELAY_WAIT);
	ULONGLONG t1 = GetTickCount64();

	PeerGetStats(w.A.Agent, &st_a);
	coretest_check(sent && idle && w.B.Received == 1 && w.B.ReceivedRelay == 1 && strcmp(w.B.Last, "ping 1") == 0 && memcmp(w.B.LastSrc, w.A.Key.Public, PEER_KEY_SIZE) == 0, "A's first datagram to B is delivered at once, through R");
	coretest_check(w.A.Received == 2 && strcmp(w.A.Last, "pong 1") == 0 && w.A.LastPath == PEER_PATH_RELAY, "B's answer reaches A: one round trip, with no handshake between A and B before it");
	coretest_check(st_a.Sent - sent_before == 1 && relay_forwarded(&w.R) - forwarded_before == 2, "A sent one datagram for that round trip, and R forwarded the two of it");
	coretest_info("the ping and its pong took %llu ms on the harness network", t1 - t0);

	// The direct path that ICE would try first
	UINT filtered = NatSimFiltered(w.NatB);
	UINT unroutable = NatSimUnroutable(w.Sim);
	coretest_check(relay_candidate(&answer, PEER_CANDIDATE_SRFLX, &srflx) && relay_candidate(&answer, PEER_CANDIDATE_HOST, &host), "B's answer holds its host and its server reflexive candidate");

	UINT size = relay_datagram(dgram, w.A.Key.Public, w.B.Key.Public, "direct");
	NatSimSend(w.A.Host, &srflx, dgram, size);
	NatSimSend(w.A.Host, &host, dgram, size);
	NatSimWaitIdle(w.Sim, RELAY_WAIT);
	coretest_check(NatSimFiltered(w.NatB) == filtered + 1 && w.B.Received == 1, "A datagram from A straight to B's server reflexive candidate is dropped by NAT B: its mapping lets in R only");
	coretest_check(NatSimUnroutable(w.Sim) == unroutable + 1 && w.B.Received == 1, "B's host candidate is a private address of another site, which A cannot reach");

	// The pair stays on the relay
	sent = PeerSend(w.A.Agent, w.B.Key.Public, "ping 2", 6);
	NatSimWaitIdle(w.Sim, RELAY_WAIT);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps_a);
	coretest_check(sent && w.B.Received == 2 && w.A.Received == 3 && strcmp(w.A.Last, "pong 2") == 0 && ps_a.Path == PEER_PATH_RELAY, "The pair stays on the relay, and its traffic goes on flowing");

	relay_world_stop(&w);
}

// Signals: altered, replayed, redirected, forged, from a stranger, and with a relay that the control plane did not
// assign
static void relay_policy_signals(RELAY_WORLD *w) {
	UCHAR env[PEER_MAX_ENVELOPE];
	UCHAR forged_env[PEER_MAX_ENVELOPE];
	UCHAR payload[PEER_MAX_ENVELOPE];
	PEER_STATUS before, after;
	PEER_SIGNAL s;
	PEER_KEY forged;
	UINT taken = 0;

	UINT size = PeerSealSignal(w->A.Agent, w->B.Key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));
	PeerGetStatus(w->B.Agent, w->A.Key.Public, &before);

	for (UINT i = 0; i < size; i++) {
		for (UINT bit = 0; bit < 8; bit++) {
			env[i] ^= (UCHAR)(1 << bit);
			if (PeerOpenSignal(w->B.Agent, env, size, NULL) == PEER_OK)
				taken++;
			env[i] ^= (UCHAR)(1 << bit);
		}
	}
	PeerGetStatus(w->B.Agent, w->A.Key.Public, &after);
	coretest_check(size != 0 && taken == 0 && after.Sequence == before.Sequence, "B refuses A's signal with any one of its bits flipped, and keeps the last signal it took");

	coretest_check(PeerOpenSignal(w->B.Agent, env, size, NULL) == PEER_OK, "B takes the signal as A sealed it");
	coretest_check(PeerOpenSignal(w->B.Agent, env, size, NULL) == PEER_DROP_REPLAY, "... and refuses it the second time: a replay");
	coretest_check(PeerOpenSignal(w->C.Agent, env, size, NULL) == PEER_DROP_FORGED, "C cannot open A's signal for B: a signal cannot be redirected");

	// A signal that C seals with A's public key in the envelope
	PeerGetStatus(w->B.Agent, w->A.Key.Public, &before);
	ZeroMemory(&s, sizeof(s));
	s.Type = PEER_SIGNAL_OFFER;
	s.Sequence = before.Sequence + 1;
	CopyMemory(s.RelayKey, w->R.Key.Public, PEER_KEY_SIZE);
	s.Relay = w->R.Addr;
	UINT payload_size = PeerSignalEncode(&s, payload, sizeof(payload));

	forged = w->C.Key;
	CopyMemory(forged.Public, w->A.Key.Public, PEER_KEY_SIZE);
	UINT forged_size = PeerEnvelopeSeal(&forged, w->B.Key.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, forged_env, sizeof(forged_env));
	coretest_check(PeerOpenSignal(w->B.Agent, forged_env, forged_size, NULL) == PEER_DROP_FORGED, "A signal that C forged in A's name is refused: C does not hold A's key");

	forged_size = PeerEnvelopeSeal(&w->C.Key, w->B.Key.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, forged_env, sizeof(forged_env));
	coretest_check(PeerOpenSignal(w->B.Agent, forged_env, forged_size, NULL) == PEER_DROP_POLICY, "A signal that C sealed with its own key is refused: C is no peer of B");

	// Relay assignments that A seals with its own key but that the control plane did not make
	PEER_KEY stranger;
	coretest_fixed_key(&stranger, 209);
	CopyMemory(s.RelayKey, stranger.Public, PEER_KEY_SIZE);
	payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	forged_size = PeerEnvelopeSeal(&w->A.Key, w->B.Key.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, forged_env, sizeof(forged_env));
	coretest_check(PeerOpenSignal(w->B.Agent, forged_env, forged_size, NULL) == PEER_DROP_RELAY, "A signal that names a relay the control plane did not assign is refused");

	CopyMemory(s.RelayKey, w->R.Key.Public, PEER_KEY_SIZE);
	PeerAddrSetV4(&s.Relay, 198, 51, 100, 66, 3478);
	payload_size = PeerSignalEncode(&s, payload, sizeof(payload));
	forged_size = PeerEnvelopeSeal(&w->A.Key, w->B.Key.Public, PEER_MSG_SIGNAL, NULL, payload, payload_size, forged_env, sizeof(forged_env));
	coretest_check(PeerOpenSignal(w->B.Agent, forged_env, forged_size, NULL) == PEER_DROP_RELAY, "A signal that names R at another address is refused: the relay assignment cannot be redirected");

	PeerGetStatus(w->B.Agent, w->A.Key.Public, &after);
	coretest_check(after.Sequence == before.Sequence && memcmp(after.RelayKey, w->R.Key.Public, PEER_KEY_SIZE) == 0, "None of them changed what B holds of A");

	PeerKeyClose(&stranger);
	SecureZeroMemory(&forged, sizeof(forged));
}

// Binds and bounds: forged, replayed, from a stranger
static void relay_policy_binds(RELAY_WORLD *w) {
	UCHAR payload[16];
	UCHAR bound[27];
	UCHAR env[PEER_MAX_ENVELOPE];
	PEER_KEY forged;
	PEER_STATS st;

	// A bind that C forges in A's name, from C's address
	forged = w->C.Key;
	CopyMemory(forged.Public, w->A.Key.Public, PEER_KEY_SIZE);
	payload[0] = 1;
	for (UINT i = 1; i < 9; i++)
		payload[i] = 0xFF;
	UINT size = PeerEnvelopeSeal(&forged, w->R.Key.Public, PEER_MSG_BIND, NULL, payload, 9, env, sizeof(env));
	UINT64 forged_before = relay_drops(&w->R, PEER_DROP_FORGED);
	NatSimSend(w->C.Host, &w->R.Addr, env, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->R, PEER_DROP_FORGED) == forged_before + 1, "R refuses a bind that C forged in A's name");

	// A's own bind of an old sequence, replayed from C's address
	for (UINT i = 1; i < 9; i++)
		payload[i] = 0;
	payload[8] = 1;
	size = PeerEnvelopeSeal(&w->A.Key, w->R.Key.Public, PEER_MSG_BIND, NULL, payload, 9, env, sizeof(env));
	UINT64 replay_before = relay_drops(&w->R, PEER_DROP_REPLAY);
	NatSimSend(w->C.Host, &w->R.Addr, env, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->R, PEER_DROP_REPLAY) == replay_before + 1, "R refuses a bind of A that is older than A's binding: a replay from another address");

	LONG received = w->B.Received;
	PeerSend(w->A.Agent, w->B.Key.Public, "after binds", 11);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(w->B.Received == received + 1 && strcmp(w->B.Last, "after binds") == 0, "A's binding stays where A bound it: its traffic still reaches B");

	PeerGetStats(w->D.Agent, &st);
	coretest_check(st.NumBound == 0, "D, which is no node of R's VRFs, is not bound to R");

	// Bounds that come to A as from R's address, as an attacker on the path would send them: version 1, a
	// sequence, an address
	ZeroMemory(bound, sizeof(bound));
	bound[0] = 1;
	size = PeerEnvelopeSeal(&w->C.Key, w->A.Key.Public, PEER_MSG_BOUND, NULL, bound, sizeof(bound), env, sizeof(env));
	UINT64 relay_before = relay_drops(&w->A, PEER_DROP_RELAY);
	PeerInput(w->A.Agent, &w->R.Addr, env, size);
	coretest_check(relay_drops(&w->A, PEER_DROP_RELAY) == relay_before + 1, "A refuses a bound from a node that is not its relay");

	forged = w->C.Key;
	CopyMemory(forged.Public, w->R.Key.Public, PEER_KEY_SIZE);
	size = PeerEnvelopeSeal(&forged, w->A.Key.Public, PEER_MSG_BOUND, NULL, bound, sizeof(bound), env, sizeof(env));
	forged_before = relay_drops(&w->A, PEER_DROP_FORGED);
	PeerInput(w->A.Agent, &w->R.Addr, env, size);
	coretest_check(relay_drops(&w->A, PEER_DROP_FORGED) == forged_before + 1, "A refuses a bound forged in R's name");

	SecureZeroMemory(&forged, sizeof(forged));
}

// The policy of the relay: VRFs, the source, the destination, a change of its peers, its rate
static void relay_policy_forwarding(RELAY_WORLD *w) {
	UCHAR dgram[PEER_MAX_DATAGRAM];
	PEER_STATS st, st2;

	coretest_check(PeerSend(w->A.Agent, w->C.Key.Public, "x", 1) == false && PeerSend(w->C.Agent, w->A.Key.Public, "x", 1) == false, "A and C, which share no VRF, are no peers of each other and have no path");

	UINT64 policy_before = relay_drops(&w->R, PEER_DROP_POLICY);
	LONG c_received = w->C.Received;
	LONG a_received = w->A.Received;
	UINT size = relay_datagram(dgram, w->A.Key.Public, w->C.Key.Public, "a to c");
	NatSimSend(w->A.Host, &w->R.Addr, dgram, size);
	size = relay_datagram(dgram, w->C.Key.Public, w->A.Key.Public, "c to a");
	NatSimSend(w->C.Host, &w->R.Addr, dgram, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->R, PEER_DROP_POLICY) == policy_before + 2 && w->C.Received == c_received && w->A.Received == a_received, "R forwards nothing between A in VRF 10 and C in VRF 20, either way, though both are bound to it");

	UINT64 source_before = relay_drops(&w->R, PEER_DROP_SOURCE);
	LONG b_received = w->B.Received;
	size = relay_datagram(dgram, w->D.Key.Public, w->B.Key.Public, "d to b");
	NatSimSend(w->D.Host, &w->R.Addr, dgram, size);
	size = relay_datagram(dgram, w->A.Key.Public, w->B.Key.Public, "c as a");
	NatSimSend(w->C.Host, &w->R.Addr, dgram, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->R, PEER_DROP_SOURCE) == source_before + 2 && w->B.Received == b_received, "R drops a datagram from D, which is not bound to it, and one that C sends in A's name from its own address");

	UINT64 not_bound_before = relay_drops(&w->R, PEER_DROP_NOT_BOUND);
	size = relay_datagram(dgram, w->A.Key.Public, w->E.Public, "a to e");
	NatSimSend(w->A.Host, &w->R.Addr, dgram, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->R, PEER_DROP_NOT_BOUND) == not_bound_before + 1, "R drops a datagram for E, a node of VRF 10 that is not bound to it");

	// The control plane moves B to VRF 20 at R, then back
	PeerGetStats(w->R.Agent, &st);
	relay_set_r_peers(w, 20);
	policy_before = relay_drops(&w->R, PEER_DROP_POLICY);
	bool sent = PeerSend(w->A.Agent, w->B.Key.Public, "moved", 5);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	PeerGetStats(w->R.Agent, &st2);
	coretest_check(sent && relay_drops(&w->R, PEER_DROP_POLICY) == policy_before + 1 && w->B.Received == b_received && st2.NumBindings == st.NumBindings, "Once the control plane puts B in another VRF, R refuses A's datagram to B at once, and keeps B's binding");

	relay_set_r_peers(w, 10);
	sent = PeerSend(w->A.Agent, w->B.Key.Public, "back", 4);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(sent && w->B.Received == b_received + 1 && strcmp(w->B.Last, "back") == 0, "Back in VRF 10, B gets A's datagrams again");

	// The rate of R for one source: RelayRate 100 per second, RelayBurst 20
	Sleep(300);
	UINT64 forwarded_before = relay_forwarded(&w->R);
	UINT64 rate_before = relay_drops(&w->R, PEER_DROP_RATE);
	b_received = w->B.Received;
	for (UINT i = 0; i < 400; i++)
		PeerSend(w->A.Agent, w->B.Key.Public, "flood", 5);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);

	UINT64 forwarded = relay_forwarded(&w->R) - forwarded_before;
	UINT64 limited = relay_drops(&w->R, PEER_DROP_RATE) - rate_before;
	coretest_info("of 400 datagrams that A sent at once, R forwarded %llu and limited %llu", forwarded, limited);
	coretest_check(forwarded + limited == 400 && forwarded >= 20 && limited != 0 && (UINT64)(w->B.Received - b_received) == forwarded, "R forwards a burst of 20 from one source and limits the rest of a flood; every datagram is forwarded or limited");
}

// A direct and a relayed datagram go through the one ingress and the one policy check
static void relay_policy_paths(RELAY_WORLD *w) {
	UCHAR dgram[PEER_MAX_DATAGRAM];
	PEER_STATUS ps;

	coretest_check(relay_pair(w, &w->G, &w->H), "G and H, on the public side, come up through R");
	bool sent = PeerSend(w->G.Agent, w->H.Key.Public, "relayed", 7);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(sent && w->H.Received == 1 && w->H.ReceivedRelay == 1 && w->H.LastPath == PEER_PATH_RELAY, "G's datagram reaches H through R");

	// As ICE does once it validated the direct path (CORE-S5-3)
	PeerSetDirect(w->G.Agent, w->H.Key.Public, &w->H.Addr);
	PeerSetDirect(w->H.Agent, w->G.Key.Public, &w->G.Addr);
	PeerGetStatus(w->G.Agent, w->H.Key.Public, &ps);
	UINT64 forwarded_before = relay_forwarded(&w->R);
	sent = PeerSend(w->G.Agent, w->H.Key.Public, "direct", 6);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(ps.Path == PEER_PATH_DIRECT && sent && w->H.Received == 2 && w->H.ReceivedRelay == 1 && w->H.LastPath == PEER_PATH_DIRECT && strcmp(w->H.Last, "direct") == 0 && relay_forwarded(&w->R) == forwarded_before, "On the direct path G's datagram reaches H without R, through the same receive procedure");

	// The same policy check on both paths: a relayed datagram from a source that is no peer of H, and a direct one
	// for a destination that is none
	UINT64 policy_before = relay_drops(&w->H, PEER_DROP_POLICY);
	UINT size = relay_datagram(dgram, w->A.Key.Public, w->H.Key.Public, "a to h");
	NatSimSend(w->A.Host, &w->R.Addr, dgram, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_forwarded(&w->R) == forwarded_before + 1 && relay_drops(&w->H, PEER_DROP_POLICY) == policy_before + 1 && w->H.Received == 2, "R forwards A's datagram to H, both in VRF 10, and H's ingress refuses it: A is no peer of H");

	size = relay_datagram(dgram, w->G.Key.Public, w->A.Key.Public, "g to a through h");
	NatSimSend(w->G.Host, &w->H.Addr, dgram, size);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(relay_drops(&w->H, PEER_DROP_POLICY) == policy_before + 2, "On the direct path the same check refuses G's datagram for A at H: A is no peer of H");

	PeerSetDirect(w->G.Agent, w->H.Key.Public, NULL);
	PeerGetStatus(w->G.Agent, w->H.Key.Public, &ps);
	sent = PeerSend(w->G.Agent, w->H.Key.Public, "relayed again", 13);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(ps.Path == PEER_PATH_RELAY && sent && w->H.Received == 3 && w->H.LastPath == PEER_PATH_RELAY, "Without the direct path G falls back to R");
}

// A relay holds no state that a restart loses: its nodes bind again on their keepalive
static void relay_policy_restart(RELAY_WORLD *w) {
	PEER_CONFIG c;
	PEER_INFO p[2];
	PEER_STATS st;

	coretest_check(relay_pair(w, &w->X, &w->Y), "X and Y come up through R2");
	bool sent = PeerSend(w->X.Agent, w->Y.Key.Public, "before", 6);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(sent && w->Y.Received == 1, "X's datagram reaches Y through R2");

	// R2 restarts: a new peer layer with the same key and the same Peer objects
	NatSimAttach(w->R2.Host, NULL);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	PeerFree(w->R2.Agent);
	PeerDefaultConfig(&c);
	c.Relay = true;
	w->R2.Agent = PeerNew(&w->R2.Key, &c, NatSimSend, w->R2.Host, relay_recv, &w->R2);
	relay_peer(&p[0], "x", w->X.Key.Public, 30);
	relay_peer(&p[1], "y", w->Y.Key.Public, 30);
	PeerSetPeers(w->R2.Agent, p, 2);
	NatSimAttach(w->R2.Host, w->R2.Agent);

	sent = PeerSend(w->X.Agent, w->Y.Key.Public, "lost", 4);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(sent && w->Y.Received == 1 && relay_drops(&w->R2, PEER_DROP_SOURCE) == 1, "Right after the restart R2 has no binding and drops X's datagram");

	// The keepalive of X and Y (BindInterval 100 ms)
	Sleep(150);
	PeerTick(w->X.Agent);
	PeerTick(w->Y.Agent);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	PeerGetStats(w->R2.Agent, &st);
	sent = PeerSend(w->X.Agent, w->Y.Key.Public, "after", 5);
	NatSimWaitIdle(w->Sim, RELAY_WAIT);
	coretest_check(st.NumBindings == 2 && sent && w->Y.Received == 2 && strcmp(w->Y.Last, "after") == 0, "After the next keepalive X and Y are bound to R2 again and their traffic flows");
}

void relaypolicy_test() {
	RELAY_WORLD w;
	PEER_CONFIG rc;

	PeerDefaultConfig(&rc);
	rc.RelayRate = 100;
	rc.RelayBurst = 20;

	bool started = relay_world_start(&w, &rc);
	coretest_check(started, "The harness network starts: R and its nodes are bound");
	if (started && coretest_check(relay_pair(&w, &w.A, &w.B), "A and B, each behind a symmetric NAT, come up through R")) {
		relay_policy_signals(&w);
		relay_policy_binds(&w);
		relay_policy_forwarding(&w);
		relay_policy_paths(&w);
		relay_policy_restart(&w);
	}

	relay_world_stop(&w);
}
