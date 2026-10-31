// punch.c
// Named test of port prediction and birthday-paradox hole punching for symmetric NAT (src/Core/PeerPunch.c;
// CORE-S5-4 #266), on the NAT simulator of natsim.c, as relay.c runs. The punch is Ranz's own code on the peer
// layer's own socket (not libjuice), so the simulated NATs carry it: a pair that ICE (CORE-S5-3) leaves on the relay
// because both ends are symmetric gets a direct path here when the ports can be predicted or hit.
//
// punch: three pairs, each behind two NATs the simulator allocates ports for in one of the three ways, come up
//   through the relay R and then try the punch, which the control plane triggers with the signal exchange:
//   - two sequential-allocation symmetric NATs meet by port prediction: each aims its first probe at the next port
//     the other predicted of itself, so the two mappings address each other, and the pair moves to the direct path;
//     a late probe of one end's burst, which reaches the other end after the pair met, leaves the pair on that path;
//   - a full-cone NAT and a random-allocation symmetric NAT meet by birthday punching: the random side reaches the
//     cone's one predictable port, and the cone learns the random side's mapping from that probe and answers it;
//   - two random-allocation symmetric NATs predict nothing, so the probes miss until the budget runs out and the
//     pair stays on the relay, its traffic flowing there throughout.
//   The test also checks that the probe count and rate stay within the configured budget and rate, that the punch
//   begins only once the control plane has carried the signals, and that the prediction success rate and the
//   direct-versus-relay split come out as metrics. A port-preserving NAT's allocation is checked on its own.
// The control plane is stood in for by the test, which hands each signal from one node to the other, as relay.c and
// the controller's conformance test do.

#include "coretest.h"

#include <string.h>

#define PUNCH_WAIT         10000 // ms: a bounded wait for the network to carry everything sent
#define PUNCH_BUDGET       64    // Probes one punch of a peer may send before it gives up
#define PUNCH_PORTS        16    // The birthday range above a predicted or reflexive port
#define PUNCH_RATE         8     // Probes one PeerTick sends per punching peer
#define PUNCH_TICKS        40    // The most tick rounds a pair is given to meet, or a punch to spend its budget
#define PUNCH_PAYLOAD_SIZE 42    // A punch message: version, sequence, type, a nonce and an echo of 16 bytes each

// One node of the test and what it received
typedef struct PUNCH_NODE {
	const char *Name;             // Its name
	PEER_KEY Key;                 // Its static key
	PEER_ADDR Addr;               // Its address: private behind a NAT
	NATSIM_HOST *Host;            // Its host on the network
	PEER_AGENT *Agent;            // Its peer layer
	volatile LONG Received;       // Data datagrams delivered to it
	volatile LONG ReceivedDirect; // ... of them on the direct path
	volatile LONG ReceivedRelay;  // ... of them through a relay
	volatile LONG Echo;           // Answer each "ping" with a "pong"
} PUNCH_NODE;

// The network of a test: the relays R (home) and R2 (the second reflexive vantage point) on the public side, and the
// pair A and B each behind a NAT of its own
typedef struct PUNCH_WORLD {
	NATSIM *Sim;      // The network
	NATSIM_NAT *NatA; // A's NAT
	NATSIM_NAT *NatB; // B's NAT
	PUNCH_NODE R, R2, A, B;
} PUNCH_WORLD;

// The receive procedure of every node: count the datagram by its path; with Echo, answer "ping ..." with "pong ..."
static void punch_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	PUNCH_NODE *n = (PUNCH_NODE *)param;
	char pong[64];

	if (path == PEER_PATH_DIRECT)
		InterlockedIncrement(&n->ReceivedDirect);
	else
		InterlockedIncrement(&n->ReceivedRelay);
	InterlockedIncrement(&n->Received);

	if (InterlockedCompareExchange(&n->Echo, 0, 0) != 0 && size >= 4 && size < sizeof(pong) && memcmp(data, "ping", 4) == 0) {
		CopyMemory(pong, data, size);
		CopyMemory(pong, "pong", 4);
		PeerSend(a, src, pong, size);
	}
}

// A node of the world: its key from the fixed scalar first, its host behind nat (NULL: public) at addr, its peer
// layer with the configuration c
static bool punch_node(PUNCH_WORLD *w, PUNCH_NODE *n, const char *name, UCHAR first, NATSIM_NAT *nat, const PEER_ADDR *addr, PEER_CONFIG *c) {
	n->Name = name;
	n->Addr = *addr;
	coretest_fixed_key(&n->Key, first);
	n->Host = NatSimAddHost(w->Sim, nat, addr);
	if (n->Host == NULL)
		return false;

	n->Agent = PeerNew(&n->Key, c, NatSimSend, n->Host, punch_recv, n);
	NatSimAttach(n->Host, n->Agent);

	return n->Agent != NULL;
}

// A peer of the peer table: a node with the key key in one VRF
static void punch_peer(PEER_INFO *p, const char *name, const UCHAR *key, UINT vrf) {
	ZeroMemory(p, sizeof(PEER_INFO));
	strcpy_s(p->Name, sizeof(p->Name), name);
	CopyMemory(p->Key, key, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = vrf;
}

// A relay of the relays of a node
static void punch_relay_info(PEER_RELAY_INFO *r, PUNCH_NODE *relay) {
	ZeroMemory(r, sizeof(PEER_RELAY_INFO));
	strcpy_s(r->Name, sizeof(r->Name), relay->Name);
	CopyMemory(r->Key, relay->Key.Public, PEER_KEY_SIZE);
	r->Addr = relay->Addr;
}

// Build the world: R and R2 on the public side with the relay role, A behind NatA and B behind NatB, both with
// punching on. A's NAT maps and allocates by a_map/a_filter/a_alloc (and a_seed for a random one), B's by the b_
// parameters. Then the peers and the relays of every node, and the binds to R and R2.
static bool punch_world_start(PUNCH_WORLD *w, UINT a_map, UINT a_filter, UINT a_alloc, UINT32 a_seed, UINT b_map, UINT b_filter, UINT b_alloc, UINT32 b_seed) {
	PEER_CONFIG rc, pc;
	PEER_ADDR addr;
	PEER_INFO p[2];
	PEER_RELAY_INFO ri[2];
	bool ok = true;

	ZeroMemory(w, sizeof(PUNCH_WORLD));
	w->Sim = NatSimNew();
	if (w->Sim == NULL)
		return false;

	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, a_map, a_filter);
	w->NatB = NatSimAddNat(w->Sim, 203, 0, 113, 20, b_map, b_filter);
	NatSimSetAllocation(w->NatA, a_alloc, a_seed);
	NatSimSetAllocation(w->NatB, b_alloc, b_seed);

	PeerDefaultConfig(&rc);
	rc.Relay = true;

	PeerDefaultConfig(&pc);
	pc.Punch = true;
	pc.PunchBudget = PUNCH_BUDGET;
	pc.PunchPorts = PUNCH_PORTS;
	pc.PunchRate = PUNCH_RATE;

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = punch_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 2, 3478);
	ok = punch_node(w, &w->R2, "r2", 161, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 10, 0, 0, 2, 5000);
	ok = punch_node(w, &w->A, "a", 1, w->NatA, &addr, &pc) && ok;
	ok = punch_node(w, &w->B, "b", 33, w->NatB, &addr, &pc) && ok;

	if (ok == false)
		return false;

	// The Peer objects: A and B are peers in VRF 10; the relays hold both of them
	punch_peer(&p[0], "a", w->A.Key.Public, 10);
	punch_peer(&p[1], "b", w->B.Key.Public, 10);
	PeerSetPeers(w->R.Agent, p, 2);
	PeerSetPeers(w->R2.Agent, p, 2);

	punch_peer(&p[0], "b", w->B.Key.Public, 10);
	PeerSetPeers(w->A.Agent, p, 1);
	punch_peer(&p[0], "a", w->A.Key.Public, 10);
	PeerSetPeers(w->B.Agent, p, 1);

	// R is the home relay of A and B, R2 their second vantage point; a punching node binds both
	punch_relay_info(&ri[0], &w->R);
	punch_relay_info(&ri[1], &w->R2);
	PeerSetHostCandidates(w->A.Agent, &w->A.Addr, 1);
	PeerSetHostCandidates(w->B.Agent, &w->B.Addr, 1);
	PeerSetRelays(w->A.Agent, ri, 2);
	PeerSetRelays(w->B.Agent, ri, 2);

	return NatSimWaitIdle(w->Sim, PUNCH_WAIT);
}

// Stop the network first, so that no datagram reaches a freed peer layer
static void punch_world_stop(PUNCH_WORLD *w) {
	PUNCH_NODE *nodes[] = {&w->R, &w->R2, &w->A, &w->B};

	NatSimFree(w->Sim);
	w->Sim = NULL;

	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		PeerFree(nodes[i]->Agent);
		nodes[i]->Agent = NULL;
		PeerKeyClose(&nodes[i]->Key);
	}
}

// The stand-in of the control plane: from seals a signal of type for to, and to takes it. Returns what PeerOpenSignal
// returned, PEER_DROP_MALFORMED when nothing was sealed.
static UINT punch_signal(PUNCH_NODE *from, PUNCH_NODE *to, UINT type, PEER_SIGNAL *sig) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(from->Agent, to->Key.Public, type, env, sizeof(env));
	if (size == 0)
		return PEER_DROP_MALFORMED;

	return PeerOpenSignal(to->Agent, env, size, sig);
}

// Bring the pair A and B up through the relay: an offer A to B and the answer B to A, which also triggers each end's
// punch of the other. Returns true when both signals were taken.
static bool punch_exchange(PUNCH_WORLD *w) {
	PEER_SIGNAL offer, answer;

	bool ok = punch_signal(&w->A, &w->B, PEER_SIGNAL_OFFER, &offer) == PEER_OK;
	ok = punch_signal(&w->B, &w->A, PEER_SIGNAL_ANSWER, &answer) == PEER_OK && ok;

	return NatSimWaitIdle(w->Sim, PUNCH_WAIT) && ok;
}

// The path from a node to a peer now
static UINT punch_path(PUNCH_NODE *from, PUNCH_NODE *to) {
	PEER_STATUS ps;

	PeerGetStatus(from->Agent, to->Key.Public, &ps);

	return ps.Path;
}

// Drive the punch until the pair reaches the direct path, at most PUNCH_TICKS rounds; true once both ends are direct
static bool punch_converge(PUNCH_WORLD *w) {
	for (UINT i = 0; i < PUNCH_TICKS; i++) {
		PeerTick(w->A.Agent);
		PeerTick(w->B.Agent);
		NatSimWaitIdle(w->Sim, PUNCH_WAIT);

		if (punch_path(&w->A, &w->B) == PEER_PATH_DIRECT && punch_path(&w->B, &w->A) == PEER_PATH_DIRECT)
			return true;
	}

	return false;
}

// Drive the punch until both ends have spent their budget, at most PUNCH_TICKS rounds; true once both failed
static bool punch_exhaust(PUNCH_WORLD *w) {
	for (UINT i = 0; i < PUNCH_TICKS; i++) {
		PEER_STATUS pa, pb;

		PeerTick(w->A.Agent);
		PeerTick(w->B.Agent);
		NatSimWaitIdle(w->Sim, PUNCH_WAIT);

		PeerGetStatus(w->A.Agent, w->B.Key.Public, &pa);
		PeerGetStatus(w->B.Agent, w->A.Key.Public, &pb);
		if (pa.Punch == PEER_PUNCH_FAILED && pb.Punch == PEER_PUNCH_FAILED)
			return true;
	}

	return false;
}

static UINT64 punch_sent(PUNCH_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Sent;
}

// Send one datagram from one node to another with the text text
static bool punch_send(PUNCH_NODE *from, PUNCH_NODE *to, const char *text) {
	return PeerSend(from->Agent, to->Key.Public, text, (UINT)strlen(text));
}

// The candidate of type in a signal, false when it has none
static bool punch_candidate(PEER_SIGNAL *s, UINT type, PEER_ADDR *addr) {
	for (UINT i = 0; i < s->NumCandidates; i++) {
		if (s->Candidates[i].Type == type) {
			*addr = s->Candidates[i].Addr;
			return true;
		}
	}

	return false;
}

// The drops of a node, all reasons
static UINT64 punch_drops(PUNCH_NODE *n) {
	PEER_STATS st;
	UINT64 sum = 0;

	PeerGetStats(n->Agent, &st);
	for (UINT r = PEER_DROP_MALFORMED; r < PEER_NUM_REASONS; r++)
		sum += st.Drops[r];

	return sum;
}

// A probe of B for A, sealed as PeerPunchTick seals one (version 1, the sequence, type 1 for a probe, and two empty
// nonces) into env; returns its size. Its sequence is the wall clock in 100 ns units, as PeerNextSequence draws one,
// so it is above every sequence B sent before.
static UINT punch_seal_probe(PUNCH_WORLD *w, UCHAR *env, UINT max) {
	FILETIME ft;
	UCHAR probe[PUNCH_PAYLOAD_SIZE];

	GetSystemTimePreciseAsFileTime(&ft);
	UINT64 seq = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

	ZeroMemory(probe, sizeof(probe));
	probe[0] = 1;
	for (UINT i = 0; i < 8; i++)
		probe[1 + i] = (UCHAR)(seq >> (56 - 8 * i));
	probe[9] = 1;

	return PeerEnvelopeSeal(&w->B.Key, w->A.Key.Public, PEER_MSG_PUNCH, NULL, probe, sizeof(probe), env, max);
}

// A probe of B for A, sent from B's host to the address to, so it leaves through B's mapping towards to
static void punch_probe_from_b(PUNCH_WORLD *w, const PEER_ADDR *to) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = punch_seal_probe(w, env, sizeof(env));
	NatSimSend(w->B.Host, to, env, size);
	NatSimWaitIdle(w->Sim, PUNCH_WAIT);
}

// The send procedure of a peer layer that the test feeds by hand: its datagrams go nowhere
static bool punch_send_nowhere(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	return true;
}

// Two sequential symmetric NATs: the pair moves to the direct path by port prediction
static void punch_sequential() {
	PUNCH_WORLD w;
	PEER_SIGNAL offer;
	PEER_STATS st_a, st_b, st_r;
	PEER_STATUS ps_a, ps_b;
	PEER_ADDR predicted;

	bool started = punch_world_start(&w, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0);
	coretest_check(started, "The network starts: R and R2 on the public side, A and B each behind a sequential-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st_a.NumBound == 2 && st_b.NumBound == 2, "A and B each bind R and R2, so two reflexive observations let them learn their NAT's pattern");
	coretest_check(st_a.PunchAttempts == 0 && st_b.PunchAttempts == 0, "No punch has begun before the control plane carries a signal");

	// The signal exchange triggers the punch; it begins only now, so its timing comes from the control plane
	coretest_check(punch_exchange(&w), "A and B exchange one signal each through the control plane");
	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st_a.PunchAttempts == 1 && st_b.PunchAttempts == 1, "The punch begins only once the signals are exchanged: its timing comes from the control plane");

	// A's signal carries the predicted next port of its NAT
	ZeroMemory(&predicted, sizeof(predicted));
	UINT r = punch_signal(&w.A, &w.B, PEER_SIGNAL_OFFER, &offer);
	coretest_check(r == PEER_OK && punch_candidate(&offer, PEER_CANDIDATE_PREDICTED, &predicted) && predicted.Port != 0, "A's offer carries the predicted next port of its NAT");

	// Relay-first: a datagram now, before any probe, goes through R
	bool sent = punch_send(&w.B, &w.A, "relayed first");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	coretest_check(sent && w.A.Received == 1 && w.A.ReceivedRelay == 1 && w.A.ReceivedDirect == 0, "Before the probes meet, the pair's traffic flows through R");

	bool direct = punch_converge(&w);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps_a);
	PeerGetStatus(w.B.Agent, w.A.Key.Public, &ps_b);
	coretest_check(direct && ps_a.Punch == PEER_PUNCH_CONNECTED && ps_b.Punch == PEER_PUNCH_CONNECTED, "Port prediction gets the pair a direct path: each aimed its first probe at the other's predicted port");

	// Both ways on the direct path, with R forwarding nothing
	InterlockedExchange(&w.B.Echo, 1);
	LONG received = w.A.Received;
	LONG a_direct = w.A.ReceivedDirect;
	PeerGetStats(w.R.Agent, &st_r);
	UINT64 forwarded = st_r.Forwarded;
	sent = punch_send(&w.A, &w.B, "ping direct");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	PeerGetStats(w.R.Agent, &st_r);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedDirect == a_direct + 1 && st_r.Forwarded == forwarded, "A's ping and B's pong both take the direct path; R forwards neither");

	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st_a.PunchSuccesses == 1 && st_b.PunchSuccesses == 1 && st_a.PunchAttempts == 1, "Each end's prediction success rate is one of one: the metric is exported");
	coretest_check(st_a.DeliveredRelay >= 1 && st_a.Delivered > st_a.DeliveredRelay, "The direct-versus-relay split is a metric: A took its first datagram through R and its later one directly");

	// A late probe of B's burst. B sends a burst of probes in one tick and can take A's answer while it still sends
	// them, so the rest of the burst reaches A after the pair met, each probe from another of B's mappings. This one
	// comes from B's mapping towards A's second mapping, one port above A's predicted one, where B's second probe went.
	PEER_ADDR late = predicted;
	late.Port++;
	UINT filtered = NatSimFiltered(w.NatA);
	UINT64 drops = punch_drops(&w.A);
	punch_probe_from_b(&w, &late);
	coretest_check(NatSimFiltered(w.NatA) == filtered && punch_drops(&w.A) == drops, "A late probe of B's burst, from B's mapping towards A's second mapping, reaches A, which takes it");

	received = w.A.Received;
	a_direct = w.A.ReceivedDirect;
	PeerGetStats(w.R.Agent, &st_r);
	forwarded = st_r.Forwarded;
	sent = punch_send(&w.A, &w.B, "ping after the late probe");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	PeerGetStats(w.R.Agent, &st_r);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedDirect == a_direct + 1 && st_r.Forwarded == forwarded, "After it, A's ping and B's pong still take the direct path: A stays on the pair it met B on, whose mapping B took A's answer from");

	punch_world_stop(&w);
}

// A full-cone NAT and a random symmetric NAT: the pair meets by birthday punching
static void punch_birthday() {
	PUNCH_WORLD w;
	PEER_STATS st_a, st_b;

	bool started = punch_world_start(&w, NATSIM_MAP_ENDPOINT_INDEPENDENT, NATSIM_FILTER_ENDPOINT_INDEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x51ED2C9B);
	coretest_check(started, "The network starts: A behind a full-cone NAT, B behind a random-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	coretest_check(punch_exchange(&w), "A and B exchange one signal each through the control plane");

	// Before any probe: an attacker on the path sends a probe of B, which it captured, to A's port from an address of
	// its own. A takes it as B's, but moves to no direct path there: its answer goes to that address, sealed to B
	// (finding F3 of the second review of AUD-5 on the direct path)
	PEER_ADDR attacker, a_public;
	PEER_STATUS ps;
	UCHAR env[PEER_MAX_ENVELOPE];
	PeerAddrSetV4(&attacker, 198, 51, 100, 66, 4000);
	NATSIM_HOST *m = NatSimAddHost(w.Sim, NULL, &attacker);
	NatSimMapped(w.NatA, &w.A.Addr, &a_public);
	UINT64 a_sent = punch_sent(&w.A);
	UINT size = punch_seal_probe(&w, env, sizeof(env));
	NatSimSend(m, &a_public, env, size);
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps);
	coretest_check(m != NULL && ps.Path == PEER_PATH_RELAY && ps.Punch == PEER_PUNCH_PROBING && punch_sent(&w.A) == a_sent + 1,
	               "A probe of B that an attacker sends from its own address moves A to no direct path there: A answers it once, sealed to B, and waits for the echo that only B can give");

	bool direct = punch_converge(&w);
	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps);
	coretest_check(direct && st_a.PunchSuccesses == 1 && st_b.PunchSuccesses == 1, "Birthday punching gets the pair a direct path within the probe budget: the random side reaches the cone's one port and the cone learns the random mapping");
	coretest_check(PeerAddrEqual(&ps.Direct, &attacker) == false && ps.Direct.Port != 0, "A's direct path to B is at B's own mapping, which proved itself with the echo of A's nonce, not at the attacker's address");

	// A probe of B sealed before A restarts is a replay at the new peer layer of A, which takes no sequence older than
	// its entry of B, while a fresh one is taken
	PEER_CONFIG pc;
	PEER_INFO p;
	PEER_RELAY_INFO ri[2];
	PEER_ADDR from;
	UINT old_size = punch_seal_probe(&w, env, sizeof(env));
	Sleep(2);
	PeerDefaultConfig(&pc);
	pc.Punch = true;
	PEER_AGENT *a2 = PeerNew(&w.A.Key, &pc, punch_send_nowhere, NULL, NULL, NULL);
	if (a2 != NULL) {
		UCHAR sig[PEER_MAX_ENVELOPE];
		UCHAR fresh[PEER_MAX_ENVELOPE];

		punch_peer(&p, "b", w.B.Key.Public, 10);
		PeerSetPeers(a2, &p, 1);
		punch_relay_info(&ri[0], &w.R);
		punch_relay_info(&ri[1], &w.R2);
		PeerSetRelays(a2, ri, 2);
		UINT sig_size = PeerSealSignal(w.B.Agent, w.A.Key.Public, PEER_SIGNAL_OFFER, sig, sizeof(sig));
		UINT taken = PeerOpenSignal(a2, sig, sig_size, NULL);
		PeerGetStatus(a2, w.B.Key.Public, &ps);

		PeerAddrSetV4(&from, 203, 0, 113, 20, 40000);
		PeerInput(a2, &from, env, old_size);
		PEER_STATS st;
		PeerGetStats(a2, &st);
		UINT64 replay = st.Drops[PEER_DROP_REPLAY];

		UINT fresh_size = punch_seal_probe(&w, fresh, sizeof(fresh));
		PeerInput(a2, &from, fresh, fresh_size);
		PeerGetStats(a2, &st);
		coretest_check(taken == PEER_OK && ps.Punch == PEER_PUNCH_PROBING && replay == 1 && st.Drops[PEER_DROP_REPLAY] == 1,
		               "After A restarts, a probe of B from before the restart is a replay, and a fresh one is taken");
	}
	coretest_check(a2 != NULL, "A's peer layer starts again with the same key");
	PeerFree(a2);

	InterlockedExchange(&w.A.Echo, 1);
	LONG b_direct = w.B.ReceivedDirect;
	bool sent = punch_send(&w.B, &w.A, "ping direct");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	coretest_check(sent && w.B.ReceivedDirect == b_direct + 1, "On the direct path B's ping and A's pong flow straight between them");

	punch_world_stop(&w);
}

// Two random symmetric NATs: nothing is predictable, so the pair stays on the relay within a bounded budget
static void punch_random() {
	PUNCH_WORLD w;
	PEER_STATS st_a, st_b;
	UINT64 before, after;

	bool started = punch_world_start(&w, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x1A2B3C4D,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x7788AA55);
	coretest_check(started, "The network starts: A and B each behind a random-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	coretest_check(punch_exchange(&w), "A and B exchange one signal each through the control plane");

	// The probe rate: one tick sends no more than the configured rate, counted from the first probe of the punch
	before = punch_sent(&w.A);
	PeerTick(w.A.Agent);
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	after = punch_sent(&w.A);
	coretest_check(after - before <= PUNCH_RATE, "One tick of a punch sends no more than the configured rate of probes");

	// The budget: the punch gives up after it, and the total probes of the punch stay within it
	bool exhausted = punch_exhaust(&w);
	after = punch_sent(&w.A);
	coretest_check(exhausted, "With nothing to predict, both ends spend their budget and the punch fails");
	coretest_check(after - before <= PUNCH_BUDGET, "A sent no more than its configured budget of probes");

	coretest_check(punch_path(&w.A, &w.B) == PEER_PATH_RELAY && punch_path(&w.B, &w.A) == PEER_PATH_RELAY, "The pair stays on the relay: no probe met");

	PeerGetStats(w.A.Agent, &st_a);
	PeerGetStats(w.B.Agent, &st_b);
	coretest_check(st_a.PunchAttempts == 1 && st_b.PunchAttempts == 1 && st_a.PunchSuccesses == 0 && st_b.PunchSuccesses == 0, "The metric records the attempt and no success: the prediction success rate is zero of one");

	// Traffic keeps flowing on the relay throughout, with no interruption
	InterlockedExchange(&w.B.Echo, 1);
	LONG received = w.A.Received;
	bool sent = punch_send(&w.A, &w.B, "ping relayed");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedRelay >= 1 && w.A.ReceivedDirect == 0, "The pair's ping and pong flow through R while the punch runs and after it fails");

	punch_world_stop(&w);
}

// A port-preserving NAT keeps the private source port of a mapping while it is free (the third pattern the seam asks
// the simulator to model, next to sequential and random)
static void punch_preserving() {
	NATSIM *sim = NatSimNew();
	NATSIM_NAT *nat;
	NATSIM_HOST *host;
	PEER_ADDR inside, dst, mapped;
	UCHAR dgram[PEER_DATA_HEADER_SIZE];

	if (coretest_check(sim != NULL, "The network for the port-preserving check starts") == false)
		return;

	nat = NatSimAddNat(sim, 203, 0, 113, 30, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	NatSimSetAllocation(nat, NATSIM_ALLOC_PRESERVING, 0);
	PeerAddrSetV4(&inside, 10, 0, 0, 9, 51000);
	host = NatSimAddHost(sim, nat, &inside);

	// A datagram straight to a public destination, so the NAT makes a mapping for the private source port 51000
	PeerAddrSetV4(&dst, 198, 51, 100, 50, 3478);
	ZeroMemory(dgram, sizeof(dgram));
	dgram[0] = PEER_MSG_DATA;
	NatSimSend(host, &dst, dgram, sizeof(dgram));
	NatSimWaitIdle(sim, PUNCH_WAIT);

	coretest_check(NatSimMapped(nat, &inside, &mapped) && mapped.Port == 51000, "The port-preserving NAT maps the private source port 51000 unchanged");

	NatSimFree(sim);
}

// The burst case of the review of PR 429 (CORE-H2-R1 #436): the punch messages that a node sends before the test hands
// them on, and the probes of the burst
#define PUNCH_WIRE_MAX 8
#define PUNCH_BURST    5

// A node of the burst case, where the test is the network: the punch messages that its peer layer sends wait in its
// outbox, each with the address it went to, until the test hands them on from the address of the node
typedef struct PUNCH_WIRE {
	PEER_KEY Key;                                  // Its static key
	PEER_ADDR Addr;                                // Its address, at which the other node sees it
	PEER_AGENT *Agent;                             // Its peer layer, with punching on
	UINT Num;                                      // The messages in its outbox
	PEER_ADDR To[PUNCH_WIRE_MAX];                  // ... the address each went to
	UINT Size[PUNCH_WIRE_MAX];                     // ... their sizes
	UCHAR Data[PUNCH_WIRE_MAX][PEER_MAX_ENVELOPE]; // ... and their bytes
} PUNCH_WIRE;

// The send procedure of a node of the burst case: the message goes into its outbox
static bool punch_wire_send(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	PUNCH_WIRE *n = (PUNCH_WIRE *)param;

	if (n->Num == PUNCH_WIRE_MAX || size > PEER_MAX_ENVELOPE)
		return false;

	n->To[n->Num] = *dst;
	n->Size[n->Num] = size;
	CopyMemory(n->Data[n->Num], data, size);
	n->Num++;

	return true;
}

static void punch_wire_free(PUNCH_WIRE *n) {
	if (n == NULL)
		return;

	PeerFree(n->Agent);
	PeerKeyClose(&n->Key);
	HeapFree(GetProcessHeap(), 0, n);
}

// A node of the burst case with the key of the fixed scalar first, at 203.0.113.last port 40000, with punching on;
// NULL when it does not start
static PUNCH_WIRE *punch_wire_new(UCHAR first, UCHAR last) {
	PEER_CONFIG c;
	PUNCH_WIRE *n = (PUNCH_WIRE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PUNCH_WIRE));

	if (n == NULL)
		return NULL;

	PeerDefaultConfig(&c);
	c.Punch = true;
	coretest_fixed_key(&n->Key, first);
	PeerAddrSetV4(&n->Addr, 203, 0, 113, last, 40000);
	n->Agent = PeerNew(&n->Key, &c, punch_wire_send, n, NULL, NULL);
	if (n->Agent == NULL) {
		punch_wire_free(n);
		return NULL;
	}

	return n;
}

// The wall clock in 100 ns units, which the sequences of the punch follow (PeerNextSequence)
static UINT64 punch_clock() {
	FILETIME ft;

	GetSystemTimePreciseAsFileTime(&ft);

	return ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

// The stand-in of the control plane of the burst case: a signal of from for to, sealed by the test with the address of
// from as its reflexive candidate, which begins the punch of to with from (PeerOpenSignal). Returns what PeerOpenSignal
// returned.
static UINT punch_wire_signal(PUNCH_WIRE *from, PUNCH_WIRE *to) {
	PEER_SIGNAL s;
	UCHAR payload[PEER_MAX_ENVELOPE];
	UCHAR env[PEER_MAX_ENVELOPE];

	ZeroMemory(&s, sizeof(s));
	s.Type = PEER_SIGNAL_OFFER;
	s.Sequence = punch_clock();
	s.NumCandidates = 1;
	s.Candidates[0].Type = PEER_CANDIDATE_SRFLX;
	s.Candidates[0].Addr = from->Addr;

	UINT len = PeerSignalEncode(&s, payload, sizeof(payload));
	UINT size = (len != 0 ? PeerEnvelopeSeal(&from->Key, to->Key.Public, PEER_MSG_SIGNAL, NULL, payload, len, env, sizeof(env)) : 0);

	return (size != 0 ? PeerOpenSignal(to->Agent, env, size, NULL) : PEER_DROP_MALFORMED);
}

// A probe of the node from for the node to with the sequence seq, sealed as PeerPunchTick seals one (version 1, the
// sequence, type 1 for a probe, and two empty nonces); returns the size of the envelope in env
static UINT punch_wire_probe(PUNCH_WIRE *from, PUNCH_WIRE *to, UINT64 seq, UCHAR *env, UINT max) {
	UCHAR probe[PUNCH_PAYLOAD_SIZE];

	ZeroMemory(probe, sizeof(probe));
	probe[0] = 1;
	for (UINT i = 0; i < 8; i++)
		probe[1 + i] = (UCHAR)(seq >> (56 - 8 * i));
	probe[9] = 1;

	return PeerEnvelopeSeal(&from->Key, to->Key.Public, PEER_MSG_PUNCH, NULL, probe, sizeof(probe), env, max);
}

// Hand the message i of the outbox of from to the node to, from the address of from
static void punch_wire_hand(PUNCH_WIRE *from, UINT i, PUNCH_WIRE *to) {
	if (i < from->Num)
		PeerInput(to->Agent, &from->Addr, from->Data[i], from->Size[i]);
}

// A burst of probes from one address, each of which draws a challenge, draws one nonce at each end, so the response to
// the first challenge meets, also when the responses to the later ones are lost. With a nonce for each message, a burst
// of more than PEER_PUNCH_NONCES (4) evicted the first one (finding 4).
static void punch_burst() {
	UCHAR env[PEER_MAX_ENVELOPE];
	PEER_INFO p;
	PEER_STATUS ls, fs;

	PUNCH_WIRE *x = punch_wire_new(1, 10);
	PUNCH_WIRE *y = punch_wire_new(33, 20);
	if (coretest_check(x != NULL && y != NULL, "Two nodes whose punch messages the test hands on start, with punching on") == false) {
		punch_wire_free(x);
		punch_wire_free(y);
		return;
	}

	// L, the node of the lower static key, leads: it answers a probe with a challenge, and F a challenge with a response
	PUNCH_WIRE *l = (memcmp(x->Key.Public, y->Key.Public, PEER_KEY_SIZE) < 0 ? x : y);
	PUNCH_WIRE *f = (l == x ? y : x);
	punch_peer(&p, "f", f->Key.Public, 10);
	PeerSetPeers(l->Agent, &p, 1);
	punch_peer(&p, "l", l->Key.Public, 10);
	PeerSetPeers(f->Agent, &p, 1);
	UINT taken = punch_wire_signal(f, l);
	taken = (taken == PEER_OK ? punch_wire_signal(l, f) : taken);
	PeerGetStatus(l->Agent, f->Key.Public, &ls);
	PeerGetStatus(f->Agent, l->Key.Public, &fs);
	coretest_check(taken == PEER_OK && ls.Punch == PEER_PUNCH_PROBING && fs.Punch == PEER_PUNCH_PROBING, "The signal of each node begins its punch with the other");

	// A burst of probes of F from its one address: L answers each with a challenge to that address, and F each challenge
	// with a response to L's address
	UINT64 seq = punch_clock();
	for (UINT i = 0; i < PUNCH_BURST; i++) {
		UINT size = punch_wire_probe(f, l, seq + i, env, sizeof(env));
		PeerInput(l->Agent, &f->Addr, env, size);
	}
	for (UINT i = 0; i < l->Num; i++)
		punch_wire_hand(l, i, f);
	coretest_check(l->Num == PUNCH_BURST && f->Num == PUNCH_BURST && PeerAddrEqual(&l->To[0], &f->Addr) && PeerAddrEqual(&f->To[0], &l->Addr),
	               "L answers each probe of a burst from F's address with a challenge to that address, and F each challenge with a response");

	// Only the response to the first challenge comes back: L meets F at F's address, and L's proof moves F to the direct
	// path at L's address
	punch_wire_hand(f, 0, l);
	PeerGetStatus(l->Agent, f->Key.Public, &ls);
	coretest_check(ls.Punch == PEER_PUNCH_CONNECTED && ls.Path == PEER_PATH_DIRECT && PeerAddrEqual(&ls.Direct, &f->Addr) && l->Num == PUNCH_BURST + 1,
	               "The response to the first challenge of the burst meets: L sent the same nonce to that address in every challenge, and the burst evicted none");
	punch_wire_hand(l, PUNCH_BURST, f);
	PeerGetStatus(f->Agent, l->Key.Public, &fs);
	coretest_check(fs.Punch == PEER_PUNCH_CONNECTED && fs.Path == PEER_PATH_DIRECT && PeerAddrEqual(&fs.Direct, &l->Addr),
	               "L's proof moves F to the direct path at L's address: F sent the same nonce in every response to that address");

	punch_wire_free(x);
	punch_wire_free(y);
}

void punch_test() {
	// The case of the review of PR 429 (CORE-H2-R1 #436)
	punch_burst();
	punch_preserving();
	punch_sequential();
	punch_birthday();
	punch_random();
}
