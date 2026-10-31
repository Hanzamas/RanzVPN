// punch.c
// Named test of port prediction and birthday-paradox hole punching for symmetric NAT (src/Core/PeerPunch.c;
// CORE-S5-4 #266, CORE-S5-7 #413), on the NAT simulator of natsim.c, as relay.c runs. The punch is Ranz's own code on
// the peer layer's own socket (not libjuice), so the simulated NATs carry it: a pair that ICE (CORE-S5-3) leaves on the
// relay because a NAT of it is symmetric gets a direct path here when the ports can be predicted or hit.
//
// punch: pairs behind two NATs that the simulator allocates ports for in one of the three ways come up through the relay R
//   and then try the punch, which the control plane times with a punch offer and its answer:
//   - two sequential-allocation symmetric NATs meet by port prediction: each node tells its NAT from the answers of its
//     binds to R and R2, its punch offer or answer names the port of its next mapping, and the sweeps of the two ends
//     cross, so the pair moves to the direct path; a late probe of a burst, which reaches the other end after the pair
//     met, leaves the pair on that path, and a probe of a node that is no peer is dropped and counted;
//   - a full-cone NAT and a random-allocation symmetric NAT meet by birthday punching: the random side reaches the
//     cone's one port, and the cone learns the random side's mapping from that probe and answers it; a probe that an
//     attacker sends from an address of its own moves the cone to no direct path there;
//   - two random-allocation symmetric NATs predict nothing: neither end takes the punch, no probe leaves either, and the
//     pair stays on the relay, its traffic flowing there throughout;
//   - two sequential NATs whose direct path is cut: each attempt spends its budget of probes within the rate of the node
//     and fails, the pair stays on the relay, and after the attempts that met nothing an offer is refused until the
//     backoff ends;
//   - the same, where the attempts of B run longer than the ones of A: each offer of A, which comes once its own attempt
//     ended, ends the attempt of B that still runs and begins the next at both ends, so the two count the same attempts
//     and reach the backoff on the same offer, and an offer that B refuses gets no answer, so A begins no attempt alone;
//   - a burst of probes from one address, on two nodes whose messages the test hands on itself and whose relays it
//     plays (CORE-H2-R1 #436): the leader answers every probe of it with the same nonce and the other end every
//     challenge, so the response to the first challenge meets, and the proof moves the other end to the direct path.
//   The test also checks that a probe begins only once the control plane carried the punch signals, and that the
//   attempts, the successes and the failures of the prediction come out as metrics. A port-preserving NAT's allocation
//   is checked on its own.
// The control plane is stood in for by the test, which hands each signal from one node to the other, as relay.c and
// the controller's conformance test do.

#include "coretest.h"

#include <string.h>

#define PUNCH_WAIT          10000 // ms: a bounded wait for the network to carry everything sent
#define PUNCH_BUDGET        64    // Punch messages one attempt of a punch may send, its probes and its answers
#define PUNCH_PORTS         12    // The birthday range above a predicted port
#define PUNCH_RATE          64    // Punch messages a node sends in any second at most
#define PUNCH_TICKS         40    // The most tick rounds a pair is given to meet
#define PUNCH_PAYLOAD_SIZE  42    // A punch message: version, sequence, type, a nonce and an echo of 16 bytes each
#define PUNCH_TICK          100   // ms between two ticks of the limits case, as the agent of a node ticks its peer layer
#define PUNCH_LIMIT_BUDGET  40    // The budget of an attempt of the limits case ...
#define PUNCH_LIMIT_RATE    32    // ... its rate, below the budget, so that one attempt spans two windows of the rate ...
#define PUNCH_LIMIT_TRIES   3     // ... its attempts before the backoff ...
#define PUNCH_LIMIT_RETRY   300   // ... the retry ...
#define PUNCH_LIMIT_BACKOFF 8000  // ... and the backoff (ms), longer than an attempt takes to fail
#define PUNCH_LIMIT_WAIT    15000 // ms that an attempt of the limits case is given to fail
#define PUNCH_TAP_MAX       1024  // Punch datagrams that the tap of the limits case keeps the times of, per node

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

// What the tap of the limits case saw: the times of the punch datagrams that A and B sent (ms of the performance counter)
typedef struct PUNCH_TAP {
	CRITICAL_SECTION Lock;
	NATSIM_HOST *Hosts[2];
	UINT Num[2];
	UINT64 Times[2][PUNCH_TAP_MAX];
} PUNCH_TAP;

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

// The configuration of the peer layer of A and B: punching on, the budget, the range and the rate of the test
static void punch_config(PEER_CONFIG *pc) {
	PeerDefaultConfig(pc);
	pc->Punch = true;
	pc->PunchBudget = PUNCH_BUDGET;
	pc->PunchPorts = PUNCH_PORTS;
	pc->PunchRate = PUNCH_RATE;
}

// Build the world: R and R2 on the public side with the relay role, A behind NatA and B behind NatB, both with the
// configuration pc. A's NAT maps and allocates by a_map/a_filter/a_alloc (and a_seed for a random one), B's by the b_
// parameters. Then the peers and the relays of every node, and the binds to R and R2.
static bool punch_world_start(PUNCH_WORLD *w, PEER_CONFIG *pc, UINT a_map, UINT a_filter, UINT a_alloc, UINT32 a_seed, UINT b_map, UINT b_filter, UINT b_alloc, UINT32 b_seed) {
	PEER_CONFIG rc;
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

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = punch_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 2, 3478);
	ok = punch_node(w, &w->R2, "r2", 161, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 10, 0, 0, 2, 5000);
	ok = punch_node(w, &w->A, "a", 1, w->NatA, &addr, pc) && ok;
	ok = punch_node(w, &w->B, "b", 33, w->NatB, &addr, pc) && ok;

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

// Bring the pair A and B up through the relay: an offer A to B and the answer B to A. Returns true when both signals
// were taken.
static bool punch_exchange(PUNCH_WORLD *w) {
	PEER_SIGNAL offer, answer;

	bool ok = punch_signal(&w->A, &w->B, PEER_SIGNAL_OFFER, &offer) == PEER_OK;
	ok = punch_signal(&w->B, &w->A, PEER_SIGNAL_ANSWER, &answer) == PEER_OK && ok;

	return NatSimWaitIdle(w->Sim, PUNCH_WAIT) && ok;
}

// The punch status of a node with a peer now
static UINT punch_state(PUNCH_NODE *from, PUNCH_NODE *to) {
	PEER_STATUS ps;

	PeerGetStatus(from->Agent, to->Key.Public, &ps);

	return ps.Punch;
}

// The punch of the control plane: a punch offer from x to y, which y takes, and y's punch answer to x when y took the
// offer and began its probes. The offer goes into offer and the answer into answer. Returns true when the offer was
// taken by y and its answer by x.
static bool punch_offer(PUNCH_WORLD *w, PUNCH_NODE *x, PUNCH_NODE *y, PEER_SIGNAL *offer, PEER_SIGNAL *answer) {
	ZeroMemory(answer, sizeof(PEER_SIGNAL));

	bool ok = punch_signal(x, y, PEER_SIGNAL_PUNCH_OFFER, offer) == PEER_OK && punch_state(y, x) == PEER_PUNCH_PROBING;
	ok = ok && punch_signal(y, x, PEER_SIGNAL_PUNCH_ANSWER, answer) == PEER_OK;

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

// Drive the punch every PUNCH_TICK ms, as the agent of a node does, until the attempt of A and the one of B both failed,
// within PUNCH_LIMIT_WAIT
static bool punch_exhaust(PUNCH_WORLD *w) {
	for (UINT64 end = GetTickCount64() + PUNCH_LIMIT_WAIT; GetTickCount64() < end; Sleep(PUNCH_TICK)) {
		PeerTick(w->A.Agent);
		PeerTick(w->B.Agent);
		NatSimWaitIdle(w->Sim, PUNCH_WAIT);

		if (punch_state(&w->A, &w->B) == PEER_PUNCH_FAILED && punch_state(&w->B, &w->A) == PEER_PUNCH_FAILED)
			return true;
	}

	return false;
}

static UINT64 punch_sent(PUNCH_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Sent;
}

static PEER_STATS punch_stats(PUNCH_NODE *n) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st;
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

// A probe of the node of key for the node of to, sealed as PeerPunchTick seals one (version 1, the sequence, type 1 for a
// probe, and two empty nonces) into env; returns its size. Its sequence is the wall clock in 100 ns units, as
// PeerNextSequence draws one, so it is above every sequence the sender sent before.
static UINT punch_seal_probe(PEER_KEY *key, const UCHAR *to, UCHAR *env, UINT max) {
	FILETIME ft;
	UCHAR probe[PUNCH_PAYLOAD_SIZE];

	GetSystemTimePreciseAsFileTime(&ft);
	UINT64 seq = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

	ZeroMemory(probe, sizeof(probe));
	probe[0] = 1;
	for (UINT i = 0; i < 8; i++)
		probe[1 + i] = (UCHAR)(seq >> (56 - 8 * i));
	probe[9] = 1;

	return PeerEnvelopeSeal(key, to, PEER_MSG_PUNCH, NULL, probe, sizeof(probe), env, max);
}

// A probe of B for A, sent from B's host to the address to, so it leaves through B's mapping towards to
static void punch_probe_from_b(PUNCH_WORLD *w, const PEER_ADDR *to) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = punch_seal_probe(&w->B.Key, w->A.Key.Public, env, sizeof(env));
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
	PEER_CONFIG pc;
	PEER_SIGNAL offer, answer;
	PEER_STATS st_a, st_b, st_r;
	PEER_STATUS ps_a, ps_b;
	PEER_ADDR predicted, next_a;
	PEER_ADDR mapped;

	punch_config(&pc);
	bool started = punch_world_start(&w, &pc, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0);
	coretest_check(started, "The network starts: R and R2 on the public side, A and B each behind a sequential-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(st_a.NumBound == 2 && st_b.NumBound == 2, "A and B each bind R and R2, so two reflexive observations let them learn their NAT's pattern");
	coretest_check(st_a.Nat == PEER_NAT_SEQUENTIAL && st_b.Nat == PEER_NAT_SEQUENTIAL,
	               "From the answers of their two binds, A and B each tell their NAT is symmetric and allocates in order");

	// The NAT of A made the mappings towards R and R2 on its first two ports: the next one is the third
	next_a = st_a.Predicted;
	coretest_check(NatSimMapped(w.NatA, &w.A.Addr, &mapped) && next_a.Port == mapped.Port + 1, "A predicts the port of its next mapping: one after the mapping towards R2");

	coretest_check(punch_exchange(&w), "A and B exchange an offer and an answer through the control plane, which brings them up through R");
	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(st_a.PunchAttempts == 0 && st_b.PunchAttempts == 0, "An offer and an answer begin no punch");

	// Relay-first: a datagram now, before any probe, goes through R
	bool sent = punch_send(&w.B, &w.A, "relayed first");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	coretest_check(sent && w.A.Received == 1 && w.A.ReceivedRelay == 1 && w.A.ReceivedDirect == 0, "Before the probes meet, the pair's traffic flows through R");

	// The punch offer and its answer begin the punch: its timing comes from the control plane
	ZeroMemory(&predicted, sizeof(predicted));
	bool offered = punch_offer(&w, &w.A, &w.B, &offer, &answer);
	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(offered && st_a.PunchAttempts == 1 && st_b.PunchAttempts == 1, "The punch begins only once the punch offer and its answer went: its timing comes from the control plane");
	coretest_check(punch_candidate(&offer, PEER_CANDIDATE_PREDICTED, &predicted) && PeerAddrEqual(&predicted, &next_a) && offer.Nat == PEER_NAT_SEQUENTIAL,
	               "A's punch offer names its NAT and the port of its next mapping");
	coretest_check(st_a.PunchProbes == 0 && st_b.PunchProbes == 0, "No probe went before the next tick");

	bool direct = punch_converge(&w);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps_a);
	PeerGetStatus(w.B.Agent, w.A.Key.Public, &ps_b);
	coretest_check(direct && ps_a.Punch == PEER_PUNCH_CONNECTED && ps_b.Punch == PEER_PUNCH_CONNECTED, "Port prediction gets the pair a direct path: the sweeps of the two ends cross");

	// Both ways on the direct path, with R forwarding nothing
	InterlockedExchange(&w.B.Echo, 1);
	LONG received = w.A.Received;
	LONG a_direct = w.A.ReceivedDirect;
	st_r = punch_stats(&w.R);
	UINT64 forwarded = st_r.Forwarded;
	sent = punch_send(&w.A, &w.B, "ping direct");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	st_r = punch_stats(&w.R);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedDirect == a_direct + 1 && st_r.Forwarded == forwarded, "A's ping and B's pong both take the direct path; R forwards neither");

	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_info("A sent %llu probes and B %llu", st_a.PunchProbes, st_b.PunchProbes);
	coretest_check(st_a.PunchSuccesses == 1 && st_b.PunchSuccesses == 1 && st_a.PunchAttempts == 1 && st_a.PunchFailures == 0 && st_b.PunchFailures == 0,
	               "Each end's prediction success rate is one of one, with no failure: the metric is exported");
	coretest_check(st_a.Upgrades == 1 && st_b.Upgrades == 1, "The move off the relay counts as an Upgrade at each end");
	coretest_check(st_a.PunchProbes <= PUNCH_BUDGET && st_b.PunchProbes <= PUNCH_BUDGET, "Each end sent no more than its budget of probes");
	coretest_check(st_a.DeliveredRelay >= 1 && st_a.Delivered > st_a.DeliveredRelay, "The direct-versus-relay split is a metric: A took its first datagram through R and its later one directly");

	// A late probe of B, from B's mapping towards A's address on the direct path: A takes it and stays on that pair
	UINT filtered = NatSimFiltered(w.NatA);
	UINT64 drops = punch_drops(&w.A);
	punch_probe_from_b(&w, &ps_b.Direct);
	coretest_check(NatSimFiltered(w.NatA) == filtered && punch_drops(&w.A) == drops, "A late probe of B, from B's mapping towards A's address on the direct path, reaches A, which takes it");

	received = w.A.Received;
	a_direct = w.A.ReceivedDirect;
	st_r = punch_stats(&w.R);
	forwarded = st_r.Forwarded;
	sent = punch_send(&w.A, &w.B, "ping after the late probe");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	st_r = punch_stats(&w.R);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedDirect == a_direct + 1 && st_r.Forwarded == forwarded, "After it, A's ping and B's pong still take the direct path, on the pair that met");

	// A probe of a node that is no peer of A: dropped and counted, unanswered
	PEER_KEY stranger;
	UCHAR env[PEER_MAX_ENVELOPE];
	PEER_ADDR from;
	coretest_fixed_key(&stranger, 97);
	PeerAddrSetV4(&from, 198, 51, 100, 77, 4000);
	UINT size = punch_seal_probe(&stranger, w.A.Key.Public, env, sizeof(env));
	UINT64 policy = punch_stats(&w.A).Drops[PEER_DROP_POLICY];
	UINT64 a_sent = punch_sent(&w.A);
	PeerInput(w.A.Agent, &from, env, size);
	coretest_check(size != 0 && punch_stats(&w.A).Drops[PEER_DROP_POLICY] == policy + 1 && punch_sent(&w.A) == a_sent,
	               "A probe of a node that is no peer is dropped and counted, and A answers it nothing");
	PeerKeyClose(&stranger);

	punch_world_stop(&w);
}

// A full-cone NAT and a random symmetric NAT: the pair meets by birthday punching
static void punch_birthday() {
	PUNCH_WORLD w;
	PEER_CONFIG pc;
	PEER_SIGNAL offer, answer;
	PEER_STATS st_a, st_b;

	punch_config(&pc);
	bool started = punch_world_start(&w, &pc, NATSIM_MAP_ENDPOINT_INDEPENDENT, NATSIM_FILTER_ENDPOINT_INDEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x51ED2C9B);
	coretest_check(started, "The network starts: A behind a full-cone NAT, B behind a random-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(st_a.Nat == PEER_NAT_CONE && st_b.Nat == PEER_NAT_RANDOM, "A tells its NAT is a cone, B that its NAT is symmetric and allocates at random");

	coretest_check(punch_exchange(&w), "A and B exchange an offer and an answer through the control plane");
	coretest_check(punch_offer(&w, &w.A, &w.B, &offer, &answer), "B takes A's punch offer, a random NAT with a cone, and answers it");

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
	UINT size = punch_seal_probe(&w.B.Key, w.A.Key.Public, env, sizeof(env));
	NatSimSend(m, &a_public, env, size);
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps);
	coretest_check(m != NULL && ps.Path == PEER_PATH_RELAY && ps.Punch == PEER_PUNCH_PROBING && punch_sent(&w.A) == a_sent + 1,
	               "A probe of B that an attacker sends from its own address moves A to no direct path there: A answers it once, sealed to B, and waits for the echo that only B can give");

	bool direct = punch_converge(&w);
	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	PeerGetStatus(w.A.Agent, w.B.Key.Public, &ps);
	coretest_check(direct && st_a.PunchSuccesses == 1 && st_b.PunchSuccesses == 1, "Birthday punching gets the pair a direct path within the probe budget: the random side reaches the cone's one port and the cone learns the random mapping");
	coretest_check(PeerAddrEqual(&ps.Direct, &attacker) == false && ps.Direct.Port != 0, "A's direct path to B is at B's own mapping, which proved itself with the echo of A's nonce, not at the attacker's address");

	// A probe of B sealed before A restarts is a replay at the new peer layer of A, which takes no sequence older than
	// its entry of B, while a fresh one is no replay: it is dropped as one of no open punch
	PEER_CONFIG pc2;
	PEER_INFO p;
	PEER_RELAY_INFO ri[2];
	PEER_ADDR from;
	UINT old_size = punch_seal_probe(&w.B.Key, w.A.Key.Public, env, sizeof(env));
	Sleep(2);
	PeerDefaultConfig(&pc2);
	pc2.Punch = true;
	PEER_AGENT *a2 = PeerNew(&w.A.Key, &pc2, punch_send_nowhere, NULL, NULL, NULL);
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

		PeerAddrSetV4(&from, 203, 0, 113, 20, 40000);
		PeerInput(a2, &from, env, old_size);
		PEER_STATS st;
		PeerGetStats(a2, &st);
		UINT64 replay = st.Drops[PEER_DROP_REPLAY];
		UINT64 forged = st.Drops[PEER_DROP_FORGED];

		UINT fresh_size = punch_seal_probe(&w.B.Key, w.A.Key.Public, fresh, sizeof(fresh));
		PeerInput(a2, &from, fresh, fresh_size);
		PeerGetStats(a2, &st);
		coretest_check(taken == PEER_OK && replay == 1 && st.Drops[PEER_DROP_REPLAY] == 1 && st.Drops[PEER_DROP_FORGED] == forged + 1,
		               "After A restarts, a probe of B from before the restart is a replay, and a fresh one is no replay but finds no punch open");
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

// Two random symmetric NATs: nothing is predictable, so neither end takes the punch and the pair stays on the relay
static void punch_random() {
	PUNCH_WORLD w;
	PEER_CONFIG pc;
	PEER_SIGNAL offer;
	PEER_STATS st_a, st_b;

	punch_config(&pc);
	bool started = punch_world_start(&w, &pc, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x1A2B3C4D,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_RANDOM, 0x7788AA55);
	coretest_check(started, "The network starts: A and B each behind a random-allocation symmetric NAT");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(st_a.Nat == PEER_NAT_RANDOM && st_b.Nat == PEER_NAT_RANDOM && st_a.Predicted.Port == 0, "A and B each tell their NAT allocates at random, whose next port they cannot predict");

	coretest_check(punch_exchange(&w), "A and B exchange an offer and an answer through the control plane");

	// The punch offer of A: B does not take it, as two random NATs predict nothing that the probes could aim at
	UINT taken = punch_signal(&w.A, &w.B, PEER_SIGNAL_PUNCH_OFFER, &offer);
	for (UINT i = 0; i < 4; i++) {
		PeerTick(w.A.Agent);
		PeerTick(w.B.Agent);
		NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	}
	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	coretest_check(taken == PEER_OK && offer.Nat == PEER_NAT_RANDOM && punch_state(&w.B, &w.A) == PEER_PUNCH_NONE && st_b.PunchAttempts == 0 && st_a.PunchAttempts == 0,
	               "B takes the signal but no punch: two random NATs cannot meet");
	coretest_check(st_a.PunchProbes == 0 && st_b.PunchProbes == 0, "No probe leaves either end");
	coretest_check(punch_path(&w.A, &w.B) == PEER_PATH_RELAY && punch_path(&w.B, &w.A) == PEER_PATH_RELAY, "The pair stays on the relay");

	// Traffic keeps flowing on the relay, with no interruption
	InterlockedExchange(&w.B.Echo, 1);
	LONG received = w.A.Received;
	bool sent = punch_send(&w.A, &w.B, "ping relayed");
	NatSimWaitIdle(w.Sim, PUNCH_WAIT);
	coretest_check(sent && w.A.Received == received + 1 && w.A.ReceivedRelay >= 1 && w.A.ReceivedDirect == 0, "The pair's ping and pong flow through R");

	punch_world_stop(&w);
}

// The tap of the limits case: the times of the punch datagrams that A and B send, before the cut loses them
static bool punch_tap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size) {
	PUNCH_TAP *t = (PUNCH_TAP *)param;
	LARGE_INTEGER now, freq;

	if (size == 0 || data[0] != PEER_MSG_PUNCH)
		return true;

	QueryPerformanceCounter(&now);
	QueryPerformanceFrequency(&freq);

	EnterCriticalSection(&t->Lock);
	for (UINT i = 0; i < 2; i++) {
		if (t->Hosts[i] == from && t->Num[i] < PUNCH_TAP_MAX)
			t->Times[i][t->Num[i]++] = (UINT64)now.QuadPart * 1000 / (UINT64)freq.QuadPart;
	}
	LeaveCriticalSection(&t->Lock);

	return true;
}

// The most punch datagrams of node i of the tap within any 1000 ms
static UINT punch_tap_peak(PUNCH_TAP *t, UINT i) {
	UINT peak = 0;

	EnterCriticalSection(&t->Lock);
	for (UINT k = 0; k < t->Num[i]; k++) {
		UINT n = 0;

		for (UINT j = k; j < t->Num[i] && t->Times[i][j] - t->Times[i][k] < 1000; j++)
			n++;
		if (n > peak)
			peak = n;
	}
	LeaveCriticalSection(&t->Lock);

	return peak;
}

// Two sequential NATs whose direct path is cut: the attempts spend their probes within the limits and fail, the pair
// stays on the relay, and after the attempts that met nothing an offer is refused until the backoff ends
static void punch_limits() {
	PUNCH_WORLD w;
	PUNCH_TAP tap;
	PEER_CONFIG pc;
	PEER_SIGNAL offer, answer;
	PEER_STATS st_a, st_b;
	char what[256];

	punch_config(&pc);
	pc.PunchBudget = PUNCH_LIMIT_BUDGET;
	pc.PunchRate = PUNCH_LIMIT_RATE;
	pc.PunchAttempts = PUNCH_LIMIT_TRIES;
	pc.PunchRetry = PUNCH_LIMIT_RETRY;
	pc.PunchBackoff = PUNCH_LIMIT_BACKOFF;

	bool started = punch_world_start(&w, &pc, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0);
	coretest_check(started, "The network starts: A and B each behind a sequential-allocation symmetric NAT, their direct path cut");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	ZeroMemory(&tap, sizeof(tap));
	InitializeCriticalSection(&tap.Lock);
	tap.Hosts[0] = w.A.Host;
	tap.Hosts[1] = w.B.Host;
	NatSimSetTap(w.Sim, punch_tap, &tap);
	NatSimCut(w.Sim, w.NatA, true);

	coretest_check(punch_exchange(&w), "A and B exchange an offer and an answer through the control plane");
	InterlockedExchange(&w.B.Echo, 1);

	bool all_failed = true;
	bool within_budget = true;
	bool relayed = true;
	UINT64 probes_a = 0, probes_b = 0;
	for (UINT k = 0; k < PUNCH_LIMIT_TRIES; k++) {
		bool offered = punch_offer(&w, &w.A, &w.B, &offer, &answer);
		bool failed = punch_exhaust(&w);

		st_a = punch_stats(&w.A);
		st_b = punch_stats(&w.B);
		coretest_info("attempt %u: A sent %llu probes and B %llu", k + 1, st_a.PunchProbes - probes_a, st_b.PunchProbes - probes_b);
		within_budget = within_budget && st_a.PunchProbes - probes_a <= PUNCH_LIMIT_BUDGET && st_b.PunchProbes - probes_b <= PUNCH_LIMIT_BUDGET &&
		                st_a.PunchProbes > probes_a && st_b.PunchProbes > probes_b;
		probes_a = st_a.PunchProbes;
		probes_b = st_b.PunchProbes;
		all_failed = all_failed && offered && failed;

		// The traffic of the pair goes on through R while the attempt fails
		LONG received = w.A.Received;
		bool sent = punch_send(&w.A, &w.B, "ping while the punch fails");
		NatSimWaitIdle(w.Sim, PUNCH_WAIT);
		relayed = relayed && sent && w.A.Received == received + 1 && w.A.ReceivedDirect == 0;

		Sleep(PUNCH_LIMIT_RETRY);
	}

	st_a = punch_stats(&w.A);
	st_b = punch_stats(&w.B);
	snprintf(what, sizeof(what), "Each of the %u attempts that a punch offer began at both ends spent its probes and failed, as the path between the NATs is cut", PUNCH_LIMIT_TRIES);
	coretest_check(all_failed && st_a.PunchAttempts == PUNCH_LIMIT_TRIES && st_b.PunchAttempts == PUNCH_LIMIT_TRIES && st_a.PunchFailures == PUNCH_LIMIT_TRIES && st_b.PunchFailures == PUNCH_LIMIT_TRIES &&
	                   st_a.PunchSuccesses == 0 && st_b.PunchSuccesses == 0,
	               what);
	snprintf(what, sizeof(what), "Each attempt sent at most its budget of %u probes", PUNCH_LIMIT_BUDGET);
	coretest_check(within_budget, what);

	UINT peak_a = punch_tap_peak(&tap, 0);
	UINT peak_b = punch_tap_peak(&tap, 1);
	coretest_info("the tap saw at most %u punch datagrams of A and %u of B within one second", peak_a, peak_b);
	snprintf(what, sizeof(what), "No node sent more than its rate of %u punch messages within any second", PUNCH_LIMIT_RATE);
	coretest_check(peak_a <= PUNCH_LIMIT_RATE && peak_b <= PUNCH_LIMIT_RATE && peak_a != 0, what);
	coretest_check(relayed && punch_path(&w.A, &w.B) == PEER_PATH_RELAY && punch_path(&w.B, &w.A) == PEER_PATH_RELAY,
	               "The pair stayed on the relay with its traffic flowing while the attempts failed");

	// After the attempts that met nothing, B refuses a punch offer until the backoff ends
	UINT taken = punch_signal(&w.A, &w.B, PEER_SIGNAL_PUNCH_OFFER, &offer);
	coretest_check(taken == PEER_OK && punch_state(&w.B, &w.A) != PEER_PUNCH_PROBING && punch_stats(&w.B).PunchAttempts == PUNCH_LIMIT_TRIES,
	               "In the backoff after the attempts that met nothing, B refuses the next punch offer: no probe begins");

	Sleep(PUNCH_LIMIT_BACKOFF);
	taken = punch_signal(&w.A, &w.B, PEER_SIGNAL_PUNCH_OFFER, &offer);
	coretest_check(taken == PEER_OK && punch_state(&w.B, &w.A) == PEER_PUNCH_PROBING && punch_stats(&w.B).PunchAttempts == PUNCH_LIMIT_TRIES + 1,
	               "Once the backoff ended, B takes the next punch offer");

	NatSimSetTap(w.Sim, NULL, NULL);
	punch_world_stop(&w);
	DeleteCriticalSection(&tap.Lock);
}

// Tick A alone every PUNCH_TICK ms until its attempt failed, within PUNCH_LIMIT_WAIT; true when the attempt of B, which is
// not ticked, still runs then
static bool punch_end_a(PUNCH_WORLD *w) {
	for (UINT64 end = GetTickCount64() + PUNCH_LIMIT_WAIT; GetTickCount64() < end; Sleep(PUNCH_TICK)) {
		PeerTick(w->A.Agent);
		NatSimWaitIdle(w->Sim, PUNCH_WAIT);

		if (punch_state(&w->A, &w->B) == PEER_PUNCH_FAILED)
			return punch_state(&w->B, &w->A) == PEER_PUNCH_PROBING;
	}

	return false;
}

// Two sequential NATs whose direct path is cut, where the attempts of B run longer than the ones of A: each punch offer of A,
// which comes once its own attempt ended, ends the attempt of B that still runs, as one that met nothing, and begins the next
// at both ends, so the two count the same attempts and reach the backoff on the same offer; the offer that B refuses in the
// backoff, while its last attempt still runs, gets no answer, so A begins no attempt alone
static void punch_overlap() {
	PUNCH_WORLD w;
	PEER_CONFIG pc;
	PEER_SIGNAL offer, answer;
	PEER_STATS st_a, st_b;
	UCHAR env[PEER_MAX_ENVELOPE];
	char what[256];

	punch_config(&pc);
	pc.PunchBudget = PUNCH_LIMIT_BUDGET;
	pc.PunchRate = PUNCH_LIMIT_RATE;
	pc.PunchAttempts = PUNCH_LIMIT_TRIES;
	pc.PunchRetry = PUNCH_LIMIT_RETRY;
	pc.PunchBackoff = PUNCH_LIMIT_BACKOFF;

	bool started = punch_world_start(&w, &pc, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0,
	                                 NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT, NATSIM_ALLOC_SEQUENTIAL, 0);
	coretest_check(started, "The network starts: A and B each behind a sequential-allocation symmetric NAT, their direct path cut, B's attempts slower than A's");
	if (started == false) {
		punch_world_stop(&w);
		return;
	}

	NatSimCut(w.Sim, w.NatA, true);
	coretest_check(punch_exchange(&w), "A and B exchange an offer and an answer through the control plane");

	// Each offer of A goes once its own attempt ended, while the one of B, which the test does not tick, still runs
	bool in_step = true;
	for (UINT k = 0; k < PUNCH_LIMIT_TRIES; k++) {
		bool offered = punch_offer(&w, &w.A, &w.B, &offer, &answer);

		st_a = punch_stats(&w.A);
		st_b = punch_stats(&w.B);
		coretest_info("offer %u: A made %llu attempts and B %llu, of which B ended %llu that still ran", k + 1, st_a.PunchAttempts, st_b.PunchAttempts, st_b.PunchFailures);
		bool ended = punch_end_a(&w);
		in_step = in_step && offered && st_a.PunchAttempts == k + 1 && st_b.PunchAttempts == k + 1 && st_b.PunchFailures == k && ended;
	}
	snprintf(what, sizeof(what), "Each of the %u punch offers of A ends the attempt of B that still runs, as one that met nothing, and begins the next at both ends: the two count the same attempts",
	         PUNCH_LIMIT_TRIES);
	coretest_check(in_step, what);

	// Both ends reached the backoff on the third offer: B refuses the next one and seals no answer to it, though its attempt
	// still runs
	UINT taken = punch_signal(&w.A, &w.B, PEER_SIGNAL_PUNCH_OFFER, &offer);
	st_b = punch_stats(&w.B);
	UINT sealed = PeerSealSignal(w.B.Agent, w.A.Key.Public, PEER_SIGNAL_PUNCH_ANSWER, env, sizeof(env));
	coretest_check(taken == PEER_OK && punch_state(&w.B, &w.A) == PEER_PUNCH_PROBING && st_b.PunchAttempts == PUNCH_LIMIT_TRIES && sealed == 0,
	               "In the backoff that both ends reached on the same offer, B refuses the next punch offer of A while its last attempt still runs, and seals no answer to it: A begins no attempt alone");

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

// The burst case of the review of PR 429 (CORE-H2-R1 #436): the messages that a node sends before the test hands them
// on, the probes of the burst, the port of the mapping of a node towards its first relay, and the payloads of a bind
// (the version and the sequence, then a cookie when it answers a challenge) and of a bound (the version, the sequence
// of the bind, and the address and the port that the relay saw the node at)
#define PUNCH_WIRE_MAX   8
#define PUNCH_BURST      5
#define PUNCH_WIRE_PORT  40000
#define PUNCH_BIND_SIZE  9
#define PUNCH_BOUND_SIZE 27

// A node of the burst case, where the test is the network and the relays: the messages that its peer layer sends wait in
// its outbox, each with the address it went to, until the test hands them on from the address of the node
typedef struct PUNCH_WIRE {
	PEER_KEY Key;                                  // Its static key
	PEER_ADDR Addr;                                // Its address, at which the other node sees it: its next mapping
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

// A node of the burst case with the key of the fixed scalar first behind a sequential NAT at 203.0.113.last, with
// punching on: its address is the mapping that comes after the two towards its relays, PUNCH_WIRE_PORT and the port
// after it. NULL when it does not start.
static PUNCH_WIRE *punch_wire_new(UCHAR first, UCHAR last) {
	PEER_CONFIG c;
	PUNCH_WIRE *n = (PUNCH_WIRE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PUNCH_WIRE));

	if (n == NULL)
		return NULL;

	PeerDefaultConfig(&c);
	c.Punch = true;
	coretest_fixed_key(&n->Key, first);
	PeerAddrSetV4(&n->Addr, 203, 0, 113, last, PUNCH_WIRE_PORT + 2);
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

// The two relays of the burst case, which the test plays, answer the binds of the node n that its outbox holds: the bind
// to the relay i draws a bound that names the address of n at the port PUNCH_WIRE_PORT + i, as a sequential NAT maps the
// node towards its two relays, so that the node tells its NAT. The outbox is emptied. Returns whether n got a bound from
// both.
static bool punch_wire_bound(PUNCH_WIRE *n, PEER_KEY *relays, const PEER_ADDR *addrs) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR bind[PEER_MAX_ENVELOPE];
	UCHAR bound[PUNCH_BOUND_SIZE];
	UCHAR env[PEER_MAX_ENVELOPE];
	UINT num = 0;

	for (UINT i = 0; i < n->Num; i++) {
		for (UINT r = 0; r < 2; r++) {
			UINT len = 0;

			if (PeerAddrEqual(&n->To[i], &addrs[r]) == false || PeerEnvelopeOpen(&relays[r], n->Data[i], n->Size[i], sender, bind, sizeof(bind), &len) == false ||
			    len < PUNCH_BIND_SIZE)
				continue;

			// The version and the sequence of the bind, then the address that the relay saw the node at
			USHORT port = (USHORT)(PUNCH_WIRE_PORT + r);
			bound[0] = 1;
			CopyMemory(bound + 1, bind + 1, 8);
			CopyMemory(bound + 9, n->Addr.Ip, sizeof(n->Addr.Ip));
			bound[25] = (UCHAR)(port >> 8);
			bound[26] = (UCHAR)port;

			UINT size = PeerEnvelopeSeal(&relays[r], n->Key.Public, PEER_MSG_BOUND, NULL, bound, sizeof(bound), env, sizeof(env));
			if (size != 0) {
				PeerInput(n->Agent, &addrs[r], env, size);
				num++;
			}
		}
	}

	n->Num = 0;

	return num == 2;
}

// The stand-in of the control plane of the burst case: from seals a signal of type for to, and to takes it. Returns what
// PeerOpenSignal returned, PEER_DROP_MALFORMED when nothing was sealed.
static UINT punch_wire_signal(PUNCH_WIRE *from, PUNCH_WIRE *to, UINT type) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(from->Agent, to->Key.Public, type, env, sizeof(env));

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
	PEER_KEY relays[2];
	PEER_ADDR addrs[2];
	PEER_RELAY_INFO ri[2];
	PEER_INFO p;
	PEER_STATS l_st, f_st;
	PEER_STATUS ls, fs;

	PUNCH_WIRE *x = punch_wire_new(1, 10);
	PUNCH_WIRE *y = punch_wire_new(33, 20);
	if (coretest_check(x != NULL && y != NULL, "Two nodes whose messages the test hands on start, with punching on") == false) {
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

	// The two relays, which the test plays: each node binds both, and their bounds tell it that its NAT is sequential
	coretest_fixed_key(&relays[0], 129);
	coretest_fixed_key(&relays[1], 161);
	PeerAddrSetV4(&addrs[0], 198, 51, 100, 1, 3478);
	PeerAddrSetV4(&addrs[1], 198, 51, 100, 2, 3478);
	for (UINT i = 0; i < 2; i++) {
		ZeroMemory(&ri[i], sizeof(PEER_RELAY_INFO));
		strcpy_s(ri[i].Name, sizeof(ri[i].Name), (i == 0 ? "r" : "r2"));
		CopyMemory(ri[i].Key, relays[i].Public, PEER_KEY_SIZE);
		ri[i].Addr = addrs[i];
	}
	PeerSetRelays(l->Agent, ri, 2);
	PeerSetRelays(f->Agent, ri, 2);
	bool bound = punch_wire_bound(l, relays, addrs);
	bound = punch_wire_bound(f, relays, addrs) && bound;
	PeerGetStats(l->Agent, &l_st);
	PeerGetStats(f->Agent, &f_st);
	coretest_check(bound && l_st.Nat == PEER_NAT_SEQUENTIAL && f_st.Nat == PEER_NAT_SEQUENTIAL,
	               "Each node binds the two relays that the test plays, whose bounds tell it that its NAT is sequential");

	// The punch offer of F and the punch answer of L begin the punch at both ends
	UINT taken = punch_wire_signal(f, l, PEER_SIGNAL_PUNCH_OFFER);
	taken = (taken == PEER_OK ? punch_wire_signal(l, f, PEER_SIGNAL_PUNCH_ANSWER) : taken);
	PeerGetStatus(l->Agent, f->Key.Public, &ls);
	PeerGetStatus(f->Agent, l->Key.Public, &fs);
	coretest_check(taken == PEER_OK && ls.Punch == PEER_PUNCH_PROBING && fs.Punch == PEER_PUNCH_PROBING && l->Num == 0 && f->Num == 0,
	               "The punch offer of F and the punch answer of L begin the punch at both ends, before any probe");

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
	PeerKeyClose(&relays[0]);
	PeerKeyClose(&relays[1]);
}

void punch_test() {
	// The case of the review of PR 429 (CORE-H2-R1 #436)
	punch_burst();
	punch_preserving();
	punch_sequential();
	punch_birthday();
	punch_random();
	punch_limits();
	punch_overlap();
}
