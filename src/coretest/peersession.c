// peersession.c
// Named test of the peer sessions of the data datagrams (src/Core/PeerSession.c; CORE-H2 #399), on the NAT simulator
// of natsim.c, as relay.c and punch.c run:
// peersession: the relay R on the public side and the nodes A and B, each behind a sequential-allocation symmetric NAT
//   with punching on, as in punch.c; C, G and H on the public side. A tap sees every datagram on every link.
//   - A packet from A reaches B through R, then, after the Upgrade that the punch makes, on the direct path, and back
//     through R after a Fallback, in one session: no byte of the inner packet is in the clear in any datagram.
//   - A record that is changed in any byte, replayed, or sent under the session of another node is dropped and
//     counted, each case on its own; so is a datagram of the old clear form, at the relay and at the node.
//   - G and H start their handshakes at the same time; the two end in one session that carries traffic both ways.
//   - G replaces the keys after a number of datagrams and on a schedule, with no datagram lost, and a session whose
//     peer is silent is dropped; the next datagram starts a new one.
//   - The timers of a session at a clock older than an initiation or keys of it, as a tick that read its clock before
//     another thread made them would see them, on two peer layers that hand their datagrams to each other: nothing is
//     sent again, dropped or replaced, and at their times the timers run (CORE-S5-6-R3 #574).
//   - The cost of the protection per datagram, measured on two peer layers that hand their datagrams to each other.
//   - The cases of the review of PR 429 (CORE-H2-R1 #436), on nodes whose datagrams the test hands on itself, in the
//     order that each case needs: the records under keys that the peer had not confirmed yet, which the peer's next
//     initiation overtakes, are taken; a response made from the clear header of an initiation leaves the handshake on
//     its way; and a peer whose clock is behind is a replay to a new entry for as long as its skew, and no longer.
// The control plane is stood in for by the test, which hands each signal from one node to the other.

#include "coretest.h"

#include "Core/Noise.h"

#include <string.h>

#define PS_WAIT      10000 // ms: a bounded wait for the network to carry everything sent
#define PS_TICKS     40    // The most tick rounds the punch of A and B is given to meet
#define PS_REKEY_N   50    // The records under one key of G and H
#define PS_REKEY_MS  400   // The rekey time of G and H
#define PS_TIMEOUT   1500  // ... the time after which a silent session is dropped
#define PS_KEEPALIVE 200   // ... and the time after which a record with no answer gets a keepalive
#define PS_FLOOD     500   // The datagrams of the rekey after a number of datagrams
#define PS_BENCH     20000 // The datagrams that the measurement of the cost sends
#define PS_WINDOW    6     // A run of this many bytes of the inner packet in a datagram counts as the packet in the clear

// The inner packet of A for B, which no link may carry in the clear
static const char ps_inner[] = "INNER PACKET of node A for node B: 10.20.30.40 -> 10.20.30.50, port 5353, ranz-ps-0123456789";

// One node of the test and what it received
typedef struct PS_NODE {
	const char *Name;             // Its name
	PEER_KEY Key;                 // Its static key
	PEER_ADDR Addr;               // Its address: private behind a NAT
	NATSIM_HOST *Host;            // Its host on the network
	PEER_AGENT *Agent;            // Its peer layer
	volatile LONG Received;       // Data datagrams delivered to it
	volatile LONG ReceivedRelay;  // ... of them through a relay
	volatile LONG ReceivedDirect; // ... of them on the direct path
	UINT LastSize;                // The size of the last one
	UCHAR Last[PEER_MAX_PAYLOAD]; // ... its payload
	UCHAR LastSrc[PEER_KEY_SIZE]; // ... and its source
} PS_NODE;

// What the tap saw on every link: the datagrams by kind, the ones that carried a run of the inner packet in the clear,
// and the last record of one host, which the test alters and sends again, and which the tap may withhold
typedef struct PS_TAP {
	CRITICAL_SECTION Lock;
	UINT Datagrams;                // Every datagram sent
	UINT Kinds[16];                // ... by its first byte
	UINT Clear;                    // ... of them with PS_WINDOW bytes of the inner packet in a row
	NATSIM_HOST *Keep;             // The host whose last record it keeps
	UINT KeptSize;                 // ... that record
	UCHAR Kept[PEER_MAX_DATAGRAM]; // ...
	bool Withhold;                 // The kept record is lost on the way: its receiver never takes it
} PS_TAP;

// The network of the test
typedef struct PS_WORLD {
	NATSIM *Sim;      // The network
	NATSIM_NAT *NatA; // A's NAT
	NATSIM_NAT *NatB; // B's NAT
	PS_NODE R, R2, A, B, C, G, H;
	PS_TAP Tap; // What the links carried
} PS_WORLD;

// Whether data holds PS_WINDOW bytes in a row of the inner packet
static bool ps_has_inner(const UCHAR *data, UINT size) {
	UINT inner = (UINT)sizeof(ps_inner) - 1;

	for (UINT i = 0; i + PS_WINDOW <= size; i++)
		for (UINT j = 0; j + PS_WINDOW <= inner; j++)
			if (data[i] == (UCHAR)ps_inner[j] && memcmp(data + i, ps_inner + j, PS_WINDOW) == 0)
				return true;

	return false;
}

static bool ps_tap(void *param, NATSIM_HOST *from, const PEER_ADDR *dst, const UCHAR *data, UINT size) {
	PS_TAP *t = (PS_TAP *)param;
	bool clear = ps_has_inner(data, size);
	bool pass = true;

	EnterCriticalSection(&t->Lock);
	t->Datagrams++;
	t->Kinds[data[0] & 15]++;
	if (clear)
		t->Clear++;
	if (from == t->Keep && data[0] == PEER_MSG_RECORD) {
		CopyMemory(t->Kept, data, size);
		t->KeptSize = size;
		pass = (t->Withhold == false);
	}
	LeaveCriticalSection(&t->Lock);

	return pass;
}

// The receive procedure of every node: keep the datagram and count it by its path
static void ps_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	PS_NODE *n = (PS_NODE *)param;

	n->LastSize = (size < sizeof(n->Last) ? size : (UINT)sizeof(n->Last));
	CopyMemory(n->Last, data, n->LastSize);
	CopyMemory(n->LastSrc, src, PEER_KEY_SIZE);

	if (path == PEER_PATH_RELAY)
		InterlockedIncrement(&n->ReceivedRelay);
	else
		InterlockedIncrement(&n->ReceivedDirect);
	InterlockedIncrement(&n->Received);
}

// A node of the world: its key from the fixed scalar first, its host behind nat (NULL: public) at addr, its peer
// layer with the configuration c
static bool ps_node(PS_WORLD *w, PS_NODE *n, const char *name, UCHAR first, NATSIM_NAT *nat, const PEER_ADDR *addr, PEER_CONFIG *c) {
	n->Name = name;
	n->Addr = *addr;
	coretest_fixed_key(&n->Key, first);
	n->Host = NatSimAddHost(w->Sim, nat, addr);
	if (n->Host == NULL)
		return false;

	n->Agent = PeerNew(&n->Key, c, NatSimSend, n->Host, ps_recv, n);
	NatSimAttach(n->Host, n->Agent);

	return n->Agent != NULL;
}

// A peer of the peer table: a node with the key key in VRF 10
static void ps_peer(PEER_INFO *p, PS_NODE *n) {
	ZeroMemory(p, sizeof(PEER_INFO));
	strcpy_s(p->Name, sizeof(p->Name), n->Name);
	CopyMemory(p->Key, n->Key.Public, PEER_KEY_SIZE);
	p->NumVrfs = 1;
	p->VrfIds[0] = 10;
}

static void ps_relay_info(PEER_RELAY_INFO *r, PS_NODE *relay) {
	ZeroMemory(r, sizeof(PEER_RELAY_INFO));
	strcpy_s(r->Name, sizeof(r->Name), relay->Name);
	CopyMemory(r->Key, relay->Key.Public, PEER_KEY_SIZE);
	r->Addr = relay->Addr;
}

// The stand-in of the control plane: an offer from one node to the other and the answer
static bool ps_pair(PS_WORLD *w, PS_NODE *x, PS_NODE *y) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(x->Agent, y->Key.Public, PEER_SIGNAL_OFFER, env, sizeof(env));
	bool ok = PeerOpenSignal(y->Agent, env, size, NULL) == PEER_OK;
	size = PeerSealSignal(y->Agent, x->Key.Public, PEER_SIGNAL_ANSWER, env, sizeof(env));
	ok = PeerOpenSignal(x->Agent, env, size, NULL) == PEER_OK && ok;

	return NatSimWaitIdle(w->Sim, PS_WAIT) && ok;
}

// The stand-in of the control plane times a punch: a punch offer from one node to the other and its punch answer, upon
// which both send their probes (PeerPunch.c)
static bool ps_punch(PS_WORLD *w, PS_NODE *x, PS_NODE *y) {
	UCHAR env[PEER_MAX_ENVELOPE];

	UINT size = PeerSealSignal(x->Agent, y->Key.Public, PEER_SIGNAL_PUNCH_OFFER, env, sizeof(env));
	bool ok = PeerOpenSignal(y->Agent, env, size, NULL) == PEER_OK;
	size = PeerSealSignal(y->Agent, x->Key.Public, PEER_SIGNAL_PUNCH_ANSWER, env, sizeof(env));
	ok = PeerOpenSignal(x->Agent, env, size, NULL) == PEER_OK && ok;

	return NatSimWaitIdle(w->Sim, PS_WAIT) && ok;
}

// Build the world: R and R2 with the relay role (R2 the second reflexive vantage point of the punch); A and B behind
// sequential symmetric NATs with punching on; C, G and H public, G and H with the short timers of the rekey checks.
// Every node is a peer of R and R2; B has the peers A and C; G and H are peers of each other.
static bool ps_world_start(PS_WORLD *w) {
	PEER_CONFIG rc, pc, gc;
	PEER_ADDR addr;
	PEER_INFO p[6];
	PEER_RELAY_INFO ri[2];
	bool ok = true;

	ZeroMemory(w, sizeof(PS_WORLD));
	InitializeCriticalSection(&w->Tap.Lock);
	w->Sim = NatSimNew();
	if (w->Sim == NULL)
		return false;

	w->NatA = NatSimAddNat(w->Sim, 203, 0, 113, 10, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);
	w->NatB = NatSimAddNat(w->Sim, 203, 0, 113, 20, NATSIM_MAP_ADDRESS_PORT_DEPENDENT, NATSIM_FILTER_ADDRESS_PORT_DEPENDENT);

	PeerDefaultConfig(&rc);
	rc.Relay = true;
	PeerDefaultConfig(&pc);
	pc.Punch = true;
	pc.PunchBudget = 64;
	PeerDefaultConfig(&gc);
	gc.SessionRekeyDatagrams = PS_REKEY_N;
	gc.SessionRekeyTime = PS_REKEY_MS;
	gc.SessionTimeout = PS_TIMEOUT;
	gc.SessionKeepalive = PS_KEEPALIVE;

	PeerAddrSetV4(&addr, 198, 51, 100, 1, 3478);
	ok = ps_node(w, &w->R, "r", 129, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 2, 3478);
	ok = ps_node(w, &w->R2, "r2", 161, NULL, &addr, &rc) && ok;
	PeerAddrSetV4(&addr, 10, 0, 0, 2, 5000);
	ok = ps_node(w, &w->A, "a", 1, w->NatA, &addr, &pc) && ok;
	ok = ps_node(w, &w->B, "b", 33, w->NatB, &addr, &pc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 3, 4000);
	ok = ps_node(w, &w->C, "c", 65, NULL, &addr, NULL) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 7, 5000);
	ok = ps_node(w, &w->G, "g", 225, NULL, &addr, &gc) && ok;
	PeerAddrSetV4(&addr, 198, 51, 100, 8, 5000);
	ok = ps_node(w, &w->H, "h", 17, NULL, &addr, &gc) && ok;

	if (ok == false)
		return false;

	ps_peer(&p[0], &w->A);
	ps_peer(&p[1], &w->B);
	ps_peer(&p[2], &w->C);
	ps_peer(&p[3], &w->G);
	ps_peer(&p[4], &w->H);
	PeerSetPeers(w->R.Agent, p, 5);
	PeerSetPeers(w->R2.Agent, p, 5);

	ps_peer(&p[0], &w->B);
	PeerSetPeers(w->A.Agent, p, 1);
	ps_peer(&p[0], &w->A);
	ps_peer(&p[1], &w->C);
	PeerSetPeers(w->B.Agent, p, 2);
	ps_peer(&p[0], &w->B);
	PeerSetPeers(w->C.Agent, p, 1);
	ps_peer(&p[0], &w->H);
	PeerSetPeers(w->G.Agent, p, 1);
	ps_peer(&p[0], &w->G);
	PeerSetPeers(w->H.Agent, p, 1);

	ps_relay_info(&ri[0], &w->R);
	ps_relay_info(&ri[1], &w->R2);
	PS_NODE *nodes[] = {&w->A, &w->B, &w->C, &w->G, &w->H};
	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		PeerSetHostCandidates(nodes[i]->Agent, &nodes[i]->Addr, 1);
		PeerSetRelays(nodes[i]->Agent, ri, 2);
	}

	return NatSimWaitIdle(w->Sim, PS_WAIT);
}

// Stop the network first, so that no datagram reaches a freed peer layer
static void ps_world_stop(PS_WORLD *w) {
	PS_NODE *nodes[] = {&w->R, &w->R2, &w->A, &w->B, &w->C, &w->G, &w->H};

	NatSimFree(w->Sim);
	w->Sim = NULL;

	for (UINT i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
		PeerFree(nodes[i]->Agent);
		nodes[i]->Agent = NULL;
		PeerKeyClose(&nodes[i]->Key);
	}

	DeleteCriticalSection(&w->Tap.Lock);
}

static PEER_STATUS ps_status(PS_NODE *from, PS_NODE *to) {
	PEER_STATUS ps;

	PeerGetStatus(from->Agent, to->Key.Public, &ps);

	return ps;
}

// The sum of the drops of a node, every reason
static UINT64 ps_drops(PS_NODE *n) {
	PEER_STATS st;
	UINT64 sum = 0;

	PeerGetStats(n->Agent, &st);
	for (UINT r = PEER_DROP_MALFORMED; r < PEER_NUM_REASONS; r++)
		sum += st.Drops[r];

	return sum;
}

static UINT64 ps_drop(PS_NODE *n, UINT reason) {
	PEER_STATS st;

	PeerGetStats(n->Agent, &st);

	return st.Drops[reason];
}

// Send the inner packet from A to B; true when B got it, whole, from A
static bool ps_send_inner(PS_WORLD *w) {
	LONG received = w->B.Received;

	bool sent = PeerSend(w->A.Agent, w->B.Key.Public, ps_inner, (UINT)sizeof(ps_inner) - 1);
	NatSimWaitIdle(w->Sim, PS_WAIT);

	return sent && w->B.Received == received + 1 && w->B.LastSize == sizeof(ps_inner) - 1 && memcmp(w->B.Last, ps_inner, sizeof(ps_inner) - 1) == 0 &&
	       memcmp(w->B.LastSrc, w->A.Key.Public, PEER_KEY_SIZE) == 0;
}

// Drive the punch of A and B until both are on the direct path
static bool ps_converge(PS_WORLD *w) {
	for (UINT i = 0; i < PS_TICKS; i++) {
		PeerTick(w->A.Agent);
		PeerTick(w->B.Agent);
		NatSimWaitIdle(w->Sim, PS_WAIT);

		if (ps_status(&w->A, &w->B).Path == PEER_PATH_DIRECT && ps_status(&w->B, &w->A).Path == PEER_PATH_DIRECT)
			return true;
	}

	return false;
}

// The inner packet through R, on the direct path after the Upgrade, and through R again after a Fallback, in one
// session, with no byte of it in the clear on any link
static void ps_capture(PS_WORLD *w) {
	coretest_check(ps_pair(w, &w->A, &w->B), "A and B exchange one signal each through the control plane");

	NatSimSetTap(w->Sim, ps_tap, &w->Tap);

	bool relayed = ps_send_inner(w);
	PEER_STATUS before = ps_status(&w->A, &w->B);
	PEER_STATUS b_side = ps_status(&w->B, &w->A);
	coretest_check(relayed && w->B.ReceivedRelay == 1 && before.Path == PEER_PATH_RELAY && before.Session == PEER_SESSION_UP,
	               "A's packet reaches B through R, in the peer session that it started");
	coretest_check(memcmp(before.SessionId, b_side.SessionId, PEER_SESSION_ID_SIZE) == 0 && before.Handshakes == 1 && b_side.Handshakes == 1,
	               "A and B hold the same session: one handshake, the same id at both ends");

	bool direct = ps_punch(w, &w->A, &w->B) && ps_converge(w);
	bool upgraded = ps_send_inner(w);
	PEER_STATUS after = ps_status(&w->A, &w->B);
	coretest_check(direct && upgraded && w->B.ReceivedDirect == 1 && after.Path == PEER_PATH_DIRECT,
	               "After the Upgrade that the punch made, A's packet reaches B on the direct path");
	coretest_check(memcmp(before.SessionId, after.SessionId, PEER_SESSION_ID_SIZE) == 0 && after.Handshakes == 1,
	               "The Upgrade keeps the session: it belongs to the pair of nodes, not to the path");

	// The Fallback: the direct path goes, and the pair is back on R
	PeerSetDirect(w->A.Agent, w->B.Key.Public, NULL);
	PeerSetDirect(w->B.Agent, w->A.Key.Public, NULL);
	bool fell_back = ps_send_inner(w);
	PEER_STATUS back = ps_status(&w->A, &w->B);
	coretest_check(fell_back && w->B.ReceivedRelay == 2 && back.Path == PEER_PATH_RELAY && memcmp(back.SessionId, before.SessionId, PEER_SESSION_ID_SIZE) == 0 &&
	                   back.Handshakes == 1,
	               "After a Fallback to R the packet goes on in the same session");

	NatSimSetTap(w->Sim, NULL, NULL);

	EnterCriticalSection(&w->Tap.Lock);
	UINT datagrams = w->Tap.Datagrams;
	UINT clear = w->Tap.Clear;
	UINT records = w->Tap.Kinds[PEER_MSG_RECORD];
	UINT inits = w->Tap.Kinds[PEER_MSG_INIT];
	UINT responses = w->Tap.Kinds[PEER_MSG_RESPONSE];
	UINT plain = w->Tap.Kinds[PEER_MSG_DATA];
	LeaveCriticalSection(&w->Tap.Lock);

	coretest_info("the tap saw %u datagrams on the links: %u records, %u initiations, %u responses", datagrams, records, inits, responses);
	coretest_check(datagrams != 0 && records >= 5 && inits == 2 && responses == 2 && plain == 0,
	               "The datagrams between A and B are one handshake, which R forwarded, and records; none is of the old clear form");
	coretest_check(clear == 0, "No datagram on any link carries 6 bytes in a row of the inner packet: no byte of it is in the clear");
}

// A record changed in any byte, the same record again, and records under another node's session are dropped and
// counted; so is a datagram of the old clear form
static void ps_tamper(PS_WORLD *w) {
	UCHAR rec[PEER_MAX_DATAGRAM];
	UCHAR alt[PEER_MAX_DATAGRAM];

	// A record from A to B, which the tap keeps as it leaves A and withholds from B: B has not taken its counter, so a
	// copy with a changed byte of the ciphertext or the tag is no replay and goes to the decryption
	UINT len = (UINT)sizeof(ps_inner) - 1;
	LONG received = w->B.Received;
	w->Tap.Keep = w->A.Host;
	w->Tap.KeptSize = 0;
	w->Tap.Withhold = true;
	NatSimSetTap(w->Sim, ps_tap, &w->Tap);
	bool sent = PeerSend(w->A.Agent, w->B.Key.Public, ps_inner, len);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	NatSimSetTap(w->Sim, NULL, NULL);
	w->Tap.Withhold = false;
	UINT size = w->Tap.KeptSize;
	CopyMemory(rec, w->Tap.Kept, size);
	coretest_check(sent && size == PEER_RECORD_HEADER + len + PEER_RECORD_TAG && w->B.Received == received,
	               "The tap keeps a record of A for B as it leaves A, and withholds it from B");

	// Every byte changed, one at a time, as from R
	UINT64 drops = ps_drops(&w->B);
	UINT64 forged = ps_drop(&w->B, PEER_DROP_FORGED);
	for (UINT i = 0; i < size; i++) {
		CopyMemory(alt, rec, size);
		alt[i] ^= 0x01;
		PeerInput(w->B.Agent, &w->R.Addr, alt, size);
	}
	coretest_info("of the %u altered records, B refused %llu as forged", size, ps_drop(&w->B, PEER_DROP_FORGED) - forged);
	coretest_check(w->B.Received == received && ps_drops(&w->B) == drops + size && ps_drop(&w->B, PEER_DROP_FORGED) - forged >= sizeof(ps_inner) - 1 + PEER_RECORD_TAG,
	               "A record changed in any one byte is dropped and counted, each one: every byte of the ciphertext and the tag fails the decryption");

	// The record as A sealed it, after all its altered copies: none of them moved the window of B
	PeerInput(w->B.Agent, &w->R.Addr, rec, size);
	coretest_check(w->B.Received == received + 1 && w->B.LastSize == len && memcmp(w->B.Last, ps_inner, len) == 0 && memcmp(w->B.LastSrc, w->A.Key.Public, PEER_KEY_SIZE) == 0,
	               "The record itself, after its altered copies, is taken and delivered");

	// The same record again
	received = w->B.Received;
	UINT64 replay = ps_drop(&w->B, PEER_DROP_REPLAY);
	PeerInput(w->B.Agent, &w->R.Addr, rec, size);
	coretest_check(w->B.Received == received && ps_drop(&w->B, PEER_DROP_REPLAY) == replay + 1, "The same record again is a replay: dropped and counted");

	// Under the session of another node: A's record in C's name, and C's record in A's name
	bool c_paired = ps_pair(w, &w->C, &w->B);
	bool c_sent = c_paired && PeerSend(w->C.Agent, w->B.Key.Public, "from c", 6);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	received = w->B.Received;
	UINT64 session = ps_drop(&w->B, PEER_DROP_SESSION);
	CopyMemory(alt, rec, size);
	CopyMemory(alt + 1, w->C.Key.Public, PEER_KEY_SIZE);
	PeerInput(w->B.Agent, &w->R.Addr, alt, size);
	coretest_check(c_sent && ps_status(&w->B, &w->C).Session == PEER_SESSION_UP && w->B.Received == received && ps_drop(&w->B, PEER_DROP_SESSION) == session + 1,
	               "A's record sent in the name of C, which has a session with B, is dropped and counted: its index names no keys of C's");

	w->Tap.Keep = w->C.Host;
	w->Tap.KeptSize = 0;
	NatSimSetTap(w->Sim, ps_tap, &w->Tap);
	PeerSend(w->C.Agent, w->B.Key.Public, "from c again", 12);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	NatSimSetTap(w->Sim, NULL, NULL);
	UINT c_size = w->Tap.KeptSize;
	CopyMemory(alt, w->Tap.Kept, c_size);
	CopyMemory(alt + 1, w->A.Key.Public, PEER_KEY_SIZE);
	received = w->B.Received;
	PeerInput(w->B.Agent, &w->R.Addr, alt, c_size);
	coretest_check(c_size != 0 && w->B.Received == received && ps_drop(&w->B, PEER_DROP_SESSION) == session + 2,
	               "C's record sent in the name of A is dropped and counted as well: a record is taken only under the session of its source");

	// The old clear form: a data datagram of A for B with the inner packet in the clear, through R and at B
	ZeroMemory(alt, PEER_DATA_HEADER_SIZE);
	alt[0] = PEER_MSG_DATA;
	CopyMemory(alt + 1, w->A.Key.Public, PEER_KEY_SIZE);
	CopyMemory(alt + 1 + PEER_KEY_SIZE, w->B.Key.Public, PEER_KEY_SIZE);
	CopyMemory(alt + PEER_DATA_HEADER_SIZE, ps_inner, len);
	UINT64 r_clear = ps_drop(&w->R, PEER_DROP_CLEAR);
	UINT64 b_clear = ps_drop(&w->B, PEER_DROP_CLEAR);
	PEER_STATS st;
	PeerGetStats(w->R.Agent, &st);
	UINT64 forwarded = st.Forwarded;
	NatSimSend(w->A.Host, &w->R.Addr, alt, PEER_DATA_HEADER_SIZE + len);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PeerInput(w->B.Agent, &w->R.Addr, alt, PEER_DATA_HEADER_SIZE + len);
	PeerGetStats(w->R.Agent, &st);
	coretest_check(ps_drop(&w->R, PEER_DROP_CLEAR) == r_clear + 1 && st.Forwarded == forwarded, "R drops a datagram of the old clear form and counts it: it forwards none");
	coretest_check(ps_drop(&w->B, PEER_DROP_CLEAR) == b_clear + 1 && w->B.Received == received, "B drops one too and counts it: there is no downgrade to the clear");
}

// G and H start their handshakes at the same time: one session, traffic both ways
static void ps_simultaneous(PS_WORLD *w) {
	coretest_check(ps_pair(w, &w->G, &w->H), "G and H exchange one signal each through the control plane");

	// Both send before either initiation is on its way, so the two cross
	NatSimHold(w->Sim, true);
	bool g_sent = PeerSend(w->G.Agent, w->H.Key.Public, "g first", 7);
	bool h_sent = PeerSend(w->H.Agent, w->G.Key.Public, "h first", 7);
	PEER_STATUS g_wait = ps_status(&w->G, &w->H);
	PEER_STATUS h_wait = ps_status(&w->H, &w->G);
	NatSimHold(w->Sim, false);
	NatSimWaitIdle(w->Sim, PS_WAIT);

	PEER_STATUS g = ps_status(&w->G, &w->H);
	PEER_STATUS h = ps_status(&w->H, &w->G);
	coretest_check(g_sent && h_sent && g_wait.Session == PEER_SESSION_HANDSHAKE && h_wait.Session == PEER_SESSION_HANDSHAKE,
	               "G and H each start a handshake with the other at the same time");
	coretest_check(g.Session == PEER_SESSION_UP && h.Session == PEER_SESSION_UP && memcmp(g.SessionId, h.SessionId, PEER_SESSION_ID_SIZE) == 0 &&
	                   g.Handshakes == 1 && h.Handshakes == 1,
	               "The two handshakes end in one session: one completed handshake at each end, with the same id");
	coretest_check(w->H.Received == 1 && memcmp(w->H.Last, "g first", 7) == 0 && w->G.Received == 1 && memcmp(w->G.Last, "h first", 7) == 0,
	               "Each datagram that waited for the handshake arrives");

	bool sent = PeerSend(w->G.Agent, w->H.Key.Public, "g again", 7) && PeerSend(w->H.Agent, w->G.Key.Public, "h again", 7);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PEER_STATUS g2 = ps_status(&w->G, &w->H);
	coretest_check(sent && w->H.Received == 2 && w->G.Received == 2 && memcmp(g2.SessionId, g.SessionId, PEER_SESSION_ID_SIZE) == 0,
	               "The one session carries traffic both ways");
}

// G replaces the keys after a number of datagrams and on a schedule without a datagram lost; a silent session is dropped
static void ps_rekey(PS_WORLD *w) {
	char text[32];

	PEER_STATUS start = ps_status(&w->G, &w->H);
	LONG received = w->H.Received;
	UINT sent = 0;
	for (UINT i = 0; i < PS_FLOOD; i++) {
		snprintf(text, sizeof(text), "flood %u", i);
		if (PeerSend(w->G.Agent, w->H.Key.Public, text, (UINT)strlen(text)))
			sent++;

		// The network keeps up, so each rekey's response comes back within a few datagrams of its initiation
		if (i % 10 == 9)
			NatSimWaitIdle(w->Sim, PS_WAIT);
	}
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PEER_STATUS flooded = ps_status(&w->G, &w->H);
	PEER_STATUS h_side = ps_status(&w->H, &w->G);
	coretest_info("G sent %u datagrams with a rekey every %u: %llu handshakes with H in all", sent, PS_REKEY_N, flooded.Handshakes);
	coretest_check(sent == PS_FLOOD && w->H.Received == received + PS_FLOOD, "Not one of the datagrams went missing through the rekeys");
	coretest_check(flooded.Handshakes >= start.Handshakes + PS_FLOOD / PS_REKEY_N / 2 && memcmp(flooded.SessionId, start.SessionId, PEER_SESSION_ID_SIZE) != 0 &&
	                   memcmp(flooded.SessionId, h_side.SessionId, PEER_SESSION_ID_SIZE) == 0,
	               "The keys were replaced after the configured number of datagrams, again and again, and both ends hold the same ones");

	// On the schedule: past the rekey time, the tick of the initiator of the keys replaces them
	Sleep(PS_REKEY_MS + 100);
	PeerTick(w->G.Agent);
	PeerTick(w->H.Agent);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	received = w->H.Received;
	sent = 0;
	for (UINT i = 0; i < 20; i++) {
		snprintf(text, sizeof(text), "after %u", i);
		if (PeerSend(w->G.Agent, w->H.Key.Public, text, (UINT)strlen(text)))
			sent++;
	}
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PEER_STATUS timed = ps_status(&w->G, &w->H);
	coretest_check(timed.Handshakes > flooded.Handshakes && memcmp(timed.SessionId, flooded.SessionId, PEER_SESSION_ID_SIZE) != 0 && sent == 20 &&
	                   w->H.Received == received + 20,
	               "Past the rekey time the keys are replaced on the tick, and the traffic goes on with no datagram lost");

	// Silent: past the timeout with no record, both ends drop the session; the next datagram starts a new one
	Sleep(PS_TIMEOUT + 200);
	PeerTick(w->G.Agent);
	PeerTick(w->H.Agent);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PEER_STATUS g_silent = ps_status(&w->G, &w->H);
	PEER_STATUS h_silent = ps_status(&w->H, &w->G);
	coretest_check(g_silent.Session == PEER_SESSION_NONE && h_silent.Session == PEER_SESSION_NONE, "A session whose other end is silent past the timeout is dropped at both ends");

	received = w->H.Received;
	bool again = PeerSend(w->G.Agent, w->H.Key.Public, "new session", 11);
	NatSimWaitIdle(w->Sim, PS_WAIT);
	PEER_STATUS renewed = ps_status(&w->G, &w->H);
	coretest_check(again && w->H.Received == received + 1 && renewed.Session == PEER_SESSION_UP && renewed.Handshakes == timed.Handshakes + 1,
	               "The next datagram starts a new session and arrives");
}

// Two peer layers that hand their datagrams to each other at once, on the direct path, for the measurement
typedef struct PS_LINK {
	PEER_AGENT *To; // The peer layer that the datagrams go to
	PEER_ADDR From; // The address they come from
} PS_LINK;

static bool ps_link_send(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	PS_LINK *l = (PS_LINK *)param;

	PeerInput(l->To, &l->From, (const UCHAR *)data, size);

	return true;
}

static void ps_bench_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	InterlockedIncrement((volatile LONG *)param);
}

// The timers of a session at a clock older than the times that they compare it with, as a tick that read its clock before
// another thread sent an initiation or made keys would see them (CORE-S5-6-R3 #574), on two peer layers that hand their
// datagrams to each other as for the measurement: X's initiation does not go again before PEER_SESSION_RETRY, the keys of
// X and Y are neither dropped nor replaced and no keepalive goes, and at their times the timers run. X's first initiation
// is lost: Y drops it, as X is no peer of Y yet.
static void ps_clock() {
	PEER_KEY kx, ky;
	PS_LINK lx, ly;
	PEER_INFO p;
	PEER_ADDR ax, ay;
	PEER_STATUS sx, sy;
	PEER_STATS st;
	volatile LONG got = 0;

	coretest_fixed_key(&kx, 1);
	coretest_fixed_key(&ky, 33);
	PeerAddrSetV4(&ax, 198, 51, 100, 23, 5000);
	PeerAddrSetV4(&ay, 198, 51, 100, 24, 5000);
	ZeroMemory(&lx, sizeof(lx));
	ZeroMemory(&ly, sizeof(ly));
	lx.From = ax;
	ly.From = ay;

	PEER_AGENT *x = PeerNew(&kx, NULL, ps_link_send, &lx, ps_bench_recv, (void *)&got);
	PEER_AGENT *y = PeerNew(&ky, NULL, ps_link_send, &ly, ps_bench_recv, (void *)&got);
	if (coretest_check(x != NULL && y != NULL, "X and Y, two peer layers that hand their datagrams to each other, start") == false) {
		PeerFree(x);
		PeerFree(y);
		PeerKeyClose(&kx);
		PeerKeyClose(&ky);
		return;
	}

	lx.To = y;
	ly.To = x;
	ZeroMemory(&p, sizeof(p));
	strcpy_s(p.Name, sizeof(p.Name), "y");
	CopyMemory(p.Key, ky.Public, PEER_KEY_SIZE);
	p.NumVrfs = 1;
	p.VrfIds[0] = 10;
	PeerSetPeers(x, &p, 1);
	PeerSetDirect(x, ky.Public, &ay);

	// X's first datagram waits for the handshake, whose initiation is lost
	ULONGLONG t0 = GetTickCount64();
	bool queued = PeerSend(x, ky.Public, "first", 5);
	ULONGLONG t1 = GetTickCount64();
	PeerGetStats(x, &st);
	UINT64 first = st.Sent;

	// A tick at a clock that the initiation was sent after, as one that read its clock before PeerSend wrote the initiation
	// would, then one 1 ms short of PEER_SESSION_RETRY after the initiation
	PeerSessionTickAt(x, t0 - 1);
	PeerGetStats(x, &st);
	UINT64 older = st.Sent;
	PeerSessionTickAt(x, t0 + PEER_SESSION_RETRY - 1);
	PeerGetStats(x, &st);
	PeerGetStatus(x, ky.Public, &sx);
	coretest_check(queued && first == 1 && older == 1 && st.Sent == 1 && sx.Session == PEER_SESSION_HANDSHAKE,
	               "A tick of X at a clock that its initiation was sent after, as when the tick read its clock before PeerSend wrote the initiation, does not send the initiation again, nor does one 1 ms short of PEER_SESSION_RETRY after it");

	// Y knows X now: PEER_SESSION_RETRY after the initiation the tick sends it again, and Y answers
	strcpy_s(p.Name, sizeof(p.Name), "x");
	CopyMemory(p.Key, kx.Public, PEER_KEY_SIZE);
	PeerSetPeers(y, &p, 1);
	PeerSetDirect(y, kx.Public, &ax);
	ULONGLONG t2 = GetTickCount64();
	PeerSessionTickAt(x, t1 + PEER_SESSION_RETRY);
	ULONGLONG t3 = GetTickCount64();
	PeerGetStatus(x, ky.Public, &sx);
	coretest_check(got == 1 && sx.Session == PEER_SESSION_UP && sx.Handshakes == 1,
	               "PEER_SESSION_RETRY after the initiation the tick of X sends it again: Y answers, and the datagram that waited arrives");

	// Ticks at a clock older than the keys, as ticks that read their clocks before the handshake made the keys would: Y
	// took a record with a payload and sent none, so only the order of the clocks keeps its keepalive back
	PeerGetStats(x, &st);
	UINT64 x_sent = st.Sent;
	PeerGetStats(y, &st);
	UINT64 y_sent = st.Sent;
	PeerSessionTickAt(x, t2 - 1);
	PeerSessionTickAt(y, t2 - 1);
	PeerGetStatus(x, ky.Public, &sx);
	PeerGetStatus(y, kx.Public, &sy);
	PeerGetStats(x, &st);
	bool x_quiet = (st.Sent == x_sent);
	PeerGetStats(y, &st);
	coretest_check(x_quiet && st.Sent == y_sent && sx.Session == PEER_SESSION_UP && sy.Session == PEER_SESSION_UP && sx.Handshakes == 1 && sy.Handshakes == 1,
	               "Ticks of X and Y at a clock older than their keys, as when the ticks read their clocks before the handshake made the keys, neither drop nor replace the keys, and send nothing");

	// Y sent X no record: X keeps the keys 1 ms short of PEER_DEFAULT_SESSION_TIMEOUT after the handshake, and drops them
	// at it
	PeerSessionTickAt(x, t2 + PEER_DEFAULT_SESSION_TIMEOUT - 1);
	PeerGetStatus(x, ky.Public, &sx);
	bool kept = (sx.Session == PEER_SESSION_UP);
	PeerSessionTickAt(x, t3 + PEER_DEFAULT_SESSION_TIMEOUT);
	PeerGetStatus(x, ky.Public, &sx);
	coretest_check(kept && sx.Session == PEER_SESSION_NONE,
	               "Y sent X no record: the tick of X keeps the keys 1 ms short of PEER_DEFAULT_SESSION_TIMEOUT after the handshake, and drops them at it");

	PeerFree(x);
	PeerFree(y);
	PeerKeyClose(&kx);
	PeerKeyClose(&ky);
}

// The cost of the protection per datagram: a record sealed, handed over and opened, of 1400 bytes
static void ps_bench() {
	PEER_KEY kx, ky;
	PS_LINK lx, ly;
	PEER_INFO p;
	PEER_ADDR ax, ay;
	UCHAR payload[1400];
	volatile LONG got = 0;
	LARGE_INTEGER freq, t0, t1;

	coretest_fixed_key(&kx, 1);
	coretest_fixed_key(&ky, 33);
	PeerAddrSetV4(&ax, 198, 51, 100, 21, 5000);
	PeerAddrSetV4(&ay, 198, 51, 100, 22, 5000);
	ZeroMemory(&lx, sizeof(lx));
	ZeroMemory(&ly, sizeof(ly));
	lx.From = ax;
	ly.From = ay;

	PEER_AGENT *x = PeerNew(&kx, NULL, ps_link_send, &lx, ps_bench_recv, (void *)&got);
	PEER_AGENT *y = PeerNew(&ky, NULL, ps_link_send, &ly, ps_bench_recv, (void *)&got);
	if (coretest_check(x != NULL && y != NULL, "Two peer layers for the measurement start") == false) {
		PeerFree(x);
		PeerFree(y);
		return;
	}

	lx.To = y;
	ly.To = x;
	ZeroMemory(&p, sizeof(p));
	strcpy_s(p.Name, sizeof(p.Name), "y");
	CopyMemory(p.Key, ky.Public, PEER_KEY_SIZE);
	p.NumVrfs = 1;
	p.VrfIds[0] = 10;
	PeerSetPeers(x, &p, 1);
	strcpy_s(p.Name, sizeof(p.Name), "x");
	CopyMemory(p.Key, kx.Public, PEER_KEY_SIZE);
	PeerSetPeers(y, &p, 1);
	PeerSetDirect(x, ky.Public, &ay);
	PeerSetDirect(y, kx.Public, &ax);

	for (UINT i = 0; i < sizeof(payload); i++)
		payload[i] = (UCHAR)i;

	// The first datagram makes the session
	PeerSend(x, ky.Public, payload, sizeof(payload));

	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&t0);
	for (UINT i = 0; i < PS_BENCH; i++)
		PeerSend(x, ky.Public, payload, sizeof(payload));
	QueryPerformanceCounter(&t1);

	double ns = (double)(t1.QuadPart - t0.QuadPart) * 1e9 / (double)freq.QuadPart / PS_BENCH;
	coretest_info("the peer session costs %.0f ns per datagram of %u bytes: sealed, handed over and opened on one thread", ns, (UINT)sizeof(payload));
	coretest_check(got == PS_BENCH + 1, "Every datagram of the measurement arrived");

	PeerFree(x);
	PeerFree(y);
	PeerKeyClose(&kx);
	PeerKeyClose(&ky);
}

// The wire cases of the review of PR 429 (CORE-H2-R1 #436): the datagrams that a node sends before the test hands them
// on, the prologue of the handshake of a peer session (PeerSession.c), and the clock of a peer that is behind: by how
// many ms, and how long the case waits beyond them
#define PS_WIRE_MAX    8
#define PS_PROLOGUE    "ranz peer session 1"
#define PS_SKEW        400
#define PS_SKEW_MARGIN 100

// A node of the wire cases, where the test is the network: what its peer layer sends waits in its outbox, and the test
// hands each datagram on, from the address of the node, in the order that the case needs
typedef struct PS_WIRE {
	PEER_KEY Key;                               // Its static key
	PEER_ADDR Addr;                             // Its address
	PEER_AGENT *Agent;                          // Its peer layer
	UINT Num;                                   // The datagrams in its outbox
	UINT Size[PS_WIRE_MAX];                     // ... their sizes
	UCHAR Data[PS_WIRE_MAX][PEER_MAX_DATAGRAM]; // ... and their bytes
	UINT Received;                              // Data datagrams delivered to it
	UINT LastSize;                              // ... the size of the last one
	UCHAR Last[PEER_MAX_PAYLOAD];               // ... and its payload
} PS_WIRE;

// The send procedure of a node of the wire cases: the datagram goes into its outbox
static bool ps_wire_send(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	PS_WIRE *n = (PS_WIRE *)param;

	if (n->Num == PS_WIRE_MAX || size > PEER_MAX_DATAGRAM)
		return false;

	CopyMemory(n->Data[n->Num], data, size);
	n->Size[n->Num] = size;
	n->Num++;

	return true;
}

// The receive procedure of a node of the wire cases: keep the datagram
static void ps_wire_recv(PEER_AGENT *a, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	PS_WIRE *n = (PS_WIRE *)param;

	n->LastSize = (size < sizeof(n->Last) ? size : (UINT)sizeof(n->Last));
	CopyMemory(n->Last, data, n->LastSize);
	n->Received++;
}

static void ps_wire_free(PS_WIRE *n) {
	if (n == NULL)
		return;

	PeerFree(n->Agent);
	PeerKeyClose(&n->Key);
	HeapFree(GetProcessHeap(), 0, n);
}

// A node of the wire cases with the key of the fixed scalar first, at 198.51.100.last port 5000, and its peer layer with
// the configuration c (NULL for the defaults); NULL when it does not start
static PS_WIRE *ps_wire_new(UCHAR first, UCHAR last, PEER_CONFIG *c) {
	PS_WIRE *n = (PS_WIRE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_WIRE));

	if (n == NULL)
		return NULL;

	coretest_fixed_key(&n->Key, first);
	PeerAddrSetV4(&n->Addr, 198, 51, 100, last, 5000);
	n->Agent = PeerNew(&n->Key, c, ps_wire_send, n, ps_wire_recv, n);
	if (n->Agent == NULL) {
		ps_wire_free(n);
		return NULL;
	}

	return n;
}

// Make x and y peers of each other in VRF 10, each on a direct path to the address of the other, set by hand
static void ps_wire_pair(PS_WIRE *x, PS_WIRE *y) {
	PEER_INFO p;

	ZeroMemory(&p, sizeof(p));
	p.NumVrfs = 1;
	p.VrfIds[0] = 10;
	CopyMemory(p.Key, y->Key.Public, PEER_KEY_SIZE);
	PeerSetPeers(x->Agent, &p, 1);
	CopyMemory(p.Key, x->Key.Public, PEER_KEY_SIZE);
	PeerSetPeers(y->Agent, &p, 1);

	PeerSetDirect(x->Agent, y->Key.Public, &y->Addr);
	PeerSetDirect(y->Agent, x->Key.Public, &x->Addr);
}

// Hand the datagram i of the outbox of from to the node to, from the address of from
static void ps_wire_hand(PS_WIRE *from, UINT i, PS_WIRE *to) {
	if (i < from->Num)
		PeerInput(to->Agent, &from->Addr, from->Data[i], from->Size[i]);
}

// The drops of a peer layer for one reason
static UINT64 ps_agent_drop(PEER_AGENT *a, UINT reason) {
	PEER_STATS st;

	PeerGetStats(a, &st);

	return st.Drops[reason];
}

// Records under keys that the peer had not confirmed yet, which the peer's next initiation overtakes on the way, are
// taken: the responder keeps those keys as the keys before (finding 1)
static void ps_unconfirmed() {
	PEER_CONFIG c;
	PEER_STATUS sx, sy;

	// X replaces its keys after every two records
	PeerDefaultConfig(&c);
	c.SessionRekeyDatagrams = 2;
	PS_WIRE *x = ps_wire_new(1, 31, &c);
	PS_WIRE *y = ps_wire_new(33, 32, NULL);
	if (coretest_check(x != NULL && y != NULL, "X and Y, whose datagrams the test hands on, start") == false) {
		ps_wire_free(x);
		ps_wire_free(y);
		return;
	}
	ps_wire_pair(x, y);

	// X's first datagram waits for the handshake, and Y answers the initiation with keys that X has sent nothing under
	// yet. The response releases X's datagram under them, and X's second datagram makes them due: a rekey follows it.
	bool first = PeerSend(x->Agent, y->Key.Public, "first", 5);
	ps_wire_hand(x, 0, y);
	ps_wire_hand(y, 0, x);
	bool second = PeerSend(x->Agent, y->Key.Public, "second", 6);
	coretest_check(first && second && x->Num == 4 && x->Data[1][0] == PEER_MSG_RECORD && x->Data[2][0] == PEER_MSG_RECORD && x->Data[3][0] == PEER_MSG_INIT,
	               "X sends two records under the keys of the first handshake, then the initiation of a rekey");

	// The initiation of the rekey overtakes the two records on the way
	UINT64 session = ps_agent_drop(y->Agent, PEER_DROP_SESSION);
	ps_wire_hand(x, 3, y);
	ps_wire_hand(x, 1, y);
	ps_wire_hand(x, 2, y);
	coretest_check(y->Received == 2 && y->LastSize == 6 && memcmp(y->Last, "second", 6) == 0 && ps_agent_drop(y->Agent, PEER_DROP_SESSION) == session,
	               "Y takes the two records after the initiation that overtook them: the keys that X had sent no record under yet stay as the keys before");

	// The response of the rekey, X's keepalive under the new keys, and its next record
	ps_wire_hand(y, 1, x);
	ps_wire_hand(x, 4, y);
	bool third = PeerSend(x->Agent, y->Key.Public, "third", 5);
	ps_wire_hand(x, 5, y);
	PeerGetStatus(x->Agent, y->Key.Public, &sx);
	PeerGetStatus(y->Agent, x->Key.Public, &sy);
	coretest_check(third && y->Received == 3 && sx.Handshakes == 2 && sy.Handshakes == 2 && memcmp(sx.SessionId, sy.SessionId, PEER_SESSION_ID_SIZE) == 0,
	               "The rekey completes: both ends hold the keys of the second handshake, and X's next record arrives under them");

	ps_wire_free(x);
	ps_wire_free(y);
}

// A response made from the clear header of an initiation, with its index, does not open: it is dropped and counted,
// and the handshake stays on its way, so the peer's own response completes it after (finding 2)
static void ps_forged_response() {
	UCHAR forged[PEER_MAX_DATAGRAM];
	PEER_STATUS st;

	PS_WIRE *x = ps_wire_new(1, 33, NULL);
	PS_WIRE *y = ps_wire_new(33, 34, NULL);
	if (coretest_check(x != NULL && y != NULL, "X and Y, whose datagrams the test hands on, start") == false) {
		ps_wire_free(x);
		ps_wire_free(y);
		return;
	}
	ps_wire_pair(x, y);

	// X's datagram waits for the handshake, and Y answers X's initiation
	bool queued = PeerSend(x->Agent, y->Key.Public, "waits", 5);
	ps_wire_hand(x, 0, y);

	// An attacker that saw the initiation makes a response of its clear header: the kind, Y's key and X's, an index of
	// its own and the index of X's initiation, then random bytes, as long as a response. It reaches X first.
	UINT size = y->Size[0];
	bool made = (queued && y->Num == 1 && size > PEER_DATA_HEADER_SIZE + 8 && size <= sizeof(forged));
	ZeroMemory(forged, sizeof(forged));
	if (made) {
		made = CryptoRandom(forged + PEER_DATA_HEADER_SIZE, size - PEER_DATA_HEADER_SIZE);
		forged[0] = PEER_MSG_RESPONSE;
		CopyMemory(forged + 1, y->Key.Public, PEER_KEY_SIZE);
		CopyMemory(forged + 1 + PEER_KEY_SIZE, x->Key.Public, PEER_KEY_SIZE);
		CopyMemory(forged + PEER_DATA_HEADER_SIZE + 4, x->Data[0] + PEER_DATA_HEADER_SIZE, 4);
	}
	UINT64 drops = ps_agent_drop(x->Agent, PEER_DROP_FORGED);
	if (made)
		PeerInput(x->Agent, &y->Addr, forged, size);
	PeerGetStatus(x->Agent, y->Key.Public, &st);
	coretest_check(made && ps_agent_drop(x->Agent, PEER_DROP_FORGED) == drops + 1 && st.Session == PEER_SESSION_HANDSHAKE && x->Num == 1,
	               "A response that an attacker makes from the clear header of X's initiation is dropped and counted as forged: X's handshake stays on its way");

	// Y's own response completes the handshake after it, and X's datagram that waited arrives
	ps_wire_hand(y, 0, x);
	ps_wire_hand(x, 1, y);
	PeerGetStatus(x->Agent, y->Key.Public, &st);
	coretest_check(st.Session == PEER_SESSION_UP && st.Handshakes == 1 && y->Received == 1 && y->LastSize == 5 && memcmp(y->Last, "waits", 5) == 0,
	               "Y's own response completes the handshake after the forged one, and X's datagram that waited for it arrives");

	ps_wire_free(x);
	ps_wire_free(y);
}

// The wall clock in 100 ns units, which the sequences of the peer layer follow (PeerWallClock)
static UINT64 ps_wall_clock() {
	FILETIME ft;

	GetSystemTimePreciseAsFileTime(&ft);

	return ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

// v big-endian at p, as the payloads of the peer layer carry a sequence
static void ps_put64(UCHAR *p, UINT64 v) {
	for (UINT i = 0; i < 8; i++)
		p[i] = (UCHAR)(v >> (56 - 8 * i));
}

// A signal of the node of the key k for the node of the public key to, with the sequence seq and no relay or candidate,
// sealed as PeerSealSignal seals one. Returns the size of the envelope in buf.
static UINT ps_signal_at(PEER_KEY *k, const UCHAR *to, UINT64 seq, UCHAR *buf, UINT max) {
	PEER_SIGNAL s;
	UCHAR payload[PEER_MAX_ENVELOPE];

	ZeroMemory(&s, sizeof(s));
	s.Type = PEER_SIGNAL_OFFER;
	s.Sequence = seq;

	UINT len = PeerSignalEncode(&s, payload, sizeof(payload));

	return (len != 0 ? PeerEnvelopeSeal(k, to, PEER_MSG_SIGNAL, NULL, payload, len, buf, max) : 0);
}

// A first bind of the node of the key k to the relay of the public key to, with the sequence seq, as PeerBind seals one:
// the version (1) and the sequence, with no cookie. Returns the size of the envelope in buf.
static UINT ps_bind_at(PEER_KEY *k, const UCHAR *to, UINT64 seq, UCHAR *buf, UINT max) {
	UCHAR payload[9];

	payload[0] = 1;
	ps_put64(payload + 1, seq);

	return PeerEnvelopeSeal(k, to, PEER_MSG_BIND, NULL, payload, sizeof(payload), buf, max);
}

// An initiation of the node of the key k to the node of the public key to, with the timestamp ts, as
// PeerSessionWriteInit writes one: the kind, the two keys and the sender's index, then the first message of Noise_IK
// with the prologue of the peer sessions, whose payload is the timestamp and the index again. Returns its size in buf,
// 0 when a step failed.
static UINT ps_init_at(PEER_KEY *k, const UCHAR *to, UINT64 ts, UCHAR *buf, UINT max) {
	static const UCHAR sender[4] = {0x5E, 0x55, 0x10, 0x01};
	NOISE_HANDSHAKE hs;
	UCHAR payload[12];
	UINT header = PEER_DATA_HEADER_SIZE + (UINT)sizeof(sender);
	UINT len = 0;

	if (max <= header)
		return 0;

	ps_put64(payload, ts);
	CopyMemory(payload + 8, sender, sizeof(sender));

	bool ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, true, PS_PROLOGUE, (UINT)sizeof(PS_PROLOGUE) - 1, k->Private, NULL, to) &&
	          NoiseHandshakeWrite(&hs, payload, sizeof(payload), buf + header, max - header, &len);
	NoiseHandshakeFree(&hs);
	if (ok == false)
		return 0;

	buf[0] = PEER_MSG_INIT;
	CopyMemory(buf + 1, k->Public, PEER_KEY_SIZE);
	CopyMemory(buf + 1 + PEER_KEY_SIZE, to, PEER_KEY_SIZE);
	CopyMemory(buf + PEER_DATA_HEADER_SIZE, sender, sizeof(sender));

	return header + len;
}

// S's clock in the skew case: the wall clock of N, PS_SKEW ms behind
static UINT64 ps_skew_clock() {
	return ps_wall_clock() - (UINT64)PS_SKEW * 10000;
}

// A peer whose clock is behind is a replay to a new entry for as long as its skew, and no longer: its signal, its bind
// and its initiation, sealed by that clock right after the receiver made its entry of the peer, are refused, as what a
// right clock sealed before the entry is (coretest relaypolicy and punch), and the ones that it seals once its clock
// passed the time of the entry are taken. The floor tolerates no skew, which would take the sequences of before a
// restart or a new entry again; finding 3 is accepted with this bound.
static void ps_skew() {
	PEER_KEY ks;
	PEER_CONFIG c;
	PEER_INFO p;
	PEER_ADDR from;
	PEER_STATS st;
	UCHAR buf[PEER_MAX_DATAGRAM];
	char what[256];

	// N, with the relay role so that it takes binds, and S, whose datagrams the test seals itself
	PeerDefaultConfig(&c);
	c.Relay = true;
	PS_WIRE *n = ps_wire_new(129, 35, &c);
	coretest_fixed_key(&ks, 65);
	PeerAddrSetV4(&from, 198, 51, 100, 36, 5000);
	if (coretest_check(n != NULL, "N, with the relay role, starts") == false) {
		PeerKeyClose(&ks);
		return;
	}

	// N makes its entry of S now, with a direct path to S's address
	ZeroMemory(&p, sizeof(p));
	CopyMemory(p.Key, ks.Public, PEER_KEY_SIZE);
	p.NumVrfs = 1;
	p.VrfIds[0] = 10;
	PeerSetPeers(n->Agent, &p, 1);
	PeerSetDirect(n->Agent, ks.Public, &from);

	// Right after the entry, S's clock has not reached the time of it
	UINT64 behind = ps_skew_clock();
	UINT size = ps_signal_at(&ks, n->Key.Public, behind, buf, sizeof(buf));
	UINT signal = PeerOpenSignal(n->Agent, buf, size, NULL);
	size = ps_bind_at(&ks, n->Key.Public, behind + 1, buf, sizeof(buf));
	PeerInput(n->Agent, &from, buf, size);
	size = ps_init_at(&ks, n->Key.Public, behind + 2, buf, sizeof(buf));
	PeerInput(n->Agent, &from, buf, size);
	PeerGetStats(n->Agent, &st);
	snprintf(what, sizeof(what), "Right after N made its entry of S, the signal, the bind and the initiation that S seals by its clock, %u ms behind N's, are replays to that entry",
	         PS_SKEW);
	coretest_check(signal == PEER_DROP_REPLAY && st.Drops[PEER_DROP_REPLAY] == 3 && st.Signals == 0 && st.Challenges == 0 && st.Handshakes == 0 && n->Num == 0, what);

	// Once S's clock passed the time of the entry, PS_SKEW ms after it at most, what S seals is taken
	Sleep(PS_SKEW + PS_SKEW_MARGIN);
	behind = ps_skew_clock();
	size = ps_signal_at(&ks, n->Key.Public, behind, buf, sizeof(buf));
	signal = PeerOpenSignal(n->Agent, buf, size, NULL);
	size = ps_bind_at(&ks, n->Key.Public, behind + 1, buf, sizeof(buf));
	PeerInput(n->Agent, &from, buf, size);
	size = ps_init_at(&ks, n->Key.Public, behind + 2, buf, sizeof(buf));
	PeerInput(n->Agent, &from, buf, size);
	PeerGetStats(n->Agent, &st);
	snprintf(what, sizeof(what), "... and %u ms later, once S's clock passed the time of the entry, they are taken: the bind draws a bind challenge and the initiation a response",
	         PS_SKEW + PS_SKEW_MARGIN);
	coretest_check(signal == PEER_OK && st.Signals == 1 && st.Challenges == 1 && st.Handshakes == 1 && st.Drops[PEER_DROP_REPLAY] == 3 && n->Num == 2, what);

	// The sequence that grows still refuses the same one again
	size = ps_signal_at(&ks, n->Key.Public, behind, buf, sizeof(buf));
	signal = PeerOpenSignal(n->Agent, buf, size, NULL);
	coretest_check(signal == PEER_DROP_REPLAY, "A signal of S with the sequence of its last one again is a replay");

	ps_wire_free(n);
	PeerKeyClose(&ks);
}

void peersession_test() {
	PS_WORLD w;

	bool started = ps_world_start(&w);
	coretest_check(started, "The network starts: R and R2 on the public side, A and B each behind a sequential symmetric NAT, C, G and H on the public side");
	if (started) {
		ps_capture(&w);
		ps_tamper(&w);
		ps_simultaneous(&w);
		ps_rekey(&w);
	}
	ps_world_stop(&w);

	ps_clock();

	ps_bench();

	// The cases of the review of PR 429 (CORE-H2-R1 #436)
	ps_unconfirmed();
	ps_forged_response();
	ps_skew();
}
