// PeerPunch.c
// Port prediction and birthday-paradox hole punching for symmetric NAT (ADR-0015 decision 2; CORE-S5-4, #266; CORE-S5-7,
// #413). ICE (PeerIce.c, libjuice) gets a direct path through cone NATs; it cannot through a symmetric NAT, whose mapping
// gives a new public port per destination. This is Ranz's own code on top of the candidates the control plane already
// exchanges: it runs on the peer layer's own socket, not libjuice, so the simulated NATs of the harness carry it.
//
// The NAT. A node tells its NAT from the answers of the binds to its first two relays, which it binds both with punching
// on (PeerPunchModel): the same port at both is one mapping for every destination, a cone; ports a small step apart in the
// order of the node's mappings are a sequential symmetric NAT, whose next port can be predicted; ports far apart, or two
// public addresses, a random one, whose next port cannot. To know the order of its mappings, the node counts the
// destinations that can make a NAT allocate one (PeerPunchDestination): the relays it binds, the addresses that its ICE
// sessions check and the addresses that its punches probe, each new one a mapping more. Its predicted next port is the
// port of the newer of the two observations, plus the step for each mapping since. The other subscribers of a
// carrier-grade NAT take ports that the node cannot count, so the punch aims at a range of ports around the prediction.
//
// The timing. ICE runs first. When the ICE session of a pair on the relay failed and the node offers the pair, it asks the
// peer for a punch with a punch offer, a signal that carries its NAT and its prediction (PeerPunchDue,
// PeerPunchSealSignal), which the control plane carries. The peer takes it when one of the two NATs is symmetric and the
// pair can meet (PeerPunchPair): it begins its probes at once and answers with a punch answer of its own, upon which the
// node begins its probes. So each end aims at the prediction that the other made just before its own probes began. The
// peer answers only an offer that began an attempt, and an offer that finds an attempt of the peer still running ends
// that one and begins the next: the node offers only once its own attempt ended, so nothing answers the probes of the
// old one any more. So the two ends begin every attempt together and count the same attempts and the same backoff.
//
// The probes. Each probe to a new address makes a new mapping of a symmetric NAT, on the next port. The node of the
// lower static key leads and sweeps the range of the peer's ports one by one, from PEER_PUNCH_BELOW under the predicted
// port; the other end sweeps the range of the leader's ports in steps of two. When the next port of the leader is k
// ports off its prediction and the one of the other end j ports off, both from -PEER_PUNCH_BELOW to under PunchPorts,
// the probe number 2j + k + 3 * PEER_PUNCH_BELOW of the leader and the probe number j + k + 2 * PEER_PUNCH_BELOW of the
// other end, counted from 0, go between the same two mappings: whichever of the two goes second passes the NAT that the
// first one made its mapping in, and the pair meets. A node behind a cone sweeps the range of the peer one by one, around
// the port of the peer's mapping towards it when the peer names one, and a node whose peer sits behind a cone probes its
// one port. A probe both opens the sender's own mapping towards that address and, when it arrives, proves to the peer
// who sent it. Two random NATs predict nothing, so their pair takes no punch.
//
// The limits, so that the probes do not look like a scan. An attempt sends PunchBudget punch messages at most, its probes
// and its answers to the messages of the peer together. Its probes go round robin over its targets and leave
// PEER_PUNCH_ANSWERS of the budget to the answers; an answer that finds the budget spent does not go. So neither the peer
// nor an attacker that sends captured probes of the peer from addresses of its own makes the node send more. The attempt
// fails PEER_PUNCH_LINGER after its last probe, or after its last response to a challenge, when nothing met. The node
// sends PunchRate punch messages in any second at most, probes and answers together, across its peers, and only the first
// proof of a meeting goes when the rate is spent, as the other end waits for it. The next attempt waits PunchRetry from
// the end of the one before, so that the attempt of the peer, which began a little earlier, ended too. After
// PunchAttempts attempts in a row that met nothing, the pair stays on the relay for PunchBackoff from the end of the last
// one, and a punch offer that comes meanwhile is refused. The node counts the attempts, the successes and the failures,
// which its control stream reports.
//
// The proof. A probe proves who sent it, not where the sender is: an attacker on the path can send a captured probe
// from an address of its own (finding F3 of the second review of AUD-5, PR 405). So a meeting moves the peer to the
// direct path only at an address that proved it, by an exchange of nonces sealed to the peer (CORE-H2 #399). Of the two
// ends, the one with the lower static key leads: it answers a probe from an address with a challenge, a fresh nonce
// sealed to the peer and sent to that address; the other end answers a probe with a probe, so that the leader gets one.
// The other end answers the challenge, from the address the challenge reached it at, with a response that echoes the
// nonce and carries a nonce of its own; the leader takes the response only from the address its nonce went to, moves the
// peer to the direct path there, and sends a proof that echoes the second nonce, which moves the other end to the direct
// path at the address that proof came from, the one its own nonce went to. Only the peer can read a nonce, and it can
// echo one only from where the nonce reached it, so a probe that names an address the peer does not own sets no path.
// A proof can be lost on the way, which would leave the other end on the relay while the leader sends on the direct
// path. So the other end says from the direct path with a keepalive that it moved there, and the leader sends the proof
// again every PEER_PUNCH_PROOF_RETRY until it hears that or a record of the peer session from there, PEER_PUNCH_PROOFS
// proofs in all; the other end answers a proof that comes after its move with a keepalive too. The other end keeps its
// attempt open PEER_PUNCH_LINGER after its response, so that a proof sent again finds it.
// Each end moves once, on the one exchange that completed, so the two ends use the same pair of mappings; the relay
// carries the traffic of the pair until then, so nothing is interrupted. A punch message of a node that is no peer, or
// of a peer with no punch open, is dropped and counted.
//
// The punched path. Each end sends a keepalive there every quarter of PunchConsent, which keeps the mappings of the two
// NATs open, and takes a word of the peer from there as its consent: a punch message, which the peer sealed, or a record
// of the peer session that opened (PeerPunchHeard). A datagram that only names the peer as its source is no word of it,
// as anyone can send one from that address. When the peer said nothing there for PunchConsent, the pair falls back to the
// relay with its peer session, a Fallback, as when consent freshness fails a path of ICE.
//
// Locks: PeerPunchStart, PeerPunchInput and PeerPunchTick take the lock of the layer to read and change the punch of
// a peer; they seal and send the punch messages without it, as the rest of the layer does. PunchLock, which comes after
// the lock of the layer, holds the destinations of the node and the times of its punch messages.

#include "Core/PeerInternal.h"

#include <string.h>

// The payload of a punch message: PEER_VERSION, the sequence, the type, a nonce and the echo of the peer's nonce
#define PEER_PUNCH_PAYLOAD_SIZE  (10 + 2 * PEER_PUNCH_NONCE_SIZE)
#define PEER_PUNCH_SEQ_THRESHOLD 16   // The largest step of the ports from one mapping to the next still read as a sequential NAT
#define PEER_PUNCH_TICK_MAX      64   // The most punch messages one PeerTick gathers across all the peers it is punching
#define PEER_PUNCH_BELOW         4    // Ports under a predicted one that the range covers, for a step that came out too large
#define PEER_PUNCH_LINGER        2000 // ms that an attempt whose budget is spent waits for the answers on their way
#define PEER_PUNCH_ANSWERS       8    // Punch messages of the rate that the probes leave to the answers and the keepalives, and of the budget of an attempt to its answers
#define PEER_PUNCH_WINDOW        1500 // ms over which the rate counts: a second, and the time that sealing a burst may take
#define PEER_PUNCH_PROOFS        8    // The most proofs of a meeting that the leader sends, until the other end says that it moved
#define PEER_PUNCH_PROOF_RETRY   200  // ms between two of them

// The types of a punch message
#define PEER_PUNCH_PROBE     1 // A probe to a predicted address
#define PEER_PUNCH_CHALLENGE 2 // The leader's answer to a probe: a nonce
#define PEER_PUNCH_RESPONSE  3 // The other end's answer: the echo of that nonce and a nonce of its own
#define PEER_PUNCH_PROOF     4 // The leader's answer: the echo of the second nonce
#define PEER_PUNCH_KEEPALIVE 5 // On the punched path: the sender is there, which keeps the mappings of the NATs open

// What the node knows of its NAT, from the answers of the binds to its first two relays
typedef struct PEER_PUNCH_MODEL {
	UINT Nat;       // PEER_NAT_*
	PEER_ADDR Base; // The newer of the two observations: the address and port that its relay saw the node at
	UINT Mapping;   // ... the number of the node's mapping towards that relay
	UINT Step;      // The ports from one mapping to the next of a sequential NAT
	UINT Mappings;  // The mappings of the node now
} PEER_PUNCH_MODEL;

// One punch message of a tick: the peer it is for, the address it goes to, its type, and the echo of a proof
typedef struct PEER_PUNCH_SEND {
	UCHAR Key[PEER_KEY_SIZE];
	PEER_ADDR To;
	UINT Type;
	UCHAR Echo[PEER_PUNCH_NONCE_SIZE];
} PEER_PUNCH_SEND;

// The limits of the punch, the configured values or the defaults
static UINT PeerPunchBudget(PEER_AGENT *a) {
	return (a->Config.PunchBudget != 0 ? a->Config.PunchBudget : PEER_DEFAULT_PUNCH_BUDGET);
}

// The punch messages of the budget of an attempt that its probes leave to its answers: PEER_PUNCH_ANSWERS, or half of a
// smaller budget
static UINT PeerPunchKeep(PEER_AGENT *a) {
	UINT half = PeerPunchBudget(a) / 2;

	return (half < PEER_PUNCH_ANSWERS ? half : PEER_PUNCH_ANSWERS);
}

static UINT PeerPunchPorts(PEER_AGENT *a) {
	return (a->Config.PunchPorts != 0 ? a->Config.PunchPorts : PEER_DEFAULT_PUNCH_PORTS);
}

static UINT PeerPunchRate(PEER_AGENT *a) {
	UINT rate = (a->Config.PunchRate != 0 ? a->Config.PunchRate : PEER_DEFAULT_PUNCH_RATE);

	return (rate < PEER_PUNCH_RATE_MAX ? rate : PEER_PUNCH_RATE_MAX);
}

static UINT PeerPunchAttempts(PEER_AGENT *a) {
	return (a->Config.PunchAttempts != 0 ? a->Config.PunchAttempts : PEER_DEFAULT_PUNCH_ATTEMPTS);
}

static UINT64 PeerPunchRetry(PEER_AGENT *a) {
	return (a->Config.PunchRetry != 0 ? a->Config.PunchRetry : PEER_DEFAULT_PUNCH_RETRY);
}

static UINT64 PeerPunchBackoff(PEER_AGENT *a) {
	return (a->Config.PunchBackoff != 0 ? a->Config.PunchBackoff : PEER_DEFAULT_PUNCH_BACKOFF);
}

static UINT64 PeerPunchConsent(PEER_AGENT *a) {
	return (a->Config.PunchConsent != 0 ? a->Config.PunchConsent : PEER_DEFAULT_PUNCH_CONSENT);
}

//
// The destinations and the NAT of the node
//

// The destination to among the destinations of the current generation, NULL when it is none. The caller holds PunchLock.
static PEER_PUNCH_DEST *PeerPunchFindDest(PEER_AGENT *a, const PEER_ADDR *to) {
	for (UINT i = 0; i < PEER_PUNCH_DESTS; i++) {
		PEER_PUNCH_DEST *d = &a->Dests[i];

		if (d->Index != 0 && d->Gen == a->DestGen && PeerAddrEqual(&d->Addr, to))
			return d;
	}

	return NULL;
}

// Add the destination to, with the number of the next mapping, in place of the oldest one. The caller holds PunchLock
// exclusively.
static PEER_PUNCH_DEST *PeerPunchAddDest(PEER_AGENT *a, const PEER_ADDR *to) {
	PEER_PUNCH_DEST *d = &a->Dests[a->NextDest];

	a->NextDest = (a->NextDest + 1) % PEER_PUNCH_DESTS;
	d->Addr = *to;
	d->Index = ++a->Mappings;
	d->Gen = a->DestGen;

	return d;
}

// The number of the mapping that the NAT of the node makes for a message to the destination to, in the order of its
// destinations: the one it has, or the next one when to is new. A relay that the node binds, an address that its ICE
// sessions check and an address that its punches probe come here before the message goes. 0 without punching. The caller
// may hold the lock of the layer.
UINT PeerPunchDestination(PEER_AGENT *a, const PEER_ADDR *to) {
	UINT index = 0;

	if (a->Config.Punch == false)
		return 0;

	AcquireSRWLockExclusive(&a->PunchLock);
	{
		PEER_PUNCH_DEST *d = PeerPunchFindDest(a, to);

		if (d == NULL)
			d = PeerPunchAddDest(a, to);
		index = d->Index;
	}
	ReleaseSRWLockExclusive(&a->PunchLock);

	return index;
}

// The relay r saw the node at another address than before: the NAT of the node lost its mapping towards the relay, as a
// NAT that restarts loses all of them, and the last bind made a new one. When the destinations still held the relay, the
// mappings of all of them are gone: a new generation of them begins, with the relay as its first. The caller holds the
// lock of the layer exclusively.
void PeerPunchRemap(PEER_AGENT *a, PEER_RELAY *r) {
	if (a->Config.Punch == false)
		return;

	AcquireSRWLockExclusive(&a->PunchLock);
	{
		if (PeerPunchFindDest(a, &r->Info.Addr) != NULL)
			a->DestGen++;

		r->Mapping = PeerPunchAddDest(a, &r->Info.Addr)->Index;
	}
	ReleaseSRWLockExclusive(&a->PunchLock);
}

// What the node knows of its NAT, from the answers of the binds to its first two relays, into m. The caller holds the
// lock of the layer.
static void PeerPunchModel(PEER_AGENT *a, PEER_PUNCH_MODEL *m) {
	const PEER_RELAY *seen[2] = {NULL, NULL};
	UINT num = 0;

	ZeroMemory(m, sizeof(PEER_PUNCH_MODEL));

	AcquireSRWLockShared(&a->PunchLock);
	m->Mappings = a->Mappings;
	ReleaseSRWLockShared(&a->PunchLock);

	for (UINT i = 0; i < a->NumRelays && i < 2; i++) {
		const PEER_RELAY *r = &a->Relays[i];

		if (r->Bound && r->Observed.Port != 0 && r->Mapping != 0 && num < 2)
			seen[num++] = r;
	}

	if (a->Config.Punch == false || num < 2 || seen[0]->Mapping == seen[1]->Mapping)
		return;

	const PEER_RELAY *older = (seen[0]->Mapping < seen[1]->Mapping ? seen[0] : seen[1]);
	const PEER_RELAY *newer = (older == seen[0] ? seen[1] : seen[0]);
	UINT steps = newer->Mapping - older->Mapping;
	UINT old_port = older->Observed.Port;
	UINT new_port = newer->Observed.Port;
	bool one = (memcmp(older->Observed.Ip, newer->Observed.Ip, sizeof(older->Observed.Ip)) == 0);

	m->Base = newer->Observed;
	m->Mapping = newer->Mapping;

	if (one && old_port == new_port) {
		m->Nat = PEER_NAT_CONE;
	} else if (one && new_port > old_port && new_port - old_port <= PEER_PUNCH_SEQ_THRESHOLD * steps) {
		m->Nat = PEER_NAT_SEQUENTIAL;
		m->Step = (new_port - old_port) / steps;
		if (m->Step == 0)
			m->Step = 1;
	} else {
		// Ports far apart, or two public addresses of a pool: the node cannot tell the next one
		m->Nat = PEER_NAT_RANDOM;
	}
}

// The public address and port of the node's mapping number index, as the model m predicts it: the one port of a cone,
// or the port of the newer observation and a step for each mapping since. False when it cannot be predicted.
static bool PeerPunchPortOf(const PEER_PUNCH_MODEL *m, UINT index, PEER_ADDR *addr) {
	if (m->Nat == PEER_NAT_CONE) {
		*addr = m->Base;
		return true;
	}

	if (m->Nat != PEER_NAT_SEQUENTIAL)
		return false;

	INT64 port = (INT64)m->Base.Port + (INT64)m->Step * ((INT64)index - (INT64)m->Mapping);
	if (port <= 0 || port > 0xFFFF)
		return false;

	*addr = m->Base;
	addr->Port = (USHORT)port;
	return true;
}

// The candidate of type among the candidates of the last signal of the peer p into addr, false when it has none
static bool PeerPunchCandidateOf(const PEER *p, UINT type, PEER_ADDR *addr) {
	for (UINT i = 0; i < p->NumCandidates; i++) {
		if (p->Candidates[i].Type == type) {
			*addr = p->Candidates[i].Addr;
			return true;
		}
	}

	return false;
}

// The public address and port of the node's mapping towards the reflexive address of the peer p, which its NAT made for
// the checks of ICE, as the model m predicts it. False when the node never sent there, or its NAT is no sequential one.
// The caller holds the lock of the layer.
static bool PeerPunchToward(PEER_AGENT *a, const PEER *p, const PEER_PUNCH_MODEL *m, PEER_ADDR *toward) {
	PEER_ADDR srflx;
	UINT index = 0;

	if (m->Nat != PEER_NAT_SEQUENTIAL || PeerPunchCandidateOf(p, PEER_CANDIDATE_SRFLX, &srflx) == false)
		return false;

	AcquireSRWLockShared(&a->PunchLock);
	{
		PEER_PUNCH_DEST *d = PeerPunchFindDest(a, &srflx);

		index = (d != NULL ? d->Index : 0);
	}
	ReleaseSRWLockShared(&a->PunchLock);

	return index != 0 && PeerPunchPortOf(m, index, toward);
}

// Whether a pair whose NATs are mine and theirs can meet by a punch: both known, one of them symmetric, and a random one
// only with a cone, whose one port it can reach
static bool PeerPunchPair(UINT mine, UINT theirs) {
	if (mine == PEER_NAT_UNKNOWN || theirs == PEER_NAT_UNKNOWN || (mine == PEER_NAT_CONE && theirs == PEER_NAT_CONE))
		return false;

	if ((mine == PEER_NAT_RANDOM && theirs != PEER_NAT_CONE) || (theirs == PEER_NAT_RANDOM && mine != PEER_NAT_CONE))
		return false;

	return true;
}

//
// The rate of the punch messages
//

// The punch messages that the rate of the node allows at now, less reserve: PunchRate in any PEER_PUNCH_WINDOW. The caller
// holds PunchLock.
static UINT PeerPunchRoom(PEER_AGENT *a, UINT64 now, UINT reserve) {
	UINT rate = PeerPunchRate(a);
	UINT used = 0;

	for (UINT k = 0; k < rate; k++) {
		UINT64 t = a->RateTimes[(a->RateNext + PEER_PUNCH_RATE_MAX - 1 - k) % PEER_PUNCH_RATE_MAX];

		if (t != 0 && now - t < PEER_PUNCH_WINDOW)
			used++;
	}

	return (used + reserve < rate ? rate - used - reserve : 0);
}

// Count num punch messages that go at now. The caller holds PunchLock exclusively.
static void PeerPunchUse(PEER_AGENT *a, UINT64 now, UINT num) {
	for (UINT k = 0; k < num; k++) {
		a->RateTimes[a->RateNext] = now;
		a->RateNext = (a->RateNext + 1) % PEER_PUNCH_RATE_MAX;
	}
}

// Whether one more punch message may go now, which then counts; with must, it goes and counts in any case. The caller
// may hold the lock of the layer.
static bool PeerPunchAllow(PEER_AGENT *a, bool must) {
	bool allow = false;

	AcquireSRWLockExclusive(&a->PunchLock);
	{
		UINT64 now = PeerNow();

		if (must || PeerPunchRoom(a, now, 0) != 0) {
			PeerPunchUse(a, now, 1);
			allow = true;
		}
	}
	ReleaseSRWLockExclusive(&a->PunchLock);

	return allow;
}

//
// The attempts
//

// Add the address addr to the targets of the punch, unless it is there already or they are full, or, with skip, the node
// sent to it before, so that a message there makes no new mapping. Returns whether it was added. The caller holds the
// lock of the layer.
static bool PeerPunchAddTarget(PEER_AGENT *a, PEER_PUNCH *punch, const PEER_ADDR *addr, bool skip) {
	bool known = false;

	if (addr->Port == 0 || punch->NumTargets >= PEER_PUNCH_MAX_TARGETS)
		return false;

	for (UINT i = 0; i < punch->NumTargets; i++)
		if (PeerAddrEqual(&punch->Targets[i], addr))
			return false;

	if (skip) {
		AcquireSRWLockShared(&a->PunchLock);
		known = (PeerPunchFindDest(a, addr) != NULL);
		ReleaseSRWLockShared(&a->PunchLock);
	}

	if (known)
		return false;

	punch->Targets[punch->NumTargets++] = *addr;
	return true;
}

// Build the targets of an attempt with the peer p from the candidates of its punch signal, the node's NAT being mine:
// - a peer behind a cone, or behind a random NAT that only a cone can meet: its one port, the predicted one, else its
//   reflexive one;
// - a peer behind a sequential NAT: a range of its ports, one by one from PEER_PUNCH_BELOW under its predicted port for
//   the leader, the node of the lower static key, and for a node behind a cone, which aims at the port of the peer's
//   mapping towards it when the peer names one; in steps of two from there for the other end, so that the two sweeps
//   cross (above). In the sweep of a symmetric NAT an address that the node sent to before is left out: it makes no new
//   mapping. After the sweep come spacers, ports of the peer's address counted down from the top that make the
//   PunchPorts + PEER_PUNCH_BELOW - 1 more mappings by which the mappings of an attempt outnumber the sweep of the other
//   end: the next attempt then sweeps ports of both NATs that the ones before did not, so it can meet too.
// The caller holds the lock of the layer exclusively.
static void PeerPunchTargets(PEER_AGENT *a, PEER *p, UINT mine) {
	PEER_PUNCH *punch = &p->Punch;
	PEER_ADDR base;
	PEER_ADDR toward;
	UINT ports = PeerPunchPorts(a);

	ZeroMemory(&base, sizeof(base));
	ZeroMemory(&toward, sizeof(toward));
	punch->NumTargets = 0;
	punch->Next = 0;

	if (punch->PeerNat != PEER_NAT_SEQUENTIAL || PeerPunchCandidateOf(p, PEER_CANDIDATE_PREDICTED, &base) == false) {
		if (PeerPunchCandidateOf(p, PEER_CANDIDATE_PREDICTED, &base) || PeerPunchCandidateOf(p, PEER_CANDIDATE_SRFLX, &base))
			PeerPunchAddTarget(a, punch, &base, false);
		return;
	}

	bool leader = (memcmp(a->Key.Public, p->Info.Key, PEER_KEY_SIZE) < 0);
	UINT stride = 1;
	UINT count = 3 * ports + 3 * PEER_PUNCH_BELOW - 2;

	if (mine == PEER_NAT_CONE) {
		// The probes of the peer come from its mapping towards the one port of the node
		if (PeerPunchCandidateOf(p, PEER_CANDIDATE_TOWARD, &toward))
			base = toward;
		count = ports + PEER_PUNCH_BELOW;
	} else if (leader == false) {
		stride = 2;
		count = 2 * ports + 2 * PEER_PUNCH_BELOW - 1;
	}

	for (UINT k = 0; k < count; k++) {
		INT64 port = (INT64)base.Port + (INT64)stride * k - PEER_PUNCH_BELOW;
		PEER_ADDR t = base;

		if (port <= 0 || port > 0xFFFF)
			continue;

		t.Port = (USHORT)port;
		PeerPunchAddTarget(a, punch, &t, mine != PEER_NAT_CONE);
	}

	// The spacers of a symmetric NAT, above the ranges that the sweeps of the two ends cover
	if (mine == PEER_NAT_CONE)
		return;

	UINT spacers = 0;
	INT64 top = (INT64)base.Port + 2 * (INT64)count;
	for (UINT port = 0xFFFF; port > top && spacers < ports + PEER_PUNCH_BELOW - 1 && punch->NumTargets < PEER_PUNCH_MAX_TARGETS; port--) {
		PEER_ADDR t = base;

		t.Port = (USHORT)port;
		if (PeerPunchAddTarget(a, punch, &t, true))
			spacers++;
	}
}

// Seal a punch offer or a punch answer for the peer of key: the relay assignment of the node, its reflexive candidate, its
// predicted next port, the port of its mapping towards the peer's reflexive address when it made one, and its NAT. An
// answer goes once, for the offer of the peer that began an attempt (PeerPunchStart), and names the prediction that the
// probes of the node began at. An offer counts as an attempt that fails unless the pair meets: the next one waits
// PunchRetry, or PunchBackoff after PunchAttempts of them, which the end of the attempt counts again (PeerPunchTick).
// Returns the size of the envelope in buf, 0 when key is no peer, for an answer with no offer to answer, or when the
// envelope does not fit size. Without the lock of the layer.
UINT PeerPunchSealSignal(PEER_AGENT *a, const UCHAR *key, UINT type, UCHAR *buf, UINT size) {
	PEER_SIGNAL s;
	UCHAR payload[PEER_MAX_SIGNAL];
	bool known = false;

	ZeroMemory(&s, sizeof(s));
	s.Type = type;
	s.Sequence = PeerNextSequence(a);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		known = (p != NULL && (type != PEER_SIGNAL_PUNCH_ANSWER || p->Punch.Answer));
		if (known) {
			PEER_PUNCH *punch = &p->Punch;
			PEER_PUNCH_MODEL m;
			PEER_ADDR next;
			PEER_ADDR toward;

			if (type == PEER_SIGNAL_PUNCH_ANSWER)
				punch->Answer = false;

			PeerPunchModel(a, &m);
			s.Nat = m.Nat;

			if (a->NumRelays != 0) {
				PEER_RELAY *home = &a->Relays[0];

				CopyMemory(s.RelayKey, home->Info.Key, PEER_KEY_SIZE);
				s.Relay = home->Info.Addr;
				if (home->Bound) {
					s.Candidates[s.NumCandidates].Type = PEER_CANDIDATE_SRFLX;
					s.Candidates[s.NumCandidates].Addr = home->Observed;
					s.NumCandidates++;
				}
			}

			// An answer names where the probes of the node began
			ZeroMemory(&next, sizeof(next));
			if (type == PEER_SIGNAL_PUNCH_ANSWER && punch->State == PEER_PUNCH_PROBING && punch->Own.Port != 0)
				next = punch->Own;
			else
				PeerPunchPortOf(&m, m.Mappings + 1, &next);

			if (next.Port != 0) {
				s.Candidates[s.NumCandidates].Type = PEER_CANDIDATE_PREDICTED;
				s.Candidates[s.NumCandidates].Addr = next;
				s.NumCandidates++;
			}

			if (PeerPunchToward(a, p, &m, &toward)) {
				s.Candidates[s.NumCandidates].Type = PEER_CANDIDATE_TOWARD;
				s.Candidates[s.NumCandidates].Addr = toward;
				s.NumCandidates++;
			}

			if (type == PEER_SIGNAL_PUNCH_OFFER) {
				UINT64 now = PeerNow();

				punch->Offered = now;
				punch->Failures++;
				punch->NextAttempt = now + (punch->Failures >= PeerPunchAttempts(a) ? PeerPunchBackoff(a) : PeerPunchRetry(a));
			}
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (known == false)
		return 0;

	UINT len = PeerSignalEncode(&s, payload, sizeof(payload));
	if (len == 0)
		return 0;

	return PeerSeal(a, key, PEER_MSG_SIGNAL, payload, len, buf, size);
}

// Whether the node, which offers the pair with the peer of key, asks the peer for a punch now (PEER_SIGNAL_PUNCH_OFFER): the
// pair is on the relay, an ICE session of it failed, the node can tell its NAT, no attempt runs, and the retry or the
// backoff after the last attempt passed. Without the lock of the layer.
bool PeerPunchDue(PEER_AGENT *a, const UCHAR *key) {
	bool due = false;

	if (a == NULL || key == NULL || a->Config.Punch == false || a->Config.Ice == false)
		return false;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL) {
			PEER_PUNCH *punch = &p->Punch;
			PEER_PUNCH_MODEL m;
			LONG ice = (p->Ice != NULL ? InterlockedCompareExchange(&p->Ice->State, 0, 0) : PEER_ICE_NONE);

			// ICE failed for the pair, until it has its direct path up again
			if (ice == PEER_ICE_FAILED)
				punch->IceFailed = true;
			else if (ice == PEER_ICE_COMPLETED)
				punch->IceFailed = false;

			PeerPunchModel(a, &m);
			due = (punch->IceFailed && p->HasRelay && p->HasDirect == false && ice != PEER_ICE_CONNECTED && ice != PEER_ICE_COMPLETED && m.Nat != PEER_NAT_UNKNOWN &&
			       punch->State != PEER_PUNCH_PROBING && PeerNow() >= punch->NextAttempt);

			// A backoff that ended begins the count of the attempts again
			if (due && punch->Failures >= PeerPunchAttempts(a))
				punch->Failures = 0;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	return due;
}

// Take the punch offer or the punch answer s of the peer of key, whose candidates PeerOpenSignal took: begin an attempt
// when the pair can meet and has no direct path. An offer is taken unless the pair is in its backoff, and counts as an
// attempt that fails unless the pair meets; an attempt of the node that still runs then ends as one that met nothing, as
// the peer offers only once its own attempt ended. Only an offer that began an attempt gets the punch answer of the node
// (PeerPunchSealSignal). An answer is taken only for the offer that the node sealed last, within PunchRetry, while no
// attempt runs. The node's own prediction is kept, so that its answer names where its probes began. Without the lock of
// the layer.
void PeerPunchStart(PEER_AGENT *a, const UCHAR *key, const PEER_SIGNAL *s) {
	bool attempt = false;
	bool ended = false;

	if (a->Config.Punch == false || s == NULL)
		return;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL) {
			PEER_PUNCH *punch = &p->Punch;
			PEER_PUNCH_MODEL m;
			UINT64 now = PeerNow();
			UINT64 retry = PeerPunchRetry(a);
			UINT attempts = PeerPunchAttempts(a);
			bool direct = (p->HasDirect || (p->Ice != NULL && PeerIceUp(p->Ice)));
			bool offer = (s->Type == PEER_SIGNAL_PUNCH_OFFER);
			bool probing = (punch->State == PEER_PUNCH_PROBING);

			PeerPunchModel(a, &m);
			punch->PeerNat = s->Nat;

			bool take = (direct == false && (offer || probing == false) && PeerPunchPair(m.Nat, s->Nat));

			if (take && offer) {
				// Refused in the backoff, which the peer keeps too: an offer up to a retry early is the clock of the peer
				if (punch->Failures >= attempts && now + retry < punch->NextAttempt) {
					take = false;
				} else {
					if (punch->Failures >= attempts)
						punch->Failures = 0;
					punch->Failures++;
					punch->NextAttempt = now + (punch->Failures >= attempts ? PeerPunchBackoff(a) : retry);
				}
			} else if (take) {
				take = (punch->Offered != 0 && now - punch->Offered <= retry);
			}

			// One answer for each offer
			if (s->Type == PEER_SIGNAL_PUNCH_ANSWER)
				punch->Offered = 0;

			if (take) {
				// The attempt that still runs met nothing
				if (probing) {
					punch->State = PEER_PUNCH_FAILED;
					ended = true;
				}

				ZeroMemory(&punch->Own, sizeof(PEER_ADDR));
				PeerPunchPortOf(&m, m.Mappings + 1, &punch->Own);
				PeerPunchTargets(a, p, m.Nat);
			}

			if (take && punch->NumTargets != 0) {
				punch->State = PEER_PUNCH_PROBING;
				punch->Budget = PeerPunchBudget(a);
				punch->Next = 0;
				punch->LastProbe = now;
				attempt = true;
			}

			if (offer)
				punch->Answer = attempt;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (ended)
		PeerCount(a, PEER_COUNT_PUNCH_FAILURES);
	if (attempt)
		PeerCount(a, PEER_COUNT_PUNCH_ATTEMPTS);
}

// Seal a punch message of type for the peer of key, with nonce and echo (NULL for none), and send it to to. Returns
// whether it went.
static bool PeerPunchSend(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *to, UINT type, const UCHAR *nonce, const UCHAR *echo) {
	UCHAR payload[PEER_PUNCH_PAYLOAD_SIZE];
	UCHAR env[PEER_ENVELOPE_HEADER + PEER_PUNCH_PAYLOAD_SIZE + PEER_ENVELOPE_TAG];

	ZeroMemory(payload, sizeof(payload));
	payload[0] = PEER_VERSION;
	PeerPutUint64(payload + 1, PeerNextSequence(a));
	payload[9] = (UCHAR)type;
	if (nonce != NULL)
		CopyMemory(payload + 10, nonce, PEER_PUNCH_NONCE_SIZE);
	if (echo != NULL)
		CopyMemory(payload + 10 + PEER_PUNCH_NONCE_SIZE, echo, PEER_PUNCH_NONCE_SIZE);

	UINT size = PeerSeal(a, key, PEER_MSG_PUNCH, payload, sizeof(payload), env, sizeof(env));
	SecureZeroMemory(payload, sizeof(payload));
	if (size == 0)
		return false;

	// A symmetric NAT makes a mapping for an address that is new to the node
	PeerPunchDestination(a, to);

	return PeerSendRaw(a, to, env, size);
}

// Read the payload of a punch message, as PeerPunchSend writes it, into m: PEER_VERSION, the sequence (big-endian), the
// type, a nonce and the echo of a nonce of the receiver, PEER_PUNCH_PAYLOAD_SIZE bytes in all. False unless it is exactly
// one punch message of this version and of a known type; Nonce and Echo point into payload.
bool PeerPunchParse(const UCHAR *payload, UINT size, PEER_PUNCH_INFO *m) {
	if (m == NULL)
		return false;

	ZeroMemory(m, sizeof(PEER_PUNCH_INFO));
	if (payload == NULL || size != PEER_PUNCH_PAYLOAD_SIZE || payload[0] != PEER_VERSION || payload[9] < PEER_PUNCH_PROBE || payload[9] > PEER_PUNCH_KEEPALIVE)
		return false;

	m->Sequence = PeerGetUint64(payload + 1);
	m->Type = payload[9];
	m->Nonce = payload + 10;
	m->Echo = payload + 10 + PEER_PUNCH_NONCE_SIZE;

	return true;
}

// A fresh nonce of the punch, which goes to the address to: kept in the next slot, in place of the oldest. False when
// the random generator fails. The caller holds the lock.
static bool PeerPunchNonce(PEER_PUNCH *punch, const PEER_ADDR *to, UCHAR *nonce) {
	if (CryptoRandom(nonce, PEER_PUNCH_NONCE_SIZE) == false)
		return false;

	UINT i = punch->NextNonce % PEER_PUNCH_NONCES;
	punch->NonceTo[i] = *to;
	CopyMemory(punch->Nonces[i], nonce, PEER_PUNCH_NONCE_SIZE);
	punch->NextNonce = i + 1;

	return true;
}

// Whether echo is a nonce of the punch that went to the address from; the nonce is used up. The caller holds the lock.
static bool PeerPunchEcho(PEER_PUNCH *punch, const PEER_ADDR *from, const UCHAR *echo) {
	static const UCHAR zero[PEER_PUNCH_NONCE_SIZE] = {0};

	if (memcmp(echo, zero, PEER_PUNCH_NONCE_SIZE) == 0)
		return false;

	for (UINT i = 0; i < PEER_PUNCH_NONCES; i++) {
		if (PeerAddrEqual(&punch->NonceTo[i], from) && memcmp(punch->Nonces[i], echo, PEER_PUNCH_NONCE_SIZE) == 0) {
			ZeroMemory(punch->Nonces[i], PEER_PUNCH_NONCE_SIZE);
			ZeroMemory(&punch->NonceTo[i], sizeof(PEER_ADDR));
			return true;
		}
	}

	return false;
}

// The timer of the punches, from PeerTick: the next burst of probes of every attempt, within the rate of the node and the
// budget of the attempt, of which the probes leave PeerPunchKeep to the answers; an attempt whose probes are spent fails
// PEER_PUNCH_LINGER after its last probe, and the next one waits the retry, or the backoff after the last of the
// attempts, from then; and on a punched path the proof of the leader again until the other end said that it moved there,
// the keepalive of the node, or the Fallback once the peer said nothing there for PunchConsent.
void PeerPunchTick(PEER_AGENT *a) {
	PEER_PUNCH_SEND send[PEER_PUNCH_TICK_MAX];
	UINT num = 0;
	UINT failed = 0;
	UINT fallbacks = 0;

	if (a->Config.Punch == false)
		return;

	ZeroMemory(send, sizeof(send));

	UINT64 consent = PeerPunchConsent(a);
	UINT64 retry = PeerPunchRetry(a);
	UINT64 backoff = PeerPunchBackoff(a);
	UINT attempts = PeerPunchAttempts(a);
	UINT keep = PeerPunchKeep(a);

	AcquireSRWLockExclusive(&a->Lock);
	AcquireSRWLockExclusive(&a->PunchLock);
	{
		UINT64 now = PeerNow();
		UINT left = PeerPunchRoom(a, now, 0);

		for (UINT i = 0; i < a->NumPeers; i++) {
			PEER *p = &a->Peers[i];
			PEER_PUNCH *punch = &p->Punch;

			if (punch->State == PEER_PUNCH_PROBING) {
				// The probes leave room in the rate for the answers and the keepalives, and in the budget for the answers
				while (punch->Budget > keep && left > PEER_PUNCH_ANSWERS && num < PEER_PUNCH_TICK_MAX) {
					CopyMemory(send[num].Key, p->Info.Key, PEER_KEY_SIZE);
					send[num].To = punch->Targets[punch->Next];
					send[num].Type = PEER_PUNCH_PROBE;
					num++;
					left--;

					punch->Next = (punch->Next + 1) % punch->NumTargets;
					punch->Budget--;
					punch->LastProbe = now;
				}

				// The probes are spent and the answers on their way had their time: the attempt met nothing
				if (punch->Budget <= keep && now - punch->LastProbe >= PEER_PUNCH_LINGER) {
					punch->State = PEER_PUNCH_FAILED;
					punch->NextAttempt = now + (punch->Failures >= attempts ? backoff : retry);
					failed++;
				}
			} else if (punch->State == PEER_PUNCH_CONNECTED && p->HasDirect == false) {
				// The direct path was taken away by hand (PeerSetDirect)
				punch->State = PEER_PUNCH_NONE;
			} else if (punch->State == PEER_PUNCH_CONNECTED && now - (UINT64)ReadAcquire64(&punch->LastHeard) >= consent) {
				// The peer said nothing on the punched path for PunchConsent: the pair falls back to the relay
				p->HasDirect = false;
				ZeroMemory(&p->Direct, sizeof(PEER_ADDR));
				punch->State = PEER_PUNCH_NONE;
				punch->NextAttempt = now + retry;
				fallbacks++;
			} else if (punch->State == PEER_PUNCH_CONNECTED && punch->Proofs != 0 && punch->Proofs < PEER_PUNCH_PROOFS && InterlockedCompareExchange(&punch->Moved, 0, 0) == 0 &&
			           now - punch->LastSent >= PEER_PUNCH_PROOF_RETRY && left != 0 && num < PEER_PUNCH_TICK_MAX) {
				// The leader: the other end has not said from the punched path that it moved there, so its proof may have been
				// lost on the way, and goes again
				CopyMemory(send[num].Key, p->Info.Key, PEER_KEY_SIZE);
				send[num].To = p->Direct;
				send[num].Type = PEER_PUNCH_PROOF;
				CopyMemory(send[num].Echo, punch->Proof, PEER_PUNCH_NONCE_SIZE);
				num++;
				left--;

				punch->Proofs++;
				punch->LastSent = now;
			} else if (punch->State == PEER_PUNCH_CONNECTED && now - punch->LastSent >= consent / 4 && left != 0 && num < PEER_PUNCH_TICK_MAX) {
				CopyMemory(send[num].Key, p->Info.Key, PEER_KEY_SIZE);
				send[num].To = p->Direct;
				send[num].Type = PEER_PUNCH_KEEPALIVE;
				num++;
				left--;

				punch->LastSent = now;
			}
		}

		PeerPunchUse(a, now, num);
	}
	ReleaseSRWLockExclusive(&a->PunchLock);
	ReleaseSRWLockExclusive(&a->Lock);

	for (UINT i = 0; i < num; i++)
		if (PeerPunchSend(a, send[i].Key, &send[i].To, send[i].Type, NULL, (send[i].Type == PEER_PUNCH_PROOF ? send[i].Echo : NULL)) && send[i].Type == PEER_PUNCH_PROBE)
			PeerCount(a, PEER_COUNT_PUNCH_PROBES);
	SecureZeroMemory(send, sizeof(send));

	for (UINT i = 0; i < failed; i++)
		PeerCount(a, PEER_COUNT_PUNCH_FAILURES);
	for (UINT i = 0; i < fallbacks; i++)
		PeerCount(a, PEER_COUNT_FALLBACKS);
}

// A punch message that arrived from the address from: open it, check it is from a peer, is not a replay and belongs to a
// punch that is open, then take its part in the exchange of nonces. A probe draws a challenge from the leader and a probe
// from the other end; a challenge draws a response from the other end; a response that echoes the leader's nonce from the
// address it went to moves the peer to the direct path at the leader and draws a proof; a proof that echoes the other
// end's nonce from the address it went to moves the peer to the direct path there, and draws a keepalive that says so to
// the leader. A node already on the direct path takes a message and answers none but a proof, which the other end
// answers with a keepalive again, so a late probe of a burst leaves the path on the pair that met; a word of the peer
// from there is its consent, and its keepalive says to the leader that it moved there, so the proof goes no more
// (PeerPunchTick). A meeting counts as a prediction success and an Upgrade. The answers of an attempt take from its
// budget and go within the rate of the node, and the proof also when the rate is spent. Called from PeerInput for a
// PEER_MSG_PUNCH datagram.
void PeerPunchInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_PUNCH_PAYLOAD_SIZE];
	UCHAR nonce[PEER_PUNCH_NONCE_SIZE];
	PEER_PUNCH_INFO m;
	UINT len = 0;
	UINT reason = PEER_OK;
	UINT reply = 0;
	bool connected = false;
	bool limited = false;

	ZeroMemory(nonce, sizeof(nonce));
	ZeroMemory(&m, sizeof(m));

	if (a->Config.Punch) {
		if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
			reason = PEER_DROP_FORGED;
		else if (PeerPunchParse(payload, len, &m) == false)
			reason = PEER_DROP_MALFORMED;
	} else {
		reason = PEER_DROP_MALFORMED;
	}

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = m.Sequence;
	UINT type = m.Type;
	const UCHAR *their_nonce = m.Nonce;
	const UCHAR *echo = m.Echo;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, sender);
		PEER_PUNCH *punch = (p != NULL ? &p->Punch : NULL);

		if (p == NULL) {
			reason = PEER_DROP_POLICY; // A node that is no peer
		} else if (seq <= PeerFloorOf(p, punch->LastSeq)) {
			reason = PEER_DROP_REPLAY;
		} else if (punch->State != PEER_PUNCH_PROBING && punch->State != PEER_PUNCH_CONNECTED) {
			reason = PEER_DROP_FORGED; // No punch is open with this peer: an unsolicited or stale message
		} else {
			bool leader = (memcmp(a->Key.Public, p->Info.Key, PEER_KEY_SIZE) < 0);
			bool probing = (punch->State == PEER_PUNCH_PROBING);

			punch->LastSeq = seq;

			if (punch->State == PEER_PUNCH_CONNECTED) {
				// On the direct path already: the exchange that got it there is the only one. A word of the peer from there is
				// its consent; its keepalive also says that it moved there, so the leader sends its proof no more, and the other
				// end answers a proof that the leader sent again with a keepalive, as the one before may have been lost.
				if (p->HasDirect && PeerAddrEqual(&p->Direct, from)) {
					InterlockedExchange64(&punch->LastHeard, (LONG64)PeerNow());
					if (type == PEER_PUNCH_KEEPALIVE)
						InterlockedExchange(&punch->Moved, 1);
					else if (type == PEER_PUNCH_PROOF && leader == false)
						reply = PEER_PUNCH_KEEPALIVE;
				}
			} else if (type == PEER_PUNCH_PROBE) {
				reply = (leader ? PEER_PUNCH_CHALLENGE : PEER_PUNCH_PROBE);
			} else if (type == PEER_PUNCH_CHALLENGE && leader == false) {
				reply = PEER_PUNCH_RESPONSE;
			} else if ((type == PEER_PUNCH_RESPONSE && leader) || (type == PEER_PUNCH_PROOF && leader == false)) {
				connected = PeerPunchEcho(punch, from, echo);
				if (connected) {
					UINT64 now = PeerNow();

					p->HasDirect = true;
					p->Direct = *from;
					punch->State = PEER_PUNCH_CONNECTED;
					punch->Failures = 0;
					punch->NextAttempt = 0;
					punch->LastSent = now;
					InterlockedExchange64(&punch->LastHeard, (LONG64)now);
					InterlockedExchange(&punch->Moved, 0);

					// The leader sends the proof, and again until the other end says that it moved (PeerPunchTick); the other
					// end says so at once, with a keepalive
					punch->Proofs = (leader ? 1 : 0);
					if (leader)
						CopyMemory(punch->Proof, their_nonce, PEER_PUNCH_NONCE_SIZE);
					reply = (leader ? PEER_PUNCH_PROOF : PEER_PUNCH_KEEPALIVE);
				}
			}

			// An answer of the attempt takes its share of the budget of the attempt, as a probe does, and goes within the rate
			// of the node: one that finds the budget or the rate spent does not go, and counts as over the rate. The first
			// proof completes the meeting that moved the node to the direct path, once for each meeting, so it goes and counts
			// when the rate is spent too; it and the keepalive of the other end take nothing of the budget of the attempt,
			// which met. A nonce is drawn only for an answer that goes, so its slots hold the nonces that went out, not the
			// ones of the answers that the budget or the rate held back.
			bool answer = (reply != 0 && probing && connected == false);

			if ((answer && punch->Budget == 0) || (reply != 0 && PeerPunchAllow(a, reply == PEER_PUNCH_PROOF) == false)) {
				limited = true;
				reply = 0;
			} else if (answer) {
				punch->Budget--;
			}
			if ((reply == PEER_PUNCH_CHALLENGE || reply == PEER_PUNCH_RESPONSE) && PeerPunchNonce(punch, from, nonce) == false)
				reply = 0;

			// An attempt that answered a challenge waits PEER_PUNCH_LINGER from then for the proof, so that a proof that the
			// leader sends again finds it open; a keepalive of the other end is one on the punched path
			if (reply == PEER_PUNCH_RESPONSE)
				punch->LastProbe = PeerNow();
			else if (reply == PEER_PUNCH_KEEPALIVE)
				punch->LastSent = PeerNow();
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		SecureZeroMemory(payload, sizeof(payload));
		return;
	}

	if (limited)
		PeerDrop(a, PEER_DROP_RATE);
	if (connected) {
		PeerCount(a, PEER_COUNT_PUNCH_SUCCESSES);
		PeerCount(a, PEER_COUNT_UPGRADES);
	}

	// A challenge carries the node's nonce; a response echoes the peer's and carries the node's; a proof echoes the
	// peer's; a keepalive carries none
	if (reply == PEER_PUNCH_PROBE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_PROBE, NULL, NULL);
	else if (reply == PEER_PUNCH_CHALLENGE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_CHALLENGE, nonce, NULL);
	else if (reply == PEER_PUNCH_RESPONSE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_RESPONSE, nonce, their_nonce);
	else if (reply == PEER_PUNCH_PROOF)
		PeerPunchSend(a, sender, from, PEER_PUNCH_PROOF, NULL, their_nonce);
	else if (reply == PEER_PUNCH_KEEPALIVE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_KEEPALIVE, NULL, NULL);

	SecureZeroMemory(nonce, sizeof(nonce));
	SecureZeroMemory(payload, sizeof(payload));
}

// A record of the peer session with the peer p, which opened, came from the address from (PeerInputData): on the punched
// path of p it is a word of the peer there, its consent, and says that the peer moved there, as it sends its records on
// the direct path only once it is there. Only a record that opened counts, as any datagram can name the peer as its
// source. The caller holds the lock of the layer, shared.
void PeerPunchHeard(PEER *p, const PEER_ADDR *from) {
	PEER_PUNCH *punch = &p->Punch;

	if (punch->State == PEER_PUNCH_CONNECTED && p->HasDirect && PeerAddrEqual(&p->Direct, from)) {
		InterlockedExchange64(&punch->LastHeard, (LONG64)PeerNow());
		InterlockedExchange(&punch->Moved, 1);
	}
}

// The NAT of the node and the address of its next mapping, into st
void PeerPunchStats(PEER_AGENT *a, PEER_STATS *st) {
	PEER_PUNCH_MODEL m;

	AcquireSRWLockShared(&a->Lock);
	PeerPunchModel(a, &m);
	ReleaseSRWLockShared(&a->Lock);

	st->Nat = m.Nat;
	if (PeerPunchPortOf(&m, m.Mappings + 1, &st->Predicted) == false)
		ZeroMemory(&st->Predicted, sizeof(PEER_ADDR));
}
