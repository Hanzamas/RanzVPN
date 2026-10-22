// PeerPunch.c
// Port prediction and birthday-paradox hole punching for symmetric NAT (ADR-0015 decision 2; CORE-S5-4, #266). ICE
// (PeerIce.c, libjuice) gets a direct path through cone NATs; it cannot through a symmetric NAT, whose mapping gives
// a new public port per destination. This is Ranz's own code on top of the candidates the control plane already
// exchanges: it runs on the peer layer's own socket, not libjuice, so the simulated NATs of the harness carry it.
//
// A node learns its NAT's port allocation pattern from the reflexive ports its relays report (PeerPunchCandidate):
// two relays that saw the same port mean an endpoint-independent mapping (a cone, or a port-preserving NAT), whose
// next port is that same one; two that saw ports a small step apart mean a sequential symmetric NAT, whose next port
// is one more step on; ports far apart mean a random symmetric NAT, which cannot be predicted. A node that can
// predict puts its predicted next port in its signals as a PEER_CANDIDATE_PREDICTED, so the peer knows where to aim.
//
// The control plane triggers a punch with the signal exchange (PeerPunchStart, from PeerOpenSignal): each end sends
// authenticated probes (PEER_MSG_PUNCH envelopes) to the ports it predicts of the peer, the predicted port first and
// then a bounded birthday range above each reflexive and mapped candidate. A probe both opens the sender's own NAT
// mapping towards that address and, when it arrives, proves to the peer who sent it. Two sequential NATs meet when
// each aims its first probe at the other's predicted port, so their two mappings address each other; a cone paired
// with a random NAT meets because the random side reaches the cone's one predictable port and the cone learns the
// random side's mapping from that probe and answers it. Two random NATs predict nothing, so the probes miss until
// the budget runs out and the pair stays on the relay. On a meeting the peer moves to the direct path (HasDirect, as
// PeerSetDirect sets it), with the relay still carrying its traffic until then, so nothing is interrupted.
//
// Locks: PeerPunchStart, PeerPunchInput and PeerPunchTick take the lock of the layer to read and change the punch of
// a peer; they seal and send the probes without it, as the rest of the layer does. PeerPunchCandidate reads the
// relays under the shared lock its caller (PeerSealSignal) already holds.

#include "Core/PeerInternal.h"

#include <string.h>

#define PEER_PUNCH_PAYLOAD_SIZE  9  // The payload of a probe: PEER_VERSION and the sequence, as a bind's is
#define PEER_PUNCH_SEQ_THRESHOLD 16 // The largest reflexive-port step still read as a sequential NAT, not a random one
#define PEER_PUNCH_TICK_MAX      64 // The most probes one PeerTick gathers across all the peers it is punching

// The budget, the birthday range and the per-tick rate of a punch, the configured values or the defaults
static UINT PeerPunchBudget(PEER_AGENT *a) {
	return (a->Config.PunchBudget != 0 ? a->Config.PunchBudget : PEER_DEFAULT_PUNCH_BUDGET);
}

static UINT PeerPunchPorts(PEER_AGENT *a) {
	return (a->Config.PunchPorts != 0 ? a->Config.PunchPorts : PEER_DEFAULT_PUNCH_PORTS);
}

static UINT PeerPunchRate(PEER_AGENT *a) {
	return (a->Config.PunchRate != 0 ? a->Config.PunchRate : PEER_DEFAULT_PUNCH_RATE);
}

// The node's predicted next public port from the reflexive ports its bound relays reported, into c. False when the
// node has fewer than two reflexive samples or its NAT allocates at random, so the node offers no prediction and the
// peer must learn its mapping from a probe instead. The caller holds the lock.
static bool PeerPunchPredict(PEER_AGENT *a, PEER_CANDIDATE *c) {
	const PEER_RELAY *lo = NULL;
	const PEER_RELAY *hi = NULL;
	UINT count = 0;

	for (UINT i = 0; i < a->NumRelays; i++) {
		const PEER_RELAY *r = &a->Relays[i];

		if (r->Bound == false || r->Observed.Port == 0)
			continue;

		count++;
		if (lo == NULL || r->Observed.Port < lo->Observed.Port)
			lo = r;
		if (hi == NULL || r->Observed.Port > hi->Observed.Port)
			hi = r;
	}

	if (count < 2)
		return false;

	ZeroMemory(c, sizeof(PEER_CANDIDATE));
	c->Type = PEER_CANDIDATE_PREDICTED;

	UINT span = hi->Observed.Port - lo->Observed.Port;
	if (span == 0) {
		// The same port from two destinations: an endpoint-independent mapping (a cone or a port-preserving NAT),
		// whose next mapping keeps that port
		c->Addr = hi->Observed;
		return true;
	}

	if (span > PEER_PUNCH_SEQ_THRESHOLD)
		return false; // Ports far apart: a random symmetric NAT, which cannot be predicted

	// A sequential symmetric NAT: the port grows by a step per mapping, so the next one is a step past the highest seen
	UINT step = span / (count - 1);
	if (step == 0)
		step = 1;

	UINT next = hi->Observed.Port + step;
	if (next > 0xFFFF)
		return false;

	c->Addr = hi->Observed;
	c->Addr.Port = (USHORT)next;
	return true;
}

// The predicted-port candidate of the node's signals, at most max (0 or 1). The caller holds the shared lock.
UINT PeerPunchCandidate(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max) {
	if (a->Config.Punch == false || max == 0)
		return 0;

	return (PeerPunchPredict(a, c) ? 1 : 0);
}

// Add the address addr to the targets of the punch, unless it is there already or they are full. The caller holds the
// lock.
static void PeerPunchAddTarget(PEER_PUNCH *punch, const PEER_ADDR *addr) {
	if (addr->Port == 0)
		return;

	for (UINT i = 0; i < punch->NumTargets; i++)
		if (PeerAddrEqual(&punch->Targets[i], addr))
			return;

	if (punch->NumTargets < PEER_PUNCH_MAX_TARGETS)
		punch->Targets[punch->NumTargets++] = *addr;
}

// Add the range of ports [base.Port, base.Port + ports) on the address of base to the targets. The caller holds the
// lock.
static void PeerPunchAddRange(PEER_PUNCH *punch, const PEER_ADDR *base, UINT ports) {
	PEER_ADDR a = *base;

	for (UINT i = 0; i <= ports && a.Port != 0; i++) {
		PeerPunchAddTarget(punch, &a);
		if ((UINT)base->Port + i + 1 > 0xFFFF)
			break;
		a.Port = (USHORT)(base->Port + i + 1);
	}
}

// Build the targets of a punch of the peer p from its candidates: its predicted port first, so two sequential NATs
// aim their first probes at each other; then a birthday range above each predicted, reflexive and mapped candidate.
// A host candidate is skipped: it is a private address the peer cannot be reached at from outside. The caller holds
// the lock.
static void PeerPunchTargets(PEER_AGENT *a, PEER *p) {
	PEER_PUNCH *punch = &p->Punch;
	UINT ports = PeerPunchPorts(a);

	punch->NumTargets = 0;

	for (UINT i = 0; i < p->NumCandidates; i++)
		if (p->Candidates[i].Type == PEER_CANDIDATE_PREDICTED)
			PeerPunchAddTarget(punch, &p->Candidates[i].Addr);

	for (UINT i = 0; i < p->NumCandidates; i++) {
		UINT type = p->Candidates[i].Type;

		if (type == PEER_CANDIDATE_PREDICTED || type == PEER_CANDIDATE_SRFLX || type == PEER_CANDIDATE_MAPPED)
			PeerPunchAddRange(punch, &p->Candidates[i].Addr, ports);
	}
}

// Begin, or begin again, a punch of the peer of key, which the control plane has just signalled. A punch starts only
// when there is no direct path yet; one already probing or connected is left as it is. Without the lock held.
void PeerPunchStart(PEER_AGENT *a, const UCHAR *key) {
	bool attempt = false;

	if (a->Config.Punch == false)
		return;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL && p->HasDirect == false && (p->Punch.State == PEER_PUNCH_NONE || p->Punch.State == PEER_PUNCH_FAILED)) {
			PEER_PUNCH *punch = &p->Punch;

			PeerPunchTargets(a, p);

			if (punch->NumTargets == 0) {
				punch->State = PEER_PUNCH_FAILED;
			} else {
				punch->State = PEER_PUNCH_PROBING;
				punch->Budget = PeerPunchBudget(a);
				punch->Next = 0;
				attempt = (punch->Attempted == false);
				punch->Attempted = true;
			}
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (attempt)
		PeerCount(a, PEER_COUNT_PUNCH_ATTEMPTS);
}

// One probe to send: the peer it is for and the address it goes to
typedef struct PEER_PUNCH_SEND {
	UCHAR Key[PEER_KEY_SIZE];
	PEER_ADDR To;
} PEER_PUNCH_SEND;

// Seal a probe for the peer of key and send it to to
static void PeerPunchProbe(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *to) {
	UCHAR payload[PEER_PUNCH_PAYLOAD_SIZE];
	UCHAR env[PEER_ENVELOPE_HEADER + PEER_PUNCH_PAYLOAD_SIZE + PEER_ENVELOPE_TAG];

	payload[0] = PEER_VERSION;
	PeerPutUint64(payload + 1, PeerNextSequence(a));

	UINT size = PeerSeal(a, key, PEER_MSG_PUNCH, payload, sizeof(payload), env, sizeof(env));
	if (size != 0 && a->Send(a->SendParam, to, env, size))
		PeerCount(a, PEER_COUNT_SENT);
}

// Send the next bounded burst of probes of every peer the node is punching, and mark a punch failed once its budget
// is spent with no meeting. Called from PeerTick.
void PeerPunchTick(PEER_AGENT *a) {
	PEER_PUNCH_SEND send[PEER_PUNCH_TICK_MAX];
	UINT num = 0;

	if (a->Config.Punch == false)
		return;

	ZeroMemory(send, sizeof(send));

	UINT rate = PeerPunchRate(a);

	AcquireSRWLockExclusive(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers && num < PEER_PUNCH_TICK_MAX; i++) {
			PEER *p = &a->Peers[i];
			PEER_PUNCH *punch = &p->Punch;

			if (punch->State != PEER_PUNCH_PROBING)
				continue;

			for (UINT k = 0; k < rate && punch->Budget != 0 && num < PEER_PUNCH_TICK_MAX; k++) {
				CopyMemory(send[num].Key, p->Info.Key, PEER_KEY_SIZE);
				send[num].To = punch->Targets[punch->Next];
				num++;

				punch->Next = (punch->Next + 1) % punch->NumTargets;
				punch->Budget--;
			}

			if (punch->Budget == 0)
				punch->State = PEER_PUNCH_FAILED;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	for (UINT i = 0; i < num; i++)
		PeerPunchProbe(a, send[i].Key, &send[i].To);
}

// A probe that arrived from the address from: open it, check it is from a peer the node is punching and is not a
// replay, then make from the direct path of that peer, as its own mapping now reaches it. The node answers the first
// probe it takes, so the peer learns the node's mapping too, and counts the meeting a prediction success. Called from
// PeerInput for a PEER_MSG_PUNCH datagram.
void PeerPunchInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_PUNCH_PAYLOAD_SIZE];
	UINT len = 0;
	UINT reason = PEER_OK;
	bool connected = false;
	bool answer = false;

	if (a->Config.Punch) {
		if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
			reason = PEER_DROP_FORGED;
		else if (len != PEER_PUNCH_PAYLOAD_SIZE || payload[0] != PEER_VERSION)
			reason = PEER_DROP_MALFORMED;
	} else {
		reason = PEER_DROP_MALFORMED;
	}

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = PeerGetUint64(payload + 1);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, sender);
		PEER_PUNCH *punch = (p != NULL ? &p->Punch : NULL);

		if (p == NULL) {
			reason = PEER_DROP_POLICY;
		} else if (punch->State != PEER_PUNCH_PROBING && punch->State != PEER_PUNCH_CONNECTED) {
			reason = PEER_DROP_FORGED; // No punch is open with this peer: an unsolicited or stale probe
		} else if (seq <= punch->LastSeq) {
			reason = PEER_DROP_REPLAY;
		} else {
			punch->LastSeq = seq;
			p->HasDirect = true;
			p->Direct = *from;
			connected = (punch->State != PEER_PUNCH_CONNECTED);
			punch->State = PEER_PUNCH_CONNECTED;
			answer = connected;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	if (connected)
		PeerCount(a, PEER_COUNT_PUNCH_SUCCESSES);

	// Answer the first probe once, so the peer learns this node's mapping; the peer, once connected, does not answer
	// back, so the exchange stops
	if (answer)
		PeerPunchProbe(a, sender, from);
}
