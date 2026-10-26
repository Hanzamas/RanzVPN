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
// the budget runs out and the pair stays on the relay.
//
// A probe proves who sent it, not where the sender is: an attacker on the path can send a captured probe from an
// address of its own (finding F3 of the second review of AUD-5, PR 405). So a meeting moves the peer to the direct path
// only at an address that proved it, by an exchange of nonces sealed to the peer (CORE-H2 #399). Of the two ends, the
// one with the lower static key leads: it answers a probe from an address with a challenge, a fresh nonce sealed to the
// peer and sent to that address; the other end answers a probe with a probe, so that the leader gets one. The other
// end answers the challenge, from the address the challenge reached it at, with a response that echoes the nonce and
// carries a nonce of its own; the leader takes the response only from the address its nonce went to, moves the peer
// to the direct path there, and sends a proof that echoes the second nonce, which moves the other end to the direct
// path at the address that proof came from, the one its own nonce went to. Only the peer can read a nonce, and it can
// echo one only from where the nonce reached it, so a probe that names an address the peer does not own sets no
// path. Each end moves once, on the one exchange that completed, so the two ends use the same pair of mappings; the
// relay carries the traffic of the pair until then, so nothing is interrupted.
//
// Locks: PeerPunchStart, PeerPunchInput and PeerPunchTick take the lock of the layer to read and change the punch of
// a peer; they seal and send the probes without it, as the rest of the layer does. PeerPunchCandidate reads the
// relays under the shared lock its caller (PeerSealSignal) already holds.

#include "Core/PeerInternal.h"

#include <string.h>

// The payload of a punch message: PEER_VERSION, the sequence, the type, a nonce and the echo of the peer's nonce
#define PEER_PUNCH_PAYLOAD_SIZE  (10 + 2 * PEER_PUNCH_NONCE_SIZE)
#define PEER_PUNCH_SEQ_THRESHOLD 16 // The largest reflexive-port step still read as a sequential NAT, not a random one
#define PEER_PUNCH_TICK_MAX      64 // The most probes one PeerTick gathers across all the peers it is punching

// The types of a punch message
#define PEER_PUNCH_PROBE     1 // A probe to a predicted address
#define PEER_PUNCH_CHALLENGE 2 // The leader's answer to a probe: a nonce
#define PEER_PUNCH_RESPONSE  3 // The other end's answer: the echo of that nonce and a nonce of its own
#define PEER_PUNCH_PROOF     4 // The leader's answer: the echo of the second nonce

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

// Seal a punch message of type for the peer of key, with nonce and echo (NULL for none), and send it to to
static void PeerPunchSend(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *to, UINT type, const UCHAR *nonce, const UCHAR *echo) {
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
	if (size != 0 && a->Send(a->SendParam, to, env, size))
		PeerCount(a, PEER_COUNT_SENT);
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
		PeerPunchSend(a, send[i].Key, &send[i].To, PEER_PUNCH_PROBE, NULL, NULL);
}

// A punch message that arrived from the address from: open it, check it is from a peer the node is punching and is not
// a replay, then take its part in the exchange of nonces. A probe draws a challenge from the leader and a probe from the
// other end; a challenge draws a response from the other end; a response that echoes the leader's nonce from the
// address it went to moves the peer to the direct path at the leader and draws a proof; a proof that echoes the other
// end's nonce from the address it went to moves the peer to the direct path there. A node already on the direct path
// takes a message and answers none, so a late probe of a burst leaves the path on the pair that met. A meeting counts
// as a prediction success. Called from PeerInput for a PEER_MSG_PUNCH datagram.
void PeerPunchInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_PUNCH_PAYLOAD_SIZE];
	UCHAR nonce[PEER_PUNCH_NONCE_SIZE];
	UINT len = 0;
	UINT reason = PEER_OK;
	UINT reply = 0;
	bool connected = false;

	ZeroMemory(nonce, sizeof(nonce));

	if (a->Config.Punch) {
		if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
			reason = PEER_DROP_FORGED;
		else if (len != PEER_PUNCH_PAYLOAD_SIZE || payload[0] != PEER_VERSION || payload[9] < PEER_PUNCH_PROBE || payload[9] > PEER_PUNCH_PROOF)
			reason = PEER_DROP_MALFORMED;
	} else {
		reason = PEER_DROP_MALFORMED;
	}

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = PeerGetUint64(payload + 1);
	UINT type = payload[9];
	const UCHAR *their_nonce = payload + 10;
	const UCHAR *echo = payload + 10 + PEER_PUNCH_NONCE_SIZE;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, sender);
		PEER_PUNCH *punch = (p != NULL ? &p->Punch : NULL);

		if (p == NULL) {
			reason = PEER_DROP_POLICY;
		} else if (punch->State != PEER_PUNCH_PROBING && punch->State != PEER_PUNCH_CONNECTED) {
			reason = PEER_DROP_FORGED; // No punch is open with this peer: an unsolicited or stale message
		} else if (seq <= PeerFloorOf(p, punch->LastSeq)) {
			reason = PEER_DROP_REPLAY;
		} else {
			bool leader = (memcmp(a->Key.Public, p->Info.Key, PEER_KEY_SIZE) < 0);

			punch->LastSeq = seq;

			if (punch->State == PEER_PUNCH_CONNECTED) {
				// On the direct path already: the exchange that got it there is the only one
			} else if (type == PEER_PUNCH_PROBE) {
				reply = (leader ? (PeerPunchNonce(punch, from, nonce) ? PEER_PUNCH_CHALLENGE : 0) : PEER_PUNCH_PROBE);
			} else if (type == PEER_PUNCH_CHALLENGE && leader == false) {
				reply = (PeerPunchNonce(punch, from, nonce) ? PEER_PUNCH_RESPONSE : 0);
			} else if ((type == PEER_PUNCH_RESPONSE && leader) || (type == PEER_PUNCH_PROOF && leader == false)) {
				connected = PeerPunchEcho(punch, from, echo);
				if (connected) {
					p->HasDirect = true;
					p->Direct = *from;
					punch->State = PEER_PUNCH_CONNECTED;
					reply = (leader ? PEER_PUNCH_PROOF : 0);
				}
			}
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	if (connected)
		PeerCount(a, PEER_COUNT_PUNCH_SUCCESSES);

	// A challenge carries the node's nonce; a response echoes the peer's and carries the node's; a proof echoes the
	// peer's
	if (reply == PEER_PUNCH_PROBE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_PROBE, NULL, NULL);
	else if (reply == PEER_PUNCH_CHALLENGE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_CHALLENGE, nonce, NULL);
	else if (reply == PEER_PUNCH_RESPONSE)
		PeerPunchSend(a, sender, from, PEER_PUNCH_RESPONSE, nonce, their_nonce);
	else if (reply == PEER_PUNCH_PROOF)
		PeerPunchSend(a, sender, from, PEER_PUNCH_PROOF, NULL, their_nonce);

	SecureZeroMemory(nonce, sizeof(nonce));
}
