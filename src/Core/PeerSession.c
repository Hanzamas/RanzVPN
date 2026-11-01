// PeerSession.c
// The peer session of a node with a peer (CORE-H2 #399): every data datagram between two nodes is a record under the
// keys of a Noise handshake between their static keys, in the manner of WireGuard, on whichever path the pair uses,
// through a relay or direct. The handshake is Noise_IK_25519_AESGCM_SHA256 (Noise.c), the pattern of the session
// layer, with the prologue "ranz peer session 1": the initiator knows the responder's static key from the Peer
// objects that the control plane set, and the responder takes the initiator's only as the one of the peer that the
// clear header names.
//
// The datagrams (PeerRecordParse) all start with the clear header that a relay forwards by, its kind, the source key
// and the destination key:
// - An initiation (PEER_MSG_INIT): the sender's index, then the first message of Noise_IK. Its payload is a
//   timestamp that grows with the clock (PeerNextSequence) and the sender's index again, so a replayed initiation is
//   refused, as WireGuard refuses one by its TAI64N timestamp, even after the responder lost its memory of the peer.
// - A response (PEER_MSG_RESPONSE): the sender's index and the receiver's, then the second message, whose payload
//   repeats the two indices, so the clear ones cannot be changed on the way.
// - A record (PEER_MSG_RECORD): the receiver's index and a counter, then the payload under AES-GCM with the counter as
//   the Noise nonce and the whole clear header as the associated data. A record is refused when its index names no
//   keys of its source (another node's session), when its counter is not new to a sliding window of
//   PEER_WINDOW_BITS, and when it does not decrypt: a change of any byte. An empty record is a keepalive.
//
// The first datagram to a peer that has no keys starts a handshake and waits in a queue of PEER_SESSION_QUEUE, which
// goes out once the response is in; an initiation that has no answer goes again after PEER_SESSION_RETRY. The
// initiator reads a response on a copy of its handshake, so a response that does not open is dropped and leaves the
// handshake on its way, as WireGuard ignores one: the index that it names is in the clear, and anyone can make one
// (CORE-H2-R1 #436). When both ends start at once, the end with the lower static key keeps its own handshake and
// ignores the other's initiation, and the other gives its own up and answers, so the two end in one session. The
// responder sends under the new keys at once when it had none that the initiator confirmed, and keeps the ones that it
// had as Previous, for the records under them that the initiation overtook on the way (CORE-H2-R1 #436); when it had
// confirmed keys, the new ones wait as Next until the initiator's first record under them, and the old ones keep the
// traffic going meanwhile, so a rekey loses nothing. The keys before stay as Previous for the records still on their
// way. The initiator of the keys replaces them after SessionRekeyTime, and either end after SessionRekeyDatagrams
// records under them; keys three times older than SessionRekeyTime are dropped. A record with a payload that had no
// answer for SessionKeepalive gets a keepalive back, and a session with no record from the peer for SessionTimeout is
// dropped; the next datagram starts a new handshake. The keys belong to the pair of nodes, not to the path, so an
// Upgrade or a Fallback keeps them.
//
// Locks: the caller holds the lock of the layer, shared, so the PEER stays; the session has a lock of its own, and
// the handshake takes KeyLock for the Diffie-Hellman of the node's static key. Nothing here sends: the layer sends
// what these functions write (Peer.c).

#include "Core/PeerInternal.h"

#include <string.h>

#define PEER_SESSION_PROLOGUE "ranz peer session 1"
#define PEER_MAX_COUNTER      0xFFFFFFFFFFFFFFFEULL // n = 2^64 - 1 is reserved (Noise section 5.1)

static void PeerPutUint32(UCHAR *p, UINT v) {
	p[0] = (UCHAR)(v >> 24);
	p[1] = (UCHAR)(v >> 16);
	p[2] = (UCHAR)(v >> 8);
	p[3] = (UCHAR)v;
}

static UINT PeerGetUint32(const UCHAR *p) {
	return ((UINT)p[0] << 24) | ((UINT)p[1] << 16) | ((UINT)p[2] << 8) | p[3];
}

// The timers of the sessions, the configured values or the defaults
static UINT64 PeerRekeyDatagrams(PEER_AGENT *a) {
	return (a->Config.SessionRekeyDatagrams != 0 ? a->Config.SessionRekeyDatagrams : PEER_DEFAULT_REKEY_DATAGRAMS);
}

static UINT64 PeerRekeyTime(PEER_AGENT *a) {
	return (a->Config.SessionRekeyTime != 0 ? a->Config.SessionRekeyTime : PEER_DEFAULT_REKEY_TIME);
}

static UINT64 PeerSessionTimeout(PEER_AGENT *a) {
	return (a->Config.SessionTimeout != 0 ? a->Config.SessionTimeout : PEER_DEFAULT_SESSION_TIMEOUT);
}

static UINT64 PeerKeepalive(PEER_AGENT *a) {
	return (a->Config.SessionKeepalive != 0 ? a->Config.SessionKeepalive : PEER_DEFAULT_KEEPALIVE);
}

// Parse the clear header of a datagram between two nodes: an initiation, a response or a record of the size its kind
// has. False for anything else. The keys point into data.
bool PeerRecordParse(const UCHAR *data, UINT size, PEER_RECORD_INFO *r) {
	bool ok = false;

	if (r == NULL)
		return false;

	ZeroMemory(r, sizeof(PEER_RECORD_INFO));
	if (data == NULL || size < PEER_DATA_HEADER_SIZE || size > PEER_MAX_DATAGRAM)
		return false;

	switch (data[0]) {
	case PEER_MSG_INIT:
		if (size == PEER_INIT_SIZE) {
			r->Sender = PeerGetUint32(data + PEER_DATA_HEADER_SIZE);
			r->HeaderSize = PEER_INIT_HEADER;
			ok = true;
		}
		break;
	case PEER_MSG_RESPONSE:
		if (size == PEER_RESPONSE_SIZE) {
			r->Sender = PeerGetUint32(data + PEER_DATA_HEADER_SIZE);
			r->Receiver = PeerGetUint32(data + PEER_DATA_HEADER_SIZE + 4);
			r->HeaderSize = PEER_RESPONSE_HEADER;
			ok = true;
		}
		break;
	case PEER_MSG_RECORD:
		if (size >= PEER_RECORD_HEADER + PEER_RECORD_TAG) {
			r->Receiver = PeerGetUint32(data + PEER_DATA_HEADER_SIZE);
			r->Counter = PeerGetUint64(data + PEER_DATA_HEADER_SIZE + 4);
			r->HeaderSize = PEER_RECORD_HEADER;
			ok = (r->Counter <= PEER_MAX_COUNTER);
		}
		break;
	default:
		break;
	}

	if (ok == false) {
		ZeroMemory(r, sizeof(PEER_RECORD_INFO));
		return false;
	}

	r->Kind = data[0];
	r->Src = data + 1;
	r->Dst = data + 1 + PEER_KEY_SIZE;

	return true;
}

// Parse the payload of a handshake message of kind: the timestamp and the index of an initiation, the two indices of
// a response. False unless it is exactly that.
bool PeerHandshakeParse(UINT kind, const UCHAR *payload, UINT size, PEER_HANDSHAKE_INFO *h) {
	if (h == NULL)
		return false;

	ZeroMemory(h, sizeof(PEER_HANDSHAKE_INFO));
	if (payload == NULL)
		return false;

	if (kind == PEER_MSG_INIT && size == PEER_INIT_PAYLOAD) {
		h->Timestamp = PeerGetUint64(payload);
		h->Sender = PeerGetUint32(payload + 8);
		return h->Sender != 0;
	}

	if (kind == PEER_MSG_RESPONSE && size == PEER_RESPONSE_PAYLOAD) {
		h->Sender = PeerGetUint32(payload);
		h->Receiver = PeerGetUint32(payload + 4);
		return h->Sender != 0 && h->Receiver != 0;
	}

	return false;
}

PEER_SESSION *PeerSessionNew() {
	PEER_SESSION *s = (PEER_SESSION *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_SESSION));

	if (s != NULL)
		InitializeSRWLock(&s->Lock);

	return s;
}

static void PeerKeypairFree(PEER_KEYPAIR *k) {
	if (k->Valid) {
		NoiseCipherFree(&k->Send);
		NoiseCipherFree(&k->Recv);
	}

	SecureZeroMemory(k, sizeof(PEER_KEYPAIR));
}

// Move the keys of src to dst, whose keys are freed; src is left empty
static void PeerKeypairMove(PEER_KEYPAIR *dst, PEER_KEYPAIR *src) {
	PeerKeypairFree(dst);
	*dst = *src;
	SecureZeroMemory(src, sizeof(PEER_KEYPAIR));
}

// Drop every key, the handshake on its way and the queue. The caller holds the lock of the session.
static void PeerSessionClear(PEER_SESSION *s) {
	PeerKeypairFree(&s->Current);
	PeerKeypairFree(&s->Previous);
	PeerKeypairFree(&s->Next);

	if (s->Pending)
		NoiseHandshakeFree(&s->Handshake);
	s->Pending = false;
	s->PendingTries = 0;
	s->SentUnderKey = 0;
}

void PeerSessionFree(PEER_SESSION *s) {
	if (s == NULL)
		return;

	PeerSessionClear(s);
	SecureZeroMemory(s, sizeof(PEER_SESSION));
	HeapFree(GetProcessHeap(), 0, s);
}

// The session of the peer p, made now if create and it has none; NULL when there is none. The caller holds the lock of
// the layer, shared: two threads that make one at once keep the first.
static PEER_SESSION *PeerSessionOf(PEER *p, bool create) {
	PEER_SESSION *s = (PEER_SESSION *)InterlockedCompareExchangePointer((PVOID volatile *)&p->Session, NULL, NULL);

	if (s != NULL || create == false)
		return s;

	s = PeerSessionNew();
	if (s == NULL)
		return NULL;

	PEER_SESSION *old = (PEER_SESSION *)InterlockedCompareExchangePointer((PVOID volatile *)&p->Session, s, NULL);
	if (old != NULL) {
		PeerSessionFree(s);
		return old;
	}

	return s;
}

// A new index for keys of the session s: random, not 0 and not one of its keys now. 0 when the random generator fails.
static UINT PeerSessionIndex(PEER_SESSION *s) {
	for (UINT i = 0; i < 8; i++) {
		UINT index = 0;

		if (CryptoRandom(&index, sizeof(index)) == false)
			return 0;

		if (index != 0 && index != s->Current.LocalIndex && index != s->Previous.LocalIndex && index != s->Next.LocalIndex &&
		    (s->Pending == false || index != s->PendingIndex))
			return index;
	}

	return 0;
}

// The handshake of a session of the node a: Noise_IK with its static key, and the peer's for the initiator
static bool PeerSessionNoiseInit(PEER_AGENT *a, NOISE_HANDSHAKE *hs, bool initiator, const UCHAR *remote) {
	return NoiseHandshakeInit(hs, NOISE_SUITE_IK, initiator, PEER_SESSION_PROLOGUE, sizeof(PEER_SESSION_PROLOGUE) - 1,
	                          a->Key.Identity != NULL ? NULL : a->Key.Private, a->Key.Identity, remote);
}

// The kind and the two keys of a datagram from the node a to the peer p
static void PeerSessionHeader(PEER_AGENT *a, PEER *p, UINT kind, UCHAR *buf) {
	buf[0] = (UCHAR)kind;
	CopyMemory(buf + 1, a->Key.Public, PEER_KEY_SIZE);
	CopyMemory(buf + 1 + PEER_KEY_SIZE, p->Info.Key, PEER_KEY_SIZE);
}

// Write a new initiation to the peer p into buf, in place of the one on its way, if any. Returns its size, 0 when a
// step failed. The caller holds the lock of the session.
static UINT PeerSessionWriteInit(PEER_AGENT *a, PEER *p, PEER_SESSION *s, UCHAR *buf) {
	UCHAR payload[PEER_INIT_PAYLOAD];
	UINT len = 0;

	if (s->Pending)
		NoiseHandshakeFree(&s->Handshake);
	s->Pending = false;

	UINT index = PeerSessionIndex(s);
	if (index == 0)
		return 0;

	PeerPutUint64(payload, PeerNextSequence(a));
	PeerPutUint32(payload + 8, index);

	AcquireSRWLockExclusive(&a->KeyLock);
	bool ok = PeerSessionNoiseInit(a, &s->Handshake, true, p->Info.Key) &&
	          NoiseHandshakeWrite(&s->Handshake, payload, sizeof(payload), buf + PEER_INIT_HEADER, PEER_MAX_DATAGRAM - PEER_INIT_HEADER, &len);
	ReleaseSRWLockExclusive(&a->KeyLock);

	if (ok == false || PEER_INIT_HEADER + len != PEER_INIT_SIZE) {
		NoiseHandshakeFree(&s->Handshake);
		return 0;
	}

	PeerSessionHeader(a, p, PEER_MSG_INIT, buf);
	PeerPutUint32(buf + PEER_DATA_HEADER_SIZE, index);

	s->Pending = true;
	s->PendingIndex = index;
	s->PendingTick = PeerNow();

	return PEER_INIT_SIZE;
}

// Write a record of size bytes of data under the current keys into buf. Returns its size, 0 when the keys are used up
// or the encryption failed. The caller holds the lock of the session.
static UINT PeerSessionWriteRecord(PEER_AGENT *a, PEER *p, PEER_SESSION *s, const void *data, UINT size, UCHAR *buf) {
	PEER_KEYPAIR *k = &s->Current;

	if (k->Valid == false || k->Send.Nonce > PEER_MAX_COUNTER)
		return 0;

	PeerSessionHeader(a, p, PEER_MSG_RECORD, buf);
	PeerPutUint32(buf + PEER_DATA_HEADER_SIZE, k->RemoteIndex);
	PeerPutUint64(buf + PEER_DATA_HEADER_SIZE + 4, k->Send.Nonce);

	if (NoiseCipherEncrypt(&k->Send, buf, PEER_RECORD_HEADER, data, size, buf + PEER_RECORD_HEADER) == false)
		return 0;

	s->SentUnderKey++;
	s->LastSent = PeerNow();

	return PEER_RECORD_HEADER + size + PEER_RECORD_TAG;
}

// Whether the current keys are due to be replaced: after the records of one key, by either end, or after the rekey
// time, by the end that started their handshake
static bool PeerSessionRekeyDue(PEER_AGENT *a, PEER_SESSION *s, UINT64 now) {
	if (s->Current.Valid == false)
		return false;

	return s->SentUnderKey >= PeerRekeyDatagrams(a) || (s->Current.Initiator && now >= s->Current.Created + PeerRekeyTime(a));
}

// Start an initiation unless one is on its way and not yet due again. The caller holds the lock of the session, and read
// now under it.
static UINT PeerSessionStart(PEER_AGENT *a, PEER *p, PEER_SESSION *s, UCHAR *buf, UINT64 now) {
	if (s->Pending && now < s->PendingTick + PEER_SESSION_RETRY)
		return 0;

	if (s->Pending == false)
		s->PendingTries = 0;

	UINT ret = PeerSessionWriteInit(a, p, s, buf);
	if (ret != 0)
		s->PendingTries++;

	return ret;
}

// Seal size bytes of data for the peer p: a record into buf under the current keys, whose size it returns; or, with no
// keys yet, data into the queue (*queued) and, unless a handshake is on its way, an initiation into buf. *rekey tells
// that the keys are due to be replaced (PeerSessionInitiate). 0 when there is nothing to send. The caller holds the
// lock of the layer, shared.
UINT PeerSessionSeal(PEER_AGENT *a, PEER *p, const void *data, UINT size, UCHAR *buf, bool *queued, bool *rekey) {
	UINT ret = 0;

	*queued = false;
	*rekey = false;
	if (size > PEER_MAX_PAYLOAD)
		return 0;

	PEER_SESSION *s = PeerSessionOf(p, true);
	if (s == NULL)
		return 0;

	AcquireSRWLockExclusive(&s->Lock);
	{
		// The clock once the lock is held: no initiation or keys that another thread made under it are later
		// (CORE-S5-6-R3, #574)
		UINT64 now = PeerNow();

		if (s->Current.Valid) {
			ret = PeerSessionWriteRecord(a, p, s, data, size, buf);
			*rekey = (s->Pending == false && PeerSessionRekeyDue(a, s, now));
		} else {
			if (s->QueueNum < PEER_SESSION_QUEUE) {
				if (size != 0)
					CopyMemory(s->Queue[s->QueueNum], data, size);
				s->QueueSize[s->QueueNum] = size;
				s->QueueNum++;
				*queued = true;
			}

			ret = PeerSessionStart(a, p, s, buf, now);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	return ret;
}

// An initiation to the peer p into buf, for a rekey, unless one is on its way; returns its size, 0 for none. The caller
// holds the lock of the layer, shared.
UINT PeerSessionInitiate(PEER_AGENT *a, PEER *p, UCHAR *buf) {
	UINT ret = 0;
	PEER_SESSION *s = PeerSessionOf(p, true);

	if (s == NULL)
		return 0;

	AcquireSRWLockExclusive(&s->Lock);
	ret = PeerSessionStart(a, p, s, buf, PeerNow());
	ReleaseSRWLockExclusive(&s->Lock);

	return ret;
}

// Whether the counter c is new to the window of the keys k: above the highest one taken, or within the window below
// it and not taken yet
static bool PeerWindowCheck(const PEER_KEYPAIR *k, UINT64 c) {
	if (k->RecvAny == false || c > k->RecvMax)
		return true;

	if (k->RecvMax - c >= PEER_WINDOW_BITS)
		return false;

	UINT bit = (UINT)(c % PEER_WINDOW_BITS);

	return (k->Window[bit / 64] & (1ULL << (bit % 64))) == 0;
}

// Mark the counter c taken: the window moves up to it when it is the highest, and the counters it passes are cleared
static void PeerWindowUpdate(PEER_KEYPAIR *k, UINT64 c) {
	if (k->RecvAny == false) {
		ZeroMemory(k->Window, sizeof(k->Window));
		k->RecvMax = c;
		k->RecvAny = true;
	} else if (c > k->RecvMax) {
		if (c - k->RecvMax >= PEER_WINDOW_BITS) {
			ZeroMemory(k->Window, sizeof(k->Window));
		} else {
			for (UINT64 i = k->RecvMax + 1; i < c; i++) {
				UINT bit = (UINT)(i % PEER_WINDOW_BITS);

				k->Window[bit / 64] &= ~(1ULL << (bit % 64));
			}
		}
		k->RecvMax = c;
	}

	UINT bit = (UINT)(c % PEER_WINDOW_BITS);
	k->Window[bit / 64] |= (1ULL << (bit % 64));
}

// An initiation from the peer p: answer it with a response in o and take the new keys, unless it does not open, is not
// from p, is a replay, or crosses the node's own initiation and the node has the lower key. The caller holds the lock
// of the session.
static UINT PeerSessionTakeInit(PEER_AGENT *a, PEER *p, PEER_SESSION *s, const PEER_RECORD_INFO *r, const UCHAR *data, UINT size, PEER_SESSION_OUT *o) {
	NOISE_HANDSHAKE hs;
	UCHAR payload[PEER_INIT_PAYLOAD];
	UCHAR reply[PEER_RESPONSE_PAYLOAD];
	PEER_HANDSHAKE_INFO h;
	PEER_KEYPAIR k;
	UINT len = 0;
	UINT out = 0;
	UINT reason = PEER_OK;

	ZeroMemory(&k, sizeof(k));

	AcquireSRWLockExclusive(&a->KeyLock);
	bool ok = PeerSessionNoiseInit(a, &hs, false, NULL) &&
	          NoiseHandshakeRead(&hs, data + r->HeaderSize, size - r->HeaderSize, payload, sizeof(payload), &len);
	ReleaseSRWLockExclusive(&a->KeyLock);

	if (ok == false || PeerHandshakeParse(PEER_MSG_INIT, payload, len, &h) == false || h.Sender != r->Sender ||
	    memcmp(hs.RemoteStatic, p->Info.Key, PEER_KEY_SIZE) != 0) {
		reason = PEER_DROP_FORGED;
	} else if (h.Timestamp <= PeerFloorOf(p, s->LastInit)) {
		reason = PEER_DROP_REPLAY;
	} else if (s->Pending && memcmp(a->Key.Public, p->Info.Key, PEER_KEY_SIZE) < 0) {
		// Two handshakes at once: the node with the lower key keeps its own, which the peer answers
		reason = PEER_OK;
	} else {
		UINT index = PeerSessionIndex(s);

		PeerPutUint32(reply, index);
		PeerPutUint32(reply + 4, h.Sender);

		AcquireSRWLockExclusive(&a->KeyLock);
		ok = index != 0 && NoiseHandshakeWrite(&hs, reply, sizeof(reply), o->Reply + PEER_RESPONSE_HEADER, PEER_MAX_DATAGRAM - PEER_RESPONSE_HEADER, &out);
		ReleaseSRWLockExclusive(&a->KeyLock);

		CopyMemory(k.Id, hs.H, PEER_SESSION_ID_SIZE);

		if (ok == false || PEER_RESPONSE_HEADER + out != PEER_RESPONSE_SIZE || NoiseHandshakeSplit(&hs, &k.Send, &k.Recv) == false) {
			reason = PEER_DROP_SESSION;
		} else {
			s->LastInit = h.Timestamp;

			// The node that lost the tie of two handshakes at once gives its own up
			if (s->Pending)
				NoiseHandshakeFree(&s->Handshake);
			s->Pending = false;
			s->PendingTries = 0;

			k.Valid = true;
			k.LocalIndex = index;
			k.RemoteIndex = h.Sender;
			k.Created = PeerNow();

			// Keys the peer has confirmed stay in use until its first record under the new ones. Else the new ones
			// replace them at once, and keys that the peer has not confirmed yet stay as the keys before: the peer may
			// have sent records under them that this initiation overtook on the way (CORE-H2-R1 #436)
			if (s->Current.Valid && s->Current.Confirmed) {
				PeerKeypairMove(&s->Next, &k);
			} else {
				if (s->Current.Valid)
					PeerKeypairMove(&s->Previous, &s->Current);
				PeerKeypairMove(&s->Current, &k);
				s->SentUnderKey = 0;
				o->Flush = (s->QueueNum != 0);
			}

			PeerSessionHeader(a, p, PEER_MSG_RESPONSE, o->Reply);
			PeerPutUint32(o->Reply + PEER_DATA_HEADER_SIZE, index);
			PeerPutUint32(o->Reply + PEER_DATA_HEADER_SIZE + 4, h.Sender);
			o->ReplySize = PEER_RESPONSE_SIZE;

			s->Handshakes++;
			PeerCount(a, PEER_COUNT_HANDSHAKES);
		}
	}

	NoiseHandshakeFree(&hs);
	SecureZeroMemory(payload, sizeof(payload));

	return reason;
}

// A response from the peer p to the node's initiation: the new keys become the current ones, and the queue goes out.
// The response is read on a copy of the handshake, so one that does not open is dropped and leaves the handshake on its
// way, for the peer's own response or the timer: the index that a response names is in the clear, so anyone that saw
// the initiation can make one, and WireGuard ignores such a response too (CORE-H2-R1 #436). The caller holds the lock
// of the session.
static UINT PeerSessionTakeResponse(PEER_AGENT *a, PEER_SESSION *s, const PEER_RECORD_INFO *r, const UCHAR *data, UINT size, PEER_SESSION_OUT *o) {
	NOISE_HANDSHAKE hs;
	UCHAR payload[PEER_RESPONSE_PAYLOAD];
	PEER_HANDSHAKE_INFO h;
	PEER_KEYPAIR k;
	UINT len = 0;

	if (s->Pending == false || r->Receiver != s->PendingIndex)
		return PEER_DROP_SESSION;

	ZeroMemory(&k, sizeof(k));

	// The copy owns no key object of the handshake: the second message of IK (<- e, ee, se) mixes no key before ee,
	// which replaces the cipher of the first message, and IK has no KEM key
	hs = s->Handshake;
	hs.Cipher.Aead.Key = NULL;
	hs.Kem.Key = NULL;

	AcquireSRWLockExclusive(&a->KeyLock);
	bool ok = NoiseHandshakeRead(&hs, data + r->HeaderSize, size - r->HeaderSize, payload, sizeof(payload), &len);
	ReleaseSRWLockExclusive(&a->KeyLock);

	ok = ok && PeerHandshakeParse(PEER_MSG_RESPONSE, payload, len, &h) && h.Sender == r->Sender && h.Receiver == s->PendingIndex;
	if (ok)
		CopyMemory(k.Id, hs.H, PEER_SESSION_ID_SIZE);
	ok = ok && NoiseHandshakeSplit(&hs, &k.Send, &k.Recv);
	NoiseHandshakeFree(&hs);
	SecureZeroMemory(payload, sizeof(payload));

	if (ok == false)
		return PEER_DROP_FORGED;

	// The response completed the handshake
	UINT index = s->PendingIndex;
	NoiseHandshakeFree(&s->Handshake);
	s->Pending = false;

	k.Valid = true;
	k.Initiator = true;
	k.Confirmed = true;
	k.LocalIndex = index;
	k.RemoteIndex = h.Sender;
	k.Created = PeerNow();

	PeerKeypairMove(&s->Previous, &s->Current);
	PeerKeypairMove(&s->Current, &k);
	PeerKeypairFree(&s->Next);
	s->SentUnderKey = 0;
	s->PendingTries = 0;

	s->Handshakes++;
	PeerCount(a, PEER_COUNT_HANDSHAKES);

	// The queue goes now, or a keepalive, so that the responder has a record under the new keys
	o->Flush = true;
	o->Keepalive = true;

	return PEER_OK;
}

// A record from the peer: under which of its keys by the index, new to the window, decrypted. A record under the
// responder's new keys makes them the current ones. The caller holds the lock of the session.
static UINT PeerSessionTakeRecord(PEER_SESSION *s, const PEER_RECORD_INFO *r, const UCHAR *data, UINT size, PEER_SESSION_OUT *o) {
	PEER_KEYPAIR *k = NULL;

	if (s->Current.Valid && s->Current.LocalIndex == r->Receiver)
		k = &s->Current;
	else if (s->Previous.Valid && s->Previous.LocalIndex == r->Receiver)
		k = &s->Previous;
	else if (s->Next.Valid && s->Next.LocalIndex == r->Receiver)
		k = &s->Next;

	if (k == NULL)
		return PEER_DROP_SESSION;

	if (PeerWindowCheck(k, r->Counter) == false)
		return PEER_DROP_REPLAY;

	k->Recv.Nonce = r->Counter;
	if (NoiseCipherDecrypt(&k->Recv, data, PEER_RECORD_HEADER, data + PEER_RECORD_HEADER, size - PEER_RECORD_HEADER, o->Payload) == false)
		return PEER_DROP_FORGED;

	PeerWindowUpdate(k, r->Counter);

	UINT64 now = PeerNow();
	UINT payload_size = size - PEER_RECORD_HEADER - PEER_RECORD_TAG;

	s->LastReceived = now;
	if (payload_size != 0)
		s->LastData = now;

	if (k == &s->Next) {
		PeerKeypairMove(&s->Previous, &s->Current);
		PeerKeypairMove(&s->Current, &s->Next);
		s->SentUnderKey = 0;
		o->Flush = (s->QueueNum != 0);
	}
	s->Current.Confirmed = s->Current.Confirmed || (k == &s->Current) || (k == &s->Next);

	o->Deliver = (payload_size != 0);
	o->DeliverSize = payload_size;

	return PEER_OK;
}

// A handshake message or a record from the peer p, whose clear header r PeerRecordParse read and whose source and
// destination the policy took. What to send back and to deliver goes into o. Returns PEER_OK or the reason it was
// dropped. The caller holds the lock of the layer, shared.
UINT PeerSessionInput(PEER_AGENT *a, PEER *p, const PEER_RECORD_INFO *r, const UCHAR *data, UINT size, PEER_SESSION_OUT *o) {
	UINT reason = PEER_DROP_MALFORMED;

	o->ReplySize = 0;
	o->Flush = false;
	o->Keepalive = false;
	o->Deliver = false;
	o->DeliverSize = 0;

	PEER_SESSION *s = PeerSessionOf(p, r->Kind == PEER_MSG_INIT);
	if (s == NULL)
		return (r->Kind == PEER_MSG_INIT ? PEER_DROP_SEND : PEER_DROP_SESSION);

	AcquireSRWLockExclusive(&s->Lock);
	{
		if (r->Kind == PEER_MSG_INIT)
			reason = PeerSessionTakeInit(a, p, s, r, data, size, o);
		else if (r->Kind == PEER_MSG_RESPONSE)
			reason = PeerSessionTakeResponse(a, s, r, data, size, o);
		else if (r->Kind == PEER_MSG_RECORD)
			reason = PeerSessionTakeRecord(s, r, data, size, o);
	}
	ReleaseSRWLockExclusive(&s->Lock);

	return reason;
}

// The next datagram of the queue of the peer p sealed under the current keys into buf, or with first and an empty
// queue a keepalive. Returns its size, 0 when there is nothing more. The caller holds the lock of the layer, shared.
UINT PeerSessionFlush(PEER_AGENT *a, PEER *p, bool first, UCHAR *buf) {
	UINT ret = 0;
	PEER_SESSION *s = PeerSessionOf(p, false);

	if (s == NULL)
		return 0;

	AcquireSRWLockExclusive(&s->Lock);
	{
		if (s->Current.Valid && s->QueueNum != 0) {
			ret = PeerSessionWriteRecord(a, p, s, s->Queue[0], s->QueueSize[0], buf);

			s->QueueNum--;
			MoveMemory(s->QueueSize, s->QueueSize + 1, sizeof(UINT) * s->QueueNum);
			MoveMemory(s->Queue[0], s->Queue[1], (SIZE_T)PEER_MAX_PAYLOAD * s->QueueNum);
		} else if (s->Current.Valid && first) {
			ret = PeerSessionWriteRecord(a, p, s, NULL, 0, buf);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	return ret;
}

// The timers of the session with the peer p: keys that are too old or whose peer is silent are dropped; an initiation
// that had no answer goes again, or its queue is dropped after PEER_SESSION_TRIES; the initiator of the keys replaces
// them on schedule; a record with a payload that had no answer gets a keepalive. Returns the size of the one datagram
// to send in buf, 0 for none. The clock is read once the lock of the session is held, under which every time that the
// timers compare it with was taken, so none is later than the clock, whatever the order of the threads; at, when not
// NULL, is the clock in its place (PeerSessionTickAt). No time is subtracted from the clock, as the difference would
// wrap for a later time (CORE-S5-6-R3, #574). The caller holds the lock of the layer, shared.
UINT PeerSessionTick(PEER_AGENT *a, PEER *p, UCHAR *buf, const UINT64 *at) {
	UINT ret = 0;
	UINT dropped = 0;
	PEER_SESSION *s = PeerSessionOf(p, false);

	if (s == NULL)
		return 0;

	AcquireSRWLockExclusive(&s->Lock);
	{
		UINT64 now = (at != NULL ? *at : PeerNow());

		if (s->Current.Valid) {
			UINT64 last = (s->LastReceived > s->Current.Created ? s->LastReceived : s->Current.Created);

			if (now >= last + PeerSessionTimeout(a) || now >= s->Current.Created + 3 * PeerRekeyTime(a)) {
				PeerSessionClear(s);
				dropped = s->QueueNum;
				s->QueueNum = 0;
			}
		}

		if (s->Pending && now >= s->PendingTick + PEER_SESSION_RETRY) {
			if (s->PendingTries >= PEER_SESSION_TRIES) {
				NoiseHandshakeFree(&s->Handshake);
				s->Pending = false;
				s->PendingTries = 0;
				dropped += s->QueueNum;
				s->QueueNum = 0;
			} else {
				ret = PeerSessionStart(a, p, s, buf, now);
			}
		} else if (s->Pending == false && s->Current.Valid && s->Current.Initiator && now >= s->Current.Created + PeerRekeyTime(a)) {
			ret = PeerSessionStart(a, p, s, buf, now);
		} else if (s->Current.Valid && s->LastData > s->LastSent && now >= s->LastData + PeerKeepalive(a)) {
			ret = PeerSessionWriteRecord(a, p, s, NULL, 0, buf);
		}
	}
	ReleaseSRWLockExclusive(&s->Lock);

	for (UINT i = 0; i < dropped; i++)
		PeerDrop(a, PEER_DROP_SEND);

	return ret;
}

// The session of the peer p into its status. The caller holds the lock of the layer, shared.
void PeerSessionStatus(PEER *p, PEER_STATUS *st) {
	PEER_SESSION *s = PeerSessionOf(p, false);

	if (s == NULL)
		return;

	AcquireSRWLockShared(&s->Lock);
	{
		if (s->Current.Valid) {
			st->Session = PEER_SESSION_UP;
			CopyMemory(st->SessionId, s->Current.Id, PEER_SESSION_ID_SIZE);
		} else if (s->Pending) {
			st->Session = PEER_SESSION_HANDSHAKE;
		}
		st->Handshakes = s->Handshakes;
	}
	ReleaseSRWLockShared(&s->Lock);
}
