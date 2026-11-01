// Peer.c
// The peer layer of a node (ADR-0015): the peer table and the relays that the control plane sets, the binding of
// the node to its relays, the paths to each peer, the relay role, and PeerInput, the one ingress of every datagram,
// which delivers a datagram for the node and forwards one for another node through the same policy check. The ICE
// sessions that move a peer to a direct path are PeerIce.c's; this file starts them from the signals, hands them the
// STUN messages that come to the socket, and sends and takes the records of a peer on the pair that its session
// validated, through the same ingress. The datagrams between two nodes are those of their peer session
// (PeerSession.c): this file sends what the session writes and hands it what comes in.

#include "Core/PeerInternal.h"

#include <stdlib.h>
#include <string.h>

// The clock of bindings, binds and sessions (ms), monotonic
UINT64 PeerNow() {
	return GetTickCount64();
}

// The wall clock in 100 ns units, which the sequences of binds, signals, punches and initiations follow
UINT64 PeerWallClock() {
	FILETIME ft;

	GetSystemTimePreciseAsFileTime(&ft);

	return ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

// The lowest sequence that the peer p must exceed, given last, the last one taken of a kind: the clock when the entry
// of p was made, at least. A receiver that lost its memory of the peer, by a restart or a new entry, so takes no
// sequence of before that, and the sequences of binds, signals and punches survive the loss (finding F3 of AUD-5). A
// peer whose clock is behind the receiver's by d is so refused for d after the entry, until its clock passes the
// floor, and no longer. The floor tolerates no skew: a sequence that a slow clock sealed just now and one that a right
// clock sealed before the loss look the same, and taking the one takes the other again (CORE-H2-R1 #436).
UINT64 PeerFloorOf(const PEER *p, UINT64 last) {
	return (last > p->Floor ? last : p->Floor);
}

void PeerCount(PEER_AGENT *a, UINT counter) {
	InterlockedIncrement64(&a->Counters[counter]);
}

void PeerDrop(PEER_AGENT *a, UINT reason) {
	if (reason < PEER_NUM_REASONS)
		InterlockedIncrement64(&a->Drops[reason]);
}

void PeerPutUint64(UCHAR *p, UINT64 v) {
	for (UINT i = 0; i < 8; i++)
		p[i] = (UCHAR)(v >> (56 - 8 * i));
}

UINT64 PeerGetUint64(const UCHAR *p) {
	UINT64 v = 0;

	for (UINT i = 0; i < 8; i++)
		v = (v << 8) | p[i];

	return v;
}

void PeerPutUint16(UCHAR *p, USHORT v) {
	p[0] = (UCHAR)(v >> 8);
	p[1] = (UCHAR)v;
}

USHORT PeerGetUint16(const UCHAR *p) {
	return (USHORT)((p[0] << 8) | p[1]);
}

// The next sequence of a bind or a signal of the node: the wall clock in 100 ns units, or one more than the last
// sequence when the clock did not move on. It grows across restarts of the node too, so a receiver that keeps the
// last sequence of each node refuses every replay, as WireGuard does with the timestamp of a handshake initiation.
UINT64 PeerNextSequence(PEER_AGENT *a) {
	UINT64 now = PeerWallClock();

	while (true) {
		LONG64 last = ReadAcquire64(&a->Sequence);
		UINT64 next = ((UINT64)last + 1 > now) ? (UINT64)last + 1 : now;

		if (InterlockedCompareExchange64(&a->Sequence, (LONG64)next, last) == last)
			return next;
	}
}

void PeerDefaultConfig(PEER_CONFIG *c) {
	if (c == NULL)
		return;

	ZeroMemory(c, sizeof(PEER_CONFIG));
	c->RelayRate = PEER_DEFAULT_RELAY_RATE;
	c->RelayBurst = PEER_DEFAULT_RELAY_BURST;
	c->BindInterval = PEER_DEFAULT_BIND;
	c->BindRetry = PEER_DEFAULT_BIND_RETRY;
	c->BindExpiry = PEER_DEFAULT_BIND_EXPIRY;
	c->SessionRekeyTime = PEER_DEFAULT_REKEY_TIME;
	c->SessionRekeyDatagrams = PEER_DEFAULT_REKEY_DATAGRAMS;
	c->SessionTimeout = PEER_DEFAULT_SESSION_TIMEOUT;
	c->SessionKeepalive = PEER_DEFAULT_KEEPALIVE;
}

// The peer layer of a node with the static key key (an identity key in it stays owned by the caller and must
// outlive the layer) and the configuration c (NULL for PeerDefaultConfig). send sends its datagrams; recv takes
// the data datagrams for the node and may be NULL. With c->Ice its ICE sessions run on the socket of send, and with
// c->PortMap it asks its home gateway for a public port of that socket once its host candidates name the port.
// NULL when the crypto module cannot start.
PEER_AGENT *PeerNew(PEER_KEY *key, PEER_CONFIG *c, PEER_SEND_PROC *send, void *send_param, PEER_RECV_PROC *recv, void *recv_param) {
	LARGE_INTEGER freq;

	if (key == NULL || send == NULL || CryptoInit() == false)
		return NULL;

	PEER_AGENT *a = (PEER_AGENT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_AGENT));
	if (a == NULL)
		return NULL;

	a->Key = *key;
	InitializeSRWLock(&a->KeyLock);
	InitializeSRWLock(&a->Lock);
	InitializeSRWLock(&a->IceLock);
	InitializeSRWLock(&a->PunchLock);
	a->Ice.PortMap = -1;

	if (c != NULL)
		a->Config = *c;
	else
		PeerDefaultConfig(&a->Config);

	// The port mapping is the public port of a candidate of ICE
	if (a->Config.Ice == false)
		a->Config.PortMap = false;

	if (a->Config.RelayRate == 0)
		a->Config.RelayRate = PEER_DEFAULT_RELAY_RATE;
	if (a->Config.RelayBurst == 0)
		a->Config.RelayBurst = 1;
	if (a->Config.BindInterval == 0)
		a->Config.BindInterval = PEER_DEFAULT_BIND;
	if (a->Config.BindRetry == 0)
		a->Config.BindRetry = PEER_DEFAULT_BIND_RETRY;
	if (a->Config.BindExpiry == 0)
		a->Config.BindExpiry = PEER_DEFAULT_BIND_EXPIRY;

	a->Send = send;
	a->SendParam = send_param;
	a->Recv = recv;
	a->RecvParam = recv_param;

	QueryPerformanceFrequency(&freq);
	a->RateInterval = freq.QuadPart / a->Config.RelayRate;
	if (a->RateInterval == 0)
		a->RateInterval = 1;
	a->RateTolerance = a->RateInterval * (LONG64)(a->Config.RelayBurst - 1);

	// The key of the bind challenges of the relay role (PeerChallenge.c)
	if (CryptoRandom(a->CookieSecret, sizeof(a->CookieSecret)) == false) {
		PeerFree(a);
		return NULL;
	}

	return a;
}

// Free the peer layer. The I/O that calls PeerInput must have stopped before; the ICE sessions, which send on the
// socket of the layer until they end, and the port mapping end here, so the socket goes after the layer.
void PeerFree(PEER_AGENT *a) {
	if (a == NULL)
		return;

	if (a->Config.Ice)
		PeerIceStop(a);

	if (a->Peers != NULL) {
		for (UINT i = 0; i < a->NumPeers; i++)
			PeerSessionFree(a->Peers[i].Session);
		HeapFree(GetProcessHeap(), 0, a->Peers);
	}
	if (a->Bindings != NULL)
		HeapFree(GetProcessHeap(), 0, a->Bindings);

	SecureZeroMemory(a, sizeof(PEER_AGENT));
	HeapFree(GetProcessHeap(), 0, a);
}

const UCHAR *PeerPublicKey(PEER_AGENT *a) {
	return (a != NULL ? a->Key.Public : NULL);
}

// The peer of key in the table, NULL for none. The caller holds the lock.
PEER *PeerFind(PEER_AGENT *a, const UCHAR *key) {
	UINT lo = 0;
	UINT hi = a->NumPeers;

	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;
		int c = memcmp(key, a->Peers[mid].Info.Key, PEER_KEY_SIZE);

		if (c == 0)
			return &a->Peers[mid];
		if (c < 0)
			hi = mid;
		else
			lo = mid + 1;
	}

	return NULL;
}

// Where the binding of key is in the bindings of the relay role, or would be; *found tells which. The caller holds
// the lock.
static UINT PeerBindingIndex(PEER_AGENT *a, const UCHAR *key, bool *found) {
	UINT lo = 0;
	UINT hi = a->NumBindings;

	*found = false;
	while (lo < hi) {
		UINT mid = lo + (hi - lo) / 2;
		int c = memcmp(key, a->Bindings[mid].Key, PEER_KEY_SIZE);

		if (c == 0) {
			*found = true;
			return mid;
		}
		if (c < 0)
			hi = mid;
		else
			lo = mid + 1;
	}

	return lo;
}

static PEER_BINDING *PeerFindBinding(PEER_AGENT *a, const UCHAR *key) {
	bool found;
	UINT i = PeerBindingIndex(a, key, &found);

	return (found ? &a->Bindings[i] : NULL);
}

// Add a binding for key, or return the one there is. NULL when there is no memory for it. The caller holds the lock
// exclusively.
static PEER_BINDING *PeerAddBinding(PEER_AGENT *a, const UCHAR *key) {
	bool found;
	UINT i = PeerBindingIndex(a, key, &found);

	if (found)
		return &a->Bindings[i];

	if (a->NumBindings == a->MaxBindings) {
		UINT max = (a->MaxBindings == 0 ? 16 : a->MaxBindings * 2);
		PEER_BINDING *b;

		if (a->Bindings == NULL)
			b = (PEER_BINDING *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_BINDING) * max);
		else
			b = (PEER_BINDING *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, a->Bindings, sizeof(PEER_BINDING) * max);
		if (b == NULL)
			return NULL;

		a->Bindings = b;
		a->MaxBindings = max;
	}

	MoveMemory(&a->Bindings[i + 1], &a->Bindings[i], sizeof(PEER_BINDING) * (a->NumBindings - i));
	ZeroMemory(&a->Bindings[i], sizeof(PEER_BINDING));
	CopyMemory(a->Bindings[i].Key, key, PEER_KEY_SIZE);
	a->NumBindings++;

	return &a->Bindings[i];
}

// Drop the bindings of nodes that are no peer: a relay binds the nodes of its VRFs only. The caller holds the lock
// exclusively.
static void PeerPruneBindings(PEER_AGENT *a) {
	UINT n = 0;

	for (UINT i = 0; i < a->NumBindings; i++) {
		if (PeerFind(a, a->Bindings[i].Key) == NULL)
			continue;
		if (n != i)
			a->Bindings[n] = a->Bindings[i];
		n++;
	}

	a->NumBindings = n;
}

// The relay of key among the relays of the node, NULL for none. The caller holds the lock.
static PEER_RELAY *PeerFindRelay(PEER_AGENT *a, const UCHAR *key) {
	for (UINT i = 0; i < a->NumRelays; i++)
		if (memcmp(a->Relays[i].Info.Key, key, PEER_KEY_SIZE) == 0)
			return &a->Relays[i];

	return NULL;
}

// Send one datagram and count it
bool PeerSendRaw(PEER_AGENT *a, const PEER_ADDR *to, const void *data, UINT size) {
	if (a->Send(a->SendParam, to, data, size)) {
		PeerCount(a, PEER_COUNT_SENT);
		return true;
	}

	PeerDrop(a, PEER_DROP_SEND);
	return false;
}

// Bind the node to the relay of relay_key: a bind envelope with the next sequence and the cookie of the relay's last
// bind challenge, which the relay answers with a bound, or with a challenge when it has no good cookie (PeerChallenge.c).
// answer: the bind answers a challenge. Without the lock.
void PeerBind(PEER_AGENT *a, const UCHAR *relay_key, bool answer) {
	UCHAR payload[PEER_BIND_MAX];
	UCHAR env[PEER_ENVELOPE_HEADER + PEER_BIND_MAX + PEER_ENVELOPE_TAG];
	UINT payload_size = PEER_BIND_SIZE;
	PEER_ADDR to;
	bool found = false;

	UINT64 seq = PeerNextSequence(a);
	payload[0] = PEER_VERSION;
	PeerPutUint64(payload + 1, seq);

	AcquireSRWLockShared(&a->Lock);
	{
		PEER_RELAY *r = PeerFindRelay(a, relay_key);

		if (r != NULL && r->HasCookie) {
			CopyMemory(payload + PEER_BIND_SIZE, r->Cookie, PEER_COOKIE_SIZE);
			payload_size = PEER_BIND_MAX;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	UINT size = PeerSeal(a, relay_key, PEER_MSG_BIND, payload, payload_size, env, sizeof(env));
	if (size == 0)
		return;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER_RELAY *r = PeerFindRelay(a, relay_key);

		if (r != NULL) {
			r->Binding = true;
			r->Answered = answer;
			r->BindSequence = seq;
			r->BindTick = PeerNow();
			to = r->Info.Addr;
			found = true;
			// The punch counts the mapping that the NAT of the node makes towards the relay (PeerPunch.c)
			if (r->Mapping == 0)
				r->Mapping = PeerPunchDestination(a, &to);
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (found)
		PeerSendRaw(a, &to, env, size);
}

// Bind to every relay that the node wants and has no fresh binding to: a first bind, a renewal after BindInterval,
// or a retry after BindRetry when the last bind had no answer. at, when not NULL, is the clock in place of the one that
// it reads (PeerTickAt).
static void PeerBindWanted(PEER_AGENT *a, const UINT64 *at) {
	UCHAR keys[PEER_MAX_RELAYS][PEER_KEY_SIZE];
	UINT num = 0;
	UINT64 now = (at != NULL ? *at : PeerNow());

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumRelays; i++) {
			PEER_RELAY *r = &a->Relays[i];
			bool due = (r->Binding == false) || (r->Bound && now - r->BindTick >= a->Config.BindInterval) || (r->Bound == false && now - r->BindTick >= a->Config.BindRetry);

			if (r->Wanted && due)
				CopyMemory(keys[num++], r->Info.Key, PEER_KEY_SIZE);
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	for (UINT i = 0; i < num; i++)
		PeerBind(a, keys[i], false);
}

static int PeerComparePeer(const void *p1, const void *p2) {
	return memcmp(((const PEER *)p1)->Info.Key, ((const PEER *)p2)->Info.Key, PEER_KEY_SIZE);
}

// Set the peer table, from the Peer objects of the desired state. A peer that stays keeps its signal, its paths and
// its ICE session; the relay role drops the bindings of the nodes that are no peer any more, and the ICE sessions
// of those peers end.
void PeerSetPeers(PEER_AGENT *a, PEER_INFO *peers, UINT num) {
	PEER *t = NULL;
	UINT n = 0;
	UINT old_num = 0;

	if (a == NULL || (peers == NULL && num != 0))
		return;

	if (num != 0) {
		t = (PEER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER) * num);
		if (t == NULL)
			return;
	}

	for (UINT i = 0; i < num; i++) {
		t[i].Info = peers[i];
		t[i].Info.Name[PEER_NAME_SIZE - 1] = 0;
		if (t[i].Info.NumVrfs > PEER_MAX_VRFS)
			t[i].Info.NumVrfs = PEER_MAX_VRFS;
	}

	if (num > 1)
		qsort(t, num, sizeof(PEER), PeerComparePeer);

	// One entry per key
	for (UINT i = 0; i < num; i++) {
		if (n != 0 && memcmp(t[n - 1].Info.Key, t[i].Info.Key, PEER_KEY_SIZE) == 0)
			continue;
		t[n++] = t[i];
	}

	// A new entry takes no sequence of before it was made (PeerFloorOf)
	UINT64 floor = PeerWallClock();

	// No ICE session starts or ends meanwhile (PeerIce.c)
	AcquireSRWLockExclusive(&a->IceLock);
	AcquireSRWLockExclusive(&a->Lock);
	{
		for (UINT i = 0; i < n; i++) {
			PEER *old = PeerFind(a, t[i].Info.Key);

			if (old != NULL) {
				PEER_INFO info = t[i].Info;

				t[i] = *old;
				t[i].Info = info;
				// The sessions move with the peer: what stays in the old table belongs to the peers that went
				old->Ice = NULL;
				old->Session = NULL;
			} else {
				t[i].Floor = floor;
			}
		}

		PEER *old_table = a->Peers;
		old_num = a->NumPeers;
		a->Peers = t;
		a->NumPeers = n;
		t = old_table;

		PeerPruneBindings(a);
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (t != NULL)
		PeerIceRetire(t, old_num);
	ReleaseSRWLockExclusive(&a->IceLock);

	if (t != NULL) {
		for (UINT i = 0; i < old_num; i++)
			PeerSessionFree(t[i].Session);
		HeapFree(GetProcessHeap(), 0, t);
	}
}

// Set the relays that the node may use, from the Relay objects of the desired state; the first is its home relay.
// The node binds to its home relay at once, and to the relay of a peer when a signal of that peer names it. A relay
// that stays, at the same address, keeps its binding. With punching on, it also binds a second relay, so that two
// reflexive observations of its own address let it learn its NAT's port allocation pattern (PeerPunch.c, CORE-S5-4).
void PeerSetRelays(PEER_AGENT *a, PEER_RELAY_INFO *relays, UINT num) {
	PEER_RELAY next[PEER_MAX_RELAYS];

	if (a == NULL || (relays == NULL && num != 0))
		return;

	if (num > PEER_MAX_RELAYS)
		num = PEER_MAX_RELAYS;

	ZeroMemory(next, sizeof(next));

	AcquireSRWLockExclusive(&a->Lock);
	{
		for (UINT i = 0; i < num; i++) {
			PEER_RELAY *old = PeerFindRelay(a, relays[i].Key);

			if (old != NULL && PeerAddrEqual(&old->Info.Addr, &relays[i].Addr))
				next[i] = *old;

			next[i].Info = relays[i];
			next[i].Info.Name[PEER_NAME_SIZE - 1] = 0;
			next[i].Wanted = (i == 0) || (a->Config.Punch && i < 2);
		}

		CopyMemory(a->Relays, next, sizeof(next));
		a->NumRelays = num;

		// The relay of every peer that named one stays wanted
		for (UINT i = 0; i < a->NumPeers; i++) {
			PEER_RELAY *r = (a->Peers[i].HasRelay ? PeerFindRelay(a, a->Peers[i].RelayKey) : NULL);

			if (r != NULL)
				r->Wanted = true;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	PeerBindWanted(a, NULL);
}

// Set the host candidates of the node: the addresses of its own that its signals offer, the addresses of the socket of
// the layer with its port. With Config.PortMap the first of them starts the port mapping of that port (PeerPortMap.c).
void PeerSetHostCandidates(PEER_AGENT *a, PEER_ADDR *addrs, UINT num) {
	if (a == NULL || (addrs == NULL && num != 0))
		return;

	if (num > PEER_MAX_CANDIDATES - 1)
		num = PEER_MAX_CANDIDATES - 1;

	AcquireSRWLockExclusive(&a->Lock);
	{
		if (num != 0)
			CopyMemory(a->Hosts, addrs, sizeof(PEER_ADDR) * num);
		a->NumHosts = num;
	}
	ReleaseSRWLockExclusive(&a->Lock);

	// libplum is never called under the lock of the layer
	if (a->Config.PortMap && num != 0)
		PeerPortMapStart(a, addrs[0].Port);
}

// Set a direct path to the peer of key by hand, at addr on the send procedure of the layer, or remove it with addr
// NULL: the peer then goes back to its ICE session or the relay path. It comes before ICE. False when key is no
// peer.
bool PeerSetDirect(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *addr) {
	bool ret = false;

	if (a == NULL || key == NULL)
		return false;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL) {
			p->HasDirect = (addr != NULL);
			if (addr != NULL)
				p->Direct = *addr;
			else
				ZeroMemory(&p->Direct, sizeof(PEER_ADDR));
			// A punched path that is taken away ends its punch (PeerPunch.c)
			if (addr == NULL && p->Punch.State == PEER_PUNCH_CONNECTED)
				p->Punch.State = PEER_PUNCH_NONE;
			ret = true;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	return ret;
}

// The relay of the peer p's last signal while the node has a binding to it: true, and its address in to. The
// caller holds the lock.
static bool PeerRelayOf(PEER_AGENT *a, PEER *p, PEER_ADDR *to) {
	if (p->HasRelay) {
		PEER_RELAY *r = PeerFindRelay(a, p->RelayKey);

		if (r != NULL && (r->Binding || r->Bound)) {
			*to = r->Info.Addr;
			return true;
		}
	}

	return false;
}

// The path that PeerSend takes to the peer p now: a direct path set by hand, else the direct path of its ICE session
// once a candidate pair validated, else the relay of its last signal while the node has a binding to that relay.
// The caller holds the lock.
static UINT PeerPathOf(PEER_AGENT *a, PEER *p) {
	PEER_ADDR to;

	if (p->HasDirect)
		return PEER_PATH_DIRECT;

	if (p->Ice != NULL && PeerIceUp(p->Ice))
		return PEER_PATH_DIRECT;

	if (PeerRelayOf(a, p, &to))
		return PEER_PATH_RELAY;

	return PEER_PATH_NONE;
}

// Seal a signal of type (PEER_SIGNAL_OFFER or PEER_SIGNAL_ANSWER) for the peer of key, for the control plane to
// carry: the relay assignment of the node (its home relay) and its candidates. Without ICE they are the host
// candidates and the server reflexive one that its home relay reported. With ICE they are those of the ICE socket
// (the public port of the home gateway, the address that the home relay saw, the host addresses), with the
// credentials of the node's ICE session with the peer. An offer starts that session when there is none, the last
// one failed, or it still checks without the public port that the home gateway granted since: a new offer restarts
// ICE. An answer carries no credentials while that session is the node's own offer that waits for the answer of the
// peer: the node did not take the offer of the peer then, as its key is higher, and the peer takes the node's offer
// instead (PeerIceRemote), so the two never end up both controlling. A punch offer or a punch answer carries the NAT and
// the prediction of the node instead (PeerPunchSealSignal). Returns the size of the envelope in buf, 0 when peer is no
// peer or the envelope does not fit size.
UINT PeerSealSignal(PEER_AGENT *a, const UCHAR *peer, UINT type, UCHAR *buf, UINT size) {
	PEER_SIGNAL s;
	UCHAR payload[PEER_MAX_SIGNAL];
	bool known = false;

	if (a == NULL || peer == NULL || buf == NULL)
		return 0;

	if (type == PEER_SIGNAL_PUNCH_OFFER || type == PEER_SIGNAL_PUNCH_ANSWER)
		return PeerPunchSealSignal(a, peer, type, buf, size);

	ZeroMemory(&s, sizeof(s));
	s.Type = type;
	s.Sequence = PeerNextSequence(a);

	// libjuice is never called under the lock of the layer (PeerIce.c)
	if (a->Config.Ice) {
		if (type == PEER_SIGNAL_OFFER)
			PeerIceOffer(a, peer);
		s.NumCandidates = PeerIceCandidates(a, s.Candidates, PEER_MAX_CANDIDATES);
	}

	// The side of the peer in an ICE session changes under IceLock, which comes before the lock of the layer (PeerIce.c)
	AcquireSRWLockShared(&a->IceLock);
	AcquireSRWLockShared(&a->Lock);
	{
		PEER *p = PeerFind(a, peer);

		known = (p != NULL);

		if (a->Config.Ice) {
			bool waiting = (p != NULL && p->Ice != NULL && p->Ice->Controlling && p->Ice->RemoteUfrag[0] == 0);

			if (p != NULL && p->Ice != NULL && (type == PEER_SIGNAL_OFFER || waiting == false)) {
				strcpy_s(s.IceUfrag, sizeof(s.IceUfrag), p->Ice->Ufrag);
				strcpy_s(s.IcePwd, sizeof(s.IcePwd), p->Ice->Pwd);
			}
		} else {
			for (UINT i = 0; i < a->NumHosts; i++) {
				s.Candidates[s.NumCandidates].Type = PEER_CANDIDATE_HOST;
				s.Candidates[s.NumCandidates].Addr = a->Hosts[i];
				s.NumCandidates++;
			}
		}

		if (a->NumRelays != 0) {
			PEER_RELAY *home = &a->Relays[0];

			CopyMemory(s.RelayKey, home->Info.Key, PEER_KEY_SIZE);
			s.Relay = home->Info.Addr;

			if (home->Bound && a->Config.Ice == false && s.NumCandidates < PEER_MAX_CANDIDATES) {
				s.Candidates[s.NumCandidates].Type = PEER_CANDIDATE_SRFLX;
				s.Candidates[s.NumCandidates].Addr = home->Observed;
				s.NumCandidates++;
			}
		}
	}
	ReleaseSRWLockShared(&a->Lock);
	ReleaseSRWLockShared(&a->IceLock);

	if (known == false)
		return 0;

	UINT len = PeerSignalEncode(&s, payload, sizeof(payload));
	if (len == 0)
		return 0;

	return PeerSeal(a, peer, PEER_MSG_SIGNAL, payload, len, buf, size);
}

// Take a signal that the control plane carried: open the envelope, check that its sender is a peer, that its
// sequence is above the last one taken from that peer, and that it names a relay that the control plane assigned,
// at the assigned address. Then the peer is reached through that relay, and the node binds to it if it has no
// binding yet. With ICE, the credentials and the candidates of the signal go to the node's ICE session with the
// peer, which an offer starts: the checks of the candidate pairs run in the background from then on. sig, when not
// NULL, receives the signal, so that the caller answers an offer. Returns PEER_OK or the reason the signal was
// dropped.
UINT PeerOpenSignal(PEER_AGENT *a, const UCHAR *env, UINT size, PEER_SIGNAL *sig) {
	static const UCHAR zero[PEER_KEY_SIZE] = {0};
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_MAX_SIGNAL];
	UINT len = 0;
	PEER_SIGNAL s;
	UINT reason = PEER_OK;
	bool bind = false;

	ZeroMemory(&s, sizeof(s));
	if (sig != NULL)
		ZeroMemory(sig, sizeof(PEER_SIGNAL));
	if (a == NULL)
		return PEER_DROP_MALFORMED;

	if (env == NULL || size < 1 || env[0] != PEER_MSG_SIGNAL)
		reason = PEER_DROP_MALFORMED;
	else if (PeerOpen(a, env, size, sender, payload, sizeof(payload), &len) == false)
		reason = PEER_DROP_FORGED;
	else if (PeerSignalDecode(payload, len, &s) == false)
		reason = PEER_DROP_MALFORMED;

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return reason;
	}

	CopyMemory(s.Sender, sender, PEER_KEY_SIZE);
	bool has_relay = (memcmp(s.RelayKey, zero, PEER_KEY_SIZE) != 0);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, sender);
		PEER_RELAY *r = (has_relay ? PeerFindRelay(a, s.RelayKey) : NULL);

		if (p == NULL)
			reason = PEER_DROP_POLICY;
		else if (s.Sequence <= PeerFloorOf(p, p->Sequence))
			reason = PEER_DROP_REPLAY;
		else if (has_relay && (r == NULL || PeerAddrEqual(&r->Info.Addr, &s.Relay) == false))
			reason = PEER_DROP_RELAY;
		else {
			p->Sequence = s.Sequence;
			p->HasRelay = has_relay;
			CopyMemory(p->RelayKey, s.RelayKey, PEER_KEY_SIZE);
			p->NumCandidates = s.NumCandidates;
			CopyMemory(p->Candidates, s.Candidates, sizeof(p->Candidates));

			if (r != NULL) {
				r->Wanted = true;
				bind = (r->Binding == false);
			}
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return reason;
	}

	PeerCount(a, PEER_COUNT_SIGNALS);

	if (bind)
		PeerBind(a, s.RelayKey, false);

	if (a->Config.Ice && s.IceUfrag[0] != 0)
		PeerIceRemote(a, sender, &s);

	// The control plane times the symmetric-NAT punch with a punch offer and its answer (PeerPunch.c, CORE-S5-7)
	if (s.Type == PEER_SIGNAL_PUNCH_OFFER || s.Type == PEER_SIGNAL_PUNCH_ANSWER)
		PeerPunchStart(a, sender, &s);

	if (sig != NULL)
		*sig = s;

	return PEER_OK;
}

// The path that a data datagram from the address from, naming the source src, came on: from a relay that the node
// is bound to, which checked the source at its own ingress; from a node bound to the relay role, at the address of
// its binding; or on the direct path of the peer src: from the address that was set by hand or won by a punch, or
// from the peer's address on the pair that the ICE session with the peer validated, and of no other peer.
// PEER_PATH_NONE when from is none of them. The caller holds the lock.
static UINT PeerSourcePath(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *src) {
	for (UINT i = 0; i < a->NumRelays; i++) {
		PEER_RELAY *r = &a->Relays[i];

		if ((r->Binding || r->Bound) && PeerAddrEqual(&r->Info.Addr, from))
			return PEER_PATH_RELAY;
	}

	if (a->Config.Relay) {
		PEER_BINDING *b = PeerFindBinding(a, src);

		if (b != NULL && PeerAddrEqual(&b->Addr, from))
			return PEER_PATH_BOUND;
	}

	PEER *p = PeerFind(a, src);
	if (p != NULL && p->HasDirect && PeerAddrEqual(&p->Direct, from))
		return PEER_PATH_DIRECT;

	if (p != NULL && p->Ice != NULL && PeerIceValid(p->Ice) && PeerAddrEqual(&p->Ice->Selected, from))
		return PEER_PATH_DIRECT;

	return PEER_PATH_NONE;
}

// Whether two peers share a VRF
static bool PeerShareVrf(PEER_INFO *x, PEER_INFO *y) {
	for (UINT i = 0; i < x->NumVrfs; i++)
		for (UINT j = 0; j < y->NumVrfs; j++)
			if (x->VrfIds[i] == y->VrfIds[j])
				return true;

	return false;
}

// The policy of the peer layer, one check for every data datagram, whether the node takes it in or its relay role
// forwards it: the source is a peer, and the destination is the node itself or a peer that shares a VRF with the
// source. A relay's peers are the nodes of its VRFs, each with the VRFs it shares with the relay, so the relay
// forwards between two nodes only inside a VRF of both. The caller holds the lock.
static UINT PeerPolicy(PEER_AGENT *a, const UCHAR *src, const UCHAR *dst) {
	PEER *s = PeerFind(a, src);

	if (s == NULL)
		return PEER_DROP_POLICY;

	if (memcmp(dst, a->Key.Public, PEER_KEY_SIZE) == 0)
		return PEER_OK;

	PEER *d = PeerFind(a, dst);
	if (d == NULL || PeerShareVrf(&s->Info, &d->Info) == false)
		return PEER_DROP_POLICY;

	return PEER_OK;
}

// GCRA (the generic cell rate algorithm of ITU-T I.371) on the binding of a source: a datagram passes unless it
// comes more than the burst tolerance before its theoretical arrival time, which then moves on by one interval. It
// takes no lock, so ingress threads that run at the same time count each datagram once.
static bool PeerRateAllow(PEER_AGENT *a, PEER_BINDING *b) {
	LARGE_INTEGER now;

	QueryPerformanceCounter(&now);

	while (true) {
		LONG64 tat = ReadAcquire64(&b->Tat);
		LONG64 start = (tat > now.QuadPart ? tat : now.QuadPart);

		if (start - now.QuadPart > a->RateTolerance)
			return false;

		if (InterlockedCompareExchange64(&b->Tat, start + a->RateInterval, tat) == tat)
			return true;
	}
}

// A datagram between two nodes, a handshake message or a record of a peer session, from the address from: taken by
// the session of its source when it is for the node, forwarded as it came when it is for a node bound to the relay
// role, after one policy check either way. The relay reads the clear header only. What goes back goes to from: a
// relay, a node bound to the relay role, or the peer's address on its direct path.
static void PeerInputData(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	PEER_RECORD_INFO r;
	PEER_SESSION_OUT out;
	PEER_ADDR to;
	UINT reason = PEER_OK;
	UINT path = PEER_PATH_NONE;
	bool forward = false;

	if (PeerRecordParse(data, size, &r) == false) {
		PeerDrop(a, PEER_DROP_MALFORMED);
		return;
	}

	const UCHAR *src = r.Src;
	const UCHAR *dst = r.Dst;
	bool to_self = (memcmp(dst, a->Key.Public, PEER_KEY_SIZE) == 0);

	out.ReplySize = 0;
	out.Flush = false;
	out.Keepalive = false;
	out.Deliver = false;
	out.DeliverSize = 0;

	AcquireSRWLockShared(&a->Lock);
	{
		path = PeerSourcePath(a, from, src);
		reason = (path == PEER_PATH_NONE ? PEER_DROP_SOURCE : PeerPolicy(a, src, dst));

		if (reason == PEER_OK && to_self) {
			// For the node: its session with the source, which the policy found to be a peer
			PEER *p = PeerFind(a, src);

			reason = (p != NULL ? PeerSessionInput(a, p, &r, data, size, &out) : PEER_DROP_POLICY);

			// A record that opened is a word of the peer: on its punched path, its consent there (PeerPunch.c)
			if (reason == PEER_OK && r.Kind == PEER_MSG_RECORD)
				PeerPunchHeard(p, from);
		} else if (reason == PEER_OK) {
			// For another node: only the relay role forwards, and only from a node bound to it to another one
			PEER_BINDING *s = (path == PEER_PATH_BOUND ? PeerFindBinding(a, src) : NULL);
			PEER_BINDING *d = (s != NULL ? PeerFindBinding(a, dst) : NULL);

			if (s == NULL) {
				reason = PEER_DROP_NOT_RELAY;
			} else if (d == NULL) {
				reason = PEER_DROP_NOT_BOUND;
			} else if (PeerRateAllow(a, s) == false) {
				reason = PEER_DROP_RATE;
			} else {
				to = d->Addr;
				forward = true;
			}
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	if (forward) {
		// As it came: the source stays the one the relay checked
		if (PeerSendRaw(a, &to, data, size))
			PeerCount(a, PEER_COUNT_FORWARDED);
		return;
	}

	// The response to an initiation, then the queue that new keys release, back the way the datagram came. out.Reply
	// holds each datagram of the queue in turn once the response went.
	if (out.ReplySize != 0)
		PeerSendRaw(a, from, out.Reply, out.ReplySize);

	for (bool first = out.Keepalive; out.Flush; first = false) {
		UINT len = 0;

		AcquireSRWLockShared(&a->Lock);
		{
			PEER *p = PeerFind(a, src);

			if (p != NULL)
				len = PeerSessionFlush(a, p, first, out.Reply);
		}
		ReleaseSRWLockShared(&a->Lock);

		if (len == 0)
			break;
		PeerSendRaw(a, from, out.Reply, len);
	}

	if (out.Deliver == false)
		return;

	PeerCount(a, PEER_COUNT_DELIVERED);
	if (path == PEER_PATH_RELAY)
		PeerCount(a, PEER_COUNT_DELIVERED_RELAY);

	if (a->Recv != NULL)
		a->Recv(a, a->RecvParam, src, (path == PEER_PATH_RELAY ? PEER_PATH_RELAY : PEER_PATH_DIRECT), out.Payload, out.DeliverSize);
}

// A bind, at the relay role: a node that holds the key of a peer binds to the address the bind came from, unless
// the bind is not above the last one of that node, and only with the cookie of a challenge that the relay sent to that
// address (PeerChallenge.c); without one, the relay sends the challenge and binds nothing. The relay answers a bind it
// takes with a bound, which tells the node the address it saw: its server reflexive candidate.
static void PeerInputBind(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_BOUND_SIZE];
	UCHAR env[PEER_ENVELOPE_HEADER + PEER_BOUND_SIZE + PEER_ENVELOPE_TAG];
	UINT len = 0;
	UINT reason = PEER_OK;
	bool challenge = false;

	if (a->Config.Relay == false)
		reason = PEER_DROP_NOT_RELAY;
	else if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
		reason = PEER_DROP_FORGED;
	else if ((len != PEER_BIND_SIZE && len != PEER_BIND_MAX) || payload[0] != PEER_VERSION)
		reason = PEER_DROP_MALFORMED;

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = PeerGetUint64(payload + 1);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, sender);

		if (p == NULL) {
			reason = PEER_DROP_POLICY;
		} else if (seq <= PeerFloorOf(p, p->BindSequence)) {
			// The sequence is kept with the peer, not the binding, so it outlives the expiry of the binding
			reason = PEER_DROP_REPLAY;
		} else if (len != PEER_BIND_MAX || PeerCookieCheck(a, sender, from, payload + PEER_BIND_SIZE) == false) {
			challenge = true;
		} else {
			PEER_BINDING *b = PeerAddBinding(a, sender);

			if (b == NULL) {
				reason = PEER_DROP_SEND;
			} else {
				b->Addr = *from;
				b->Sequence = seq;
				b->Tick = PeerNow();
				p->BindSequence = seq;
			}
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	if (challenge) {
		PeerChallengeSend(a, sender, from, seq);
		return;
	}

	PeerCount(a, PEER_COUNT_BINDS);

	payload[0] = PEER_VERSION;
	PeerPutUint64(payload + 1, seq);
	CopyMemory(payload + 9, from->Ip, sizeof(from->Ip));
	PeerPutUint16(payload + 25, from->Port);

	UINT env_size = PeerSeal(a, sender, PEER_MSG_BOUND, payload, PEER_BOUND_SIZE, env, sizeof(env));
	if (env_size != 0)
		PeerSendRaw(a, from, env, env_size);
}

// A bound, at a node: the answer of one of its relays, from that relay's address, to the last bind the node sent
static void PeerInputBound(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_BOUND_SIZE];
	UINT len = 0;
	UINT reason = PEER_OK;

	if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
		reason = PEER_DROP_FORGED;
	else if (len != PEER_BOUND_SIZE || payload[0] != PEER_VERSION)
		reason = PEER_DROP_MALFORMED;

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = PeerGetUint64(payload + 1);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER_RELAY *r = PeerFindRelay(a, sender);

		if (r == NULL || PeerAddrEqual(&r->Info.Addr, from) == false) {
			reason = PEER_DROP_RELAY;
		} else if (r->Binding == false || seq != r->BindSequence) {
			reason = PEER_DROP_REPLAY;
		} else {
			PEER_ADDR seen;

			CopyMemory(seen.Ip, payload + 9, sizeof(seen.Ip));
			seen.Port = PeerGetUint16(payload + 25);

			// A relay that sees the node at another address saw a new mapping of its NAT (PeerPunch.c)
			if (r->Bound && PeerAddrEqual(&r->Observed, &seen) == false)
				PeerPunchRemap(a, r);

			r->Bound = true;
			r->Observed = seen;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (reason != PEER_OK)
		PeerDrop(a, reason);
}

// The one ingress of the peer layer: every datagram that the node receives, on any path, from the address from.
// A signal never comes as a datagram: the control plane carries it to PeerOpenSignal. With ICE, a STUN message is a
// check of an ICE session of the node or its answer, which goes to that session (PeerIce.c).
void PeerInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	if (a == NULL || from == NULL || data == NULL)
		return;

	if (size == 0 || size > PEER_MAX_DATAGRAM) {
		PeerDrop(a, PEER_DROP_MALFORMED);
		return;
	}

	if (a->Config.Ice && PeerIceIsStun(data, size)) {
		PeerIceInput(a, from, data, size);
		return;
	}

	switch (data[0]) {
	case PEER_MSG_DATA:
		// The old clear form: no node or relay takes it, so nothing can go back to the clear
		PeerDrop(a, PEER_DROP_CLEAR);
		break;
	case PEER_MSG_INIT:
	case PEER_MSG_RESPONSE:
	case PEER_MSG_RECORD:
		PeerInputData(a, from, data, size);
		break;
	case PEER_MSG_BIND:
		PeerInputBind(a, from, data, size);
		break;
	case PEER_MSG_BOUND:
		PeerInputBound(a, from, data, size);
		break;
	case PEER_MSG_CHALLENGE:
		PeerInputChallenge(a, from, data, size);
		break;
	case PEER_MSG_PUNCH:
		PeerPunchInput(a, from, data, size);
		break;
	default:
		PeerDrop(a, PEER_DROP_MALFORMED);
		break;
	}
}

// Send one datagram of a peer session, buf, to the peer of dst on its path now (PeerGetStatus): a direct path, set by
// hand, won by a punch or validated by ICE, else the relay of the peer's last signal. Every path is on the socket of
// the layer: on the direct path of ICE the datagram goes to the peer's address on the validated pair. False when dst
// is no peer or has no path.
static bool PeerSendTo(PEER_AGENT *a, const UCHAR *dst, const UCHAR *buf, UINT size) {
	PEER_ADDR to;
	UINT path = PEER_PATH_NONE;

	AcquireSRWLockShared(&a->Lock);
	{
		PEER *p = PeerFind(a, dst);

		if (p != NULL) {
			path = PeerPathOf(a, p);
			if (path == PEER_PATH_DIRECT && p->HasDirect)
				to = p->Direct;
			else if (path == PEER_PATH_DIRECT)
				to = p->Ice->Selected;
			else if (path == PEER_PATH_RELAY)
				PeerRelayOf(a, p, &to);
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	if (path == PEER_PATH_NONE)
		return false;

	return PeerSendRaw(a, &to, buf, size);
}

// Send one datagram of data to the peer of dst, in the peer session with it, on its path now: a record under the
// keys of the session, or, before it has keys, the datagram waits in its queue and the handshake starts (PeerSession.c).
// Keys that are due are replaced after the record went. False when dst is no peer, has no path yet, size is above
// PEER_MAX_PAYLOAD, or the record could not be sent or queued.
bool PeerSend(PEER_AGENT *a, const UCHAR *dst, const void *data, UINT size) {
	UCHAR buf[PEER_MAX_DATAGRAM];
	UINT len = 0;
	bool known = false;
	bool queued = false;
	bool rekey = false;

	if (a == NULL || dst == NULL || (data == NULL && size != 0) || size > PEER_MAX_PAYLOAD)
		return false;

	AcquireSRWLockShared(&a->Lock);
	{
		PEER *p = PeerFind(a, dst);

		if (p != NULL && PeerPathOf(a, p) != PEER_PATH_NONE) {
			known = true;
			len = PeerSessionSeal(a, p, data, size, buf, &queued, &rekey);
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	if (known == false)
		return false;

	bool sent = (len != 0 && PeerSendTo(a, dst, buf, len));

	if (rekey) {
		AcquireSRWLockShared(&a->Lock);
		{
			PEER *p = PeerFind(a, dst);

			len = (p != NULL ? PeerSessionInitiate(a, p, buf) : 0);
		}
		ReleaseSRWLockShared(&a->Lock);

		if (len != 0)
			PeerSendTo(a, dst, buf, len);
	}

	return sent || queued;
}

// The timers of the peer sessions (PeerSessionTick): an initiation again, a rekey or a keepalive, sent on the path of
// each peer. Each session reads the clock once it holds its lock, or takes at when it is not NULL (PeerSessionTickAt).
static void PeerSessionTimers(PEER_AGENT *a, const UINT64 *at) {
	UCHAR buf[PEER_MAX_DATAGRAM];
	UCHAR key[PEER_KEY_SIZE];

	for (UINT i = 0;; i++) {
		UINT len = 0;
		bool more = false;

		AcquireSRWLockShared(&a->Lock);
		{
			more = (i < a->NumPeers);
			if (more) {
				CopyMemory(key, a->Peers[i].Info.Key, PEER_KEY_SIZE);
				len = PeerSessionTick(a, &a->Peers[i], buf, at);
			}
		}
		ReleaseSRWLockShared(&a->Lock);

		if (more == false)
			break;
		if (len != 0)
			PeerSendTo(a, key, buf, len);
	}
}

// The timers of the binds, from PeerTick: the relay role drops the bindings that were not renewed in BindExpiry, and the
// node renews or retries its own binds (PeerBindWanted). at, when not NULL, is the clock in place of the one that they
// read (PeerTickAt).
static void PeerBindTimers(PEER_AGENT *a, const UINT64 *at) {
	if (a->Config.Relay) {
		UINT64 now = (at != NULL ? *at : PeerNow());

		AcquireSRWLockExclusive(&a->Lock);
		{
			UINT n = 0;

			for (UINT i = 0; i < a->NumBindings; i++) {
				if (now - a->Bindings[i].Tick >= a->Config.BindExpiry)
					continue;
				if (n != i)
					a->Bindings[n] = a->Bindings[i];
				n++;
			}

			a->NumBindings = n;
		}
		ReleaseSRWLockExclusive(&a->Lock);
	}

	PeerBindWanted(a, at);
}

// The timer of the peer layer, at least once a second: the relay role drops the bindings that were not renewed in
// BindExpiry, the node renews or retries its own binds, and with ICE a session of its offer that had no answer in time
// fails (PeerIceTick)
void PeerTick(PEER_AGENT *a) {
	if (a == NULL)
		return;

	PeerBindTimers(a, NULL);
	PeerPunchTick(a);
	PeerSessionTimers(a, NULL);
	if (a->Config.Ice)
		PeerIceTick(a);
}

// The timers of the binds at the clock now (ms, the clock of PeerNow) in place of the one that they read: a test gives it
// a clock that is older than a bind that the node sent or the relay role took, as a tick that read its clock before
// another thread sent or took the bind would see it (CORE-S5-6-R4, #595). The sessions have PeerSessionTickAt and ICE has
// PeerIceTickAt; the punches need none, as PeerPunchTick reads its clock under both of their locks.
void PeerTickAt(PEER_AGENT *a, UINT64 now) {
	if (a == NULL)
		return;

	PeerBindTimers(a, &now);
}

// The timers of the peer sessions at the clock now (ms, the clock of PeerNow) in place of the one that each session
// reads: a test gives it a clock that is older than an initiation or keys of a session, as a tick that read its clock
// before another thread sent the initiation or made the keys would see them (CORE-S5-6-R3, #574)
void PeerSessionTickAt(PEER_AGENT *a, UINT64 now) {
	if (a == NULL)
		return;

	PeerSessionTimers(a, &now);
}

// How the node reaches the peer of key; false when key is no peer
bool PeerGetStatus(PEER_AGENT *a, const UCHAR *key, PEER_STATUS *st) {
	bool ret = false;

	if (st == NULL)
		return false;

	ZeroMemory(st, sizeof(PEER_STATUS));
	if (a == NULL || key == NULL)
		return false;

	AcquireSRWLockShared(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL) {
			st->Path = PeerPathOf(a, p);
			if (p->HasRelay)
				CopyMemory(st->RelayKey, p->RelayKey, PEER_KEY_SIZE);
			st->NumCandidates = p->NumCandidates;
			st->Sequence = p->Sequence;
			if (p->Ice != NULL)
				st->Ice = (UINT)InterlockedCompareExchange(&p->Ice->State, 0, 0);
			st->Punch = p->Punch.State;
			if (p->HasDirect)
				st->Direct = p->Direct;
			else if (p->Ice != NULL && PeerIceUp(p->Ice))
				st->Direct = p->Ice->Selected;
			PeerSessionStatus(p, st);
			ret = true;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	return ret;
}

// The counters of the peer layer
void PeerGetStats(PEER_AGENT *a, PEER_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(PEER_STATS));
	if (a == NULL)
		return;

	st->Sent = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_SENT]);
	st->Delivered = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_DELIVERED]);
	st->DeliveredRelay = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_DELIVERED_RELAY]);
	st->Forwarded = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_FORWARDED]);
	st->Binds = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_BINDS]);
	st->Signals = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_SIGNALS]);
	st->Upgrades = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_UPGRADES]);
	st->Fallbacks = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_FALLBACKS]);
	st->PunchAttempts = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_PUNCH_ATTEMPTS]);
	st->PunchSuccesses = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_PUNCH_SUCCESSES]);
	st->Handshakes = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_HANDSHAKES]);
	st->Challenges = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_CHALLENGES]);
	st->PunchFailures = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_PUNCH_FAILURES]);
	st->PunchProbes = (UINT64)ReadAcquire64(&a->Counters[PEER_COUNT_PUNCH_PROBES]);
	for (UINT i = 0; i < PEER_NUM_REASONS; i++)
		st->Drops[i] = (UINT64)ReadAcquire64(&a->Drops[i]);

	// The NAT of the node and its next mapping, which the punch predicts (PeerPunch.c)
	PeerPunchStats(a, st);

	// libplum is never called under the lock of the layer
	st->PortMap = PeerPortMapState(a);
	if (st->PortMap == PEER_PORTMAP_MAPPED && PeerPortMapGet(a, &st->Mapped) == false)
		st->PortMap = PEER_PORTMAP_PENDING;

	AcquireSRWLockShared(&a->Lock);
	{
		st->NumBindings = a->NumBindings;
		for (UINT i = 0; i < a->NumRelays; i++)
			if (a->Relays[i].Bound)
				st->NumBound++;
		for (UINT i = 0; i < a->NumPeers; i++)
			if (a->Peers[i].Ice != NULL)
				st->NumIce++;
	}
	ReleaseSRWLockShared(&a->Lock);

	st->StunMessages = (UINT64)ReadAcquire64(&a->StunMessages);
}

// Whether the node is bound to its home relay: its signals then name the address that the relay saw it at, its server
// reflexive candidate
bool PeerHomeBound(PEER_AGENT *a) {
	bool bound = false;

	if (a == NULL)
		return false;

	AcquireSRWLockShared(&a->Lock);
	bound = (a->NumRelays != 0 && a->Relays[0].Bound);
	ReleaseSRWLockShared(&a->Lock);

	return bound;
}

// The candidates that the node's signals offer now, at most max: with ICE, those of the ICE socket (the public port
// of the home gateway once it granted one, the address that the home relay saw, the host addresses); without, the
// host candidates and the server reflexive one that the home relay reported. Returns their number.
UINT PeerGetCandidates(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max) {
	UINT n = 0;

	if (a == NULL || c == NULL)
		return 0;

	if (a->Config.Ice)
		return PeerIceCandidates(a, c, max);

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumHosts && n < max; i++) {
			c[n].Type = PEER_CANDIDATE_HOST;
			c[n].Addr = a->Hosts[i];
			n++;
		}

		if (a->NumRelays != 0 && a->Relays[0].Bound && n < max) {
			c[n].Type = PEER_CANDIDATE_SRFLX;
			c[n].Addr = a->Relays[0].Observed;
			n++;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	return n;
}

// An IPv4 address b0.b1.b2.b3 and a port, as an IPv4-mapped IPv6 address
void PeerAddrSetV4(PEER_ADDR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, USHORT port) {
	if (a == NULL)
		return;

	ZeroMemory(a, sizeof(PEER_ADDR));
	a->Ip[10] = 0xFF;
	a->Ip[11] = 0xFF;
	a->Ip[12] = b0;
	a->Ip[13] = b1;
	a->Ip[14] = b2;
	a->Ip[15] = b3;
	a->Port = port;
}

bool PeerAddrEqual(const PEER_ADDR *a, const PEER_ADDR *b) {
	return a->Port == b->Port && memcmp(a->Ip, b->Ip, sizeof(a->Ip)) == 0;
}

// The name of a reason of PEER_DROP_* in the counters, for logs and tests
const char *PeerReasonName(UINT reason) {
	static const char *names[PEER_NUM_REASONS] = {"ok", "malformed", "forged", "replay", "policy", "source", "not a relay", "not bound", "rate", "relay", "send", "clear", "session", "ice"};

	return (reason < PEER_NUM_REASONS ? names[reason] : "unknown");
}
