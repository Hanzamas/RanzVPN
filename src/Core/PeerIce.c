// PeerIce.c
// ICE of the peer layer (ADR-0015 decisions 1 and 4; CORE-S5-3, #79; CORE-S5-6, #412) on libjuice: a relayed peer pair
// moves to a direct path in the background once ICE validates one (an Upgrade), and back to the relay when that path
// fails (a Fallback). The peer session of the pair moves with it and keeps its keys (PeerSession.c).
//
// Every ICE session of a node runs on the socket of its peer layer, the ICE socket, which its binds and its records go
// on too: each agent of libjuice runs in the peer mode of juice-peer.c, which sends through the send procedure of the
// layer and takes the STUN messages that come to the socket from PeerInput (PeerIceInput). One socket means one NAT
// mapping for the relay and every peer, so the address that the home relay saw the node at, which the answer of its
// bind gives, is its server reflexive candidate, and no STUN server is needed. The candidates of the node's signals are
// the public port of its home gateway when it asked for one (PeerPortMap.c), then that server reflexive address, then
// the host addresses of the socket (PeerSetHostCandidates). On the network of a test the NAT simulator of the core
// tests carries the checks as it carries every datagram of the layer.
//
// An offer of the node starts its session with the peer as the controlling end; an offer of the peer starts it as the
// controlled end, and the answer gives the offering end the peer's credentials and candidates. A check of the peer
// that comes before that answer is not taken, and the peer sends it again (juice-peer.c says why). libjuice starts no
// timer of a session before it has the peer's credentials, so a session of the node's offer whose answer does not
// come in PEER_ICE_ANSWER_TIMEOUT, as when the answer was lost on the way or the peer had no session to answer with,
// fails (PeerIceTick; CORE-S5-6-R1, #537), and the node offers again, as after any failure. The checks run on
// the thread of each session while the pair stays on the relay. Once a candidate pair validates, PeerSend sends the records
// of the peer session to the peer's address on that pair, on the socket of the layer, and PeerInput takes the records
// from there as the direct path (PeerSourcePath), so the move holds back no datagram. Consent freshness (RFC 7675)
// keeps the direct path alive and checks it: when the peer stops answering for 30 s, libjuice fails the session and the
// pair is on the relay again. A session that failed answers no check (juice_peer_take), so the consent of the peer
// fails too and both ends fall back. A new offer starts a new session, as libjuice has no ICE restart: after one that
// failed, and in place of one that is still checking when the home gateway granted its public port since it started,
// so the checks go to that port. A pair whose NATs let no check through, as two symmetric NATs do, stays on the relay;
// port prediction and birthday punching are CORE-S5-4 (#266).
//
// Locks: libjuice calls back under the mutex of the agent, on the thread of the session or on the thread of PeerInput,
// and the callbacks take the lock of the layer, so nothing here calls libjuice under that lock. IceLock serialises the
// start, the remote side and the end of the sessions; PeerIceInput holds it shared, so no session ends while it hands
// one a message, and so does PeerIceTick, so no answer comes while it fails a session that waits for one, and no session
// that it looks at started after the clock that it reads once it holds the lock (CORE-S5-6-R2, #557).

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/PeerInternal.h"

#include <stdio.h>
#include <string.h>

#define PEER_ICE_UFRAG_LEN 8  // The username fragment of a session of the node, in ice-chars
#define PEER_ICE_PWD_LEN   24 // ... and its password

// The ice-chars of RFC 8839 section 5.4, which the credentials of a session are drawn from
static const char PeerIceChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// A random string of len ice-chars into str, which holds len + 1
static bool PeerIceRandom(char *str, UINT len) {
	UCHAR r[PEER_ICE_PWD_SIZE];

	if (len >= sizeof(r) || CryptoRandom(r, len) == false)
		return false;

	for (UINT i = 0; i < len; i++)
		str[i] = PeerIceChars[r[i] % 64];
	str[len] = 0;

	SecureZeroMemory(r, sizeof(r));
	return true;
}

// The address host, IPv4 or IPv6 text, and port into a; false when host is neither
bool PeerAddrFromHost(PEER_ADDR *a, const char *host, USHORT port) {
	IN_ADDR in4;
	IN6_ADDR in6;

	ZeroMemory(a, sizeof(PEER_ADDR));

	if (inet_pton(AF_INET, host, &in4) == 1) {
		const UCHAR *b = (const UCHAR *)&in4;

		PeerAddrSetV4(a, b[0], b[1], b[2], b[3], port);
		return true;
	}

	if (inet_pton(AF_INET6, host, &in6) == 1) {
		CopyMemory(a->Ip, &in6, sizeof(a->Ip));
		a->Port = port;
		return true;
	}

	return false;
}

// Whether a is an IPv4 address as an IPv4-mapped IPv6 address
static bool PeerIceIsV4(const PEER_ADDR *a) {
	static const UCHAR mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};

	return memcmp(a->Ip, mapped, sizeof(mapped)) == 0;
}

// The socket address of a, IPv4 for an IPv4-mapped address, as libjuice names the addresses of its candidates; returns
// its length
static int PeerIceToSockaddr(SOCKADDR_STORAGE *sa, const PEER_ADDR *a) {
	ZeroMemory(sa, sizeof(SOCKADDR_STORAGE));

	if (PeerIceIsV4(a)) {
		SOCKADDR_IN *in = (SOCKADDR_IN *)sa;

		in->sin_family = AF_INET;
		in->sin_port = htons(a->Port);
		CopyMemory(&in->sin_addr, a->Ip + 12, 4);
		return (int)sizeof(SOCKADDR_IN);
	}

	SOCKADDR_IN6 *in6 = (SOCKADDR_IN6 *)sa;
	in6->sin6_family = AF_INET6;
	in6->sin6_port = htons(a->Port);
	CopyMemory(&in6->sin6_addr, a->Ip, sizeof(a->Ip));
	return (int)sizeof(SOCKADDR_IN6);
}

// The PEER_ADDR of a socket address of len bytes; false for a family other than IPv4 and IPv6
static bool PeerIceFromSockaddr(PEER_ADDR *a, const SOCKADDR *sa, int len) {
	ZeroMemory(a, sizeof(PEER_ADDR));

	if (sa->sa_family == AF_INET && len >= (int)sizeof(SOCKADDR_IN)) {
		const SOCKADDR_IN *in = (const SOCKADDR_IN *)sa;
		const UCHAR *b = (const UCHAR *)&in->sin_addr;

		PeerAddrSetV4(a, b[0], b[1], b[2], b[3], ntohs(in->sin_port));
		return true;
	}

	if (sa->sa_family == AF_INET6 && len >= (int)sizeof(SOCKADDR_IN6)) {
		const SOCKADDR_IN6 *in6 = (const SOCKADDR_IN6 *)sa;

		CopyMemory(a->Ip, &in6->sin6_addr, sizeof(a->Ip));
		a->Port = ntohs(in6->sin6_port);
		return true;
	}

	return false;
}

// The text of the address of a as a candidate line names it: a.b.c.d for an IPv4-mapped address, else IPv6
static void PeerIceHost(char *str, UINT size, const PEER_ADDR *a) {
	if (PeerIceIsV4(a))
		snprintf(str, size, "%u.%u.%u.%u", a->Ip[12], a->Ip[13], a->Ip[14], a->Ip[15]);
	else if (inet_ntop(AF_INET6, a->Ip, str, size) == NULL)
		str[0] = 0;
}

// Whether one of the n candidates c is at addr
static bool PeerIceHasCandidate(const PEER_CANDIDATE *c, UINT n, const PEER_ADDR *addr) {
	for (UINT i = 0; i < n; i++)
		if (PeerAddrEqual(&c[i].Addr, addr))
			return true;

	return false;
}

// The SDP of the peer's session for libjuice: the credentials and every candidate of its signal s, and the end of
// its candidates. A host candidate has the type preference 126, a server reflexive one and a mapped port, which a
// check reaches as it reaches a server reflexive one, have 100 (RFC 8445 section 5.1.2.1); the local preference
// falls with the order of the signal, which puts the mapped port first. False when it does not fit size.
static bool PeerIceRemoteSdp(char *sdp, UINT size, const PEER_SIGNAL *s) {
	char host[INET6_ADDRSTRLEN];

	int len = snprintf(sdp, size, "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n", s->IceUfrag, s->IcePwd);

	for (UINT i = 0; i < s->NumCandidates && len > 0 && (UINT)len < size; i++) {
		const PEER_CANDIDATE *c = &s->Candidates[i];
		UINT preference = (c->Type == PEER_CANDIDATE_HOST ? 126 : 100);
		UINT priority = (preference << 24) | ((65535 - i) << 8) | 255;

		PeerIceHost(host, sizeof(host), &c->Addr);
		if (host[0] == 0)
			continue;

		len += snprintf(sdp + len, size - (UINT)len, "a=candidate:%u 1 UDP %u %s %u typ %s\r\n", i + 1, priority, host, c->Addr.Port, (c->Type == PEER_CANDIDATE_HOST ? "host" : "srflx"));
	}

	if (len > 0 && (UINT)len < size)
		len += snprintf(sdp + len, size - (UINT)len, "a=end-of-candidates\r\n");

	return len > 0 && (UINT)len < size;
}

// The send procedure of an agent (juice_peer_io_t): a datagram of libjuice, a check or its answer, goes on the socket of
// the layer, as every datagram of the layer goes
static int PeerIceIoSend(void *user_ptr, const struct sockaddr *dst, int dst_len, const char *data, size_t size) {
	PEER_ICE *ice = (PEER_ICE *)user_ptr;
	PEER_ADDR to;

	if (size == 0 || size > PEER_MAX_DATAGRAM || PeerIceFromSockaddr(&to, (const SOCKADDR *)dst, dst_len) == false)
		return -1;

	return (PeerSendRaw(ice->Agent, &to, data, (UINT)size) ? (int)size : -1);
}

// The host addresses of an agent (juice_peer_io_t): the host candidates of the layer, the addresses of its socket
static int PeerIceIoAddrs(void *user_ptr, struct sockaddr_storage *addrs, int max) {
	PEER_ICE *ice = (PEER_ICE *)user_ptr;
	PEER_AGENT *a = ice->Agent;
	int n = 0;

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumHosts && n < max; i++)
			PeerIceToSockaddr((SOCKADDR_STORAGE *)&addrs[n++], &a->Hosts[i]);
	}
	ReleaseSRWLockShared(&a->Lock);

	return n;
}

// The state of a session changed, under the mutex of its agent: on the thread of the session, on the thread of
// PeerInput, or on the one that gathers for GATHERING and CONNECTING. A validated pair lets the node take the records
// of the peer from its address; the nominated pair moves the peer to the direct path, which counts as an Upgrade; a
// failure after it moves the peer back to the relay, which counts as a Fallback.
static void PeerIceOnState(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	PEER_ICE *ice = (PEER_ICE *)user_ptr;
	SOCKADDR_STORAGE remote;
	PEER_ADDR selected;

	switch (state) {
	case JUICE_STATE_CONNECTED:
	case JUICE_STATE_COMPLETED: {
		// The peer's address on the selected pair, where PeerSend sends its records and where PeerInput takes them from
		int len = juice_peer_selected(agent, (struct sockaddr_storage *)&remote);

		if (len > 0 && PeerIceFromSockaddr(&selected, (const SOCKADDR *)&remote, len)) {
			AcquireSRWLockExclusive(&ice->Agent->Lock);
			ice->Selected = selected;
			ReleaseSRWLockExclusive(&ice->Agent->Lock);
		}

		InterlockedExchange(&ice->State, (state == JUICE_STATE_CONNECTED ? PEER_ICE_CONNECTED : PEER_ICE_COMPLETED));
		if (state == JUICE_STATE_COMPLETED && InterlockedCompareExchange(&ice->Upgraded, 1, 0) == 0)
			PeerCount(ice->Agent, PEER_COUNT_UPGRADES);
		break;
	}
	case JUICE_STATE_FAILED:
		InterlockedExchange(&ice->State, PEER_ICE_FAILED);
		if (InterlockedCompareExchange(&ice->Upgraded, 2, 1) == 1)
			PeerCount(ice->Agent, PEER_COUNT_FALLBACKS);
		break;
	default:
		break;
	}
}

// End a session: libjuice ends its thread and destroys its agent. Without the lock of the layer.
static void PeerIceFree(PEER_ICE *ice) {
	if (ice->Juice != NULL)
		juice_destroy(ice->Juice);

	SecureZeroMemory(ice, sizeof(PEER_ICE));
	HeapFree(GetProcessHeap(), 0, ice);
}

// A new session of the node with the peer of key on the socket of the layer, controlling when the node offers: an
// agent of libjuice in the peer mode with fresh credentials, which has not gathered yet. NULL when libjuice refuses it.
static PEER_ICE *PeerIceNew(PEER_AGENT *a, const UCHAR *key, bool controlling) {
	juice_config_t jc;
	PEER_ADDR mapped;

	PEER_ICE *ice = (PEER_ICE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_ICE));
	if (ice == NULL)
		return NULL;

	ice->Io.send = PeerIceIoSend;
	ice->Io.get_addrs = PeerIceIoAddrs;
	ice->Agent = a;
	CopyMemory(ice->Key, key, PEER_KEY_SIZE);
	ice->Controlling = controlling;
	ice->Mapped = PeerPortMapGet(a, &mapped);
	ice->Started = PeerNow();
	ice->State = PEER_ICE_CHECKING;

	// No STUN or TURN server: the server reflexive candidate is the address that the home relay saw
	ZeroMemory(&jc, sizeof(jc));
	jc.concurrency_mode = JUICE_CONCURRENCY_MODE_PEER;
	jc.cb_state_changed = PeerIceOnState;
	jc.user_ptr = ice;

	if (PeerIceRandom(ice->Ufrag, PEER_ICE_UFRAG_LEN) && PeerIceRandom(ice->Pwd, PEER_ICE_PWD_LEN))
		ice->Juice = juice_create(&jc);

	if (ice->Juice == NULL || juice_set_local_ice_attributes(ice->Juice, ice->Ufrag, ice->Pwd) != JUICE_ERR_SUCCESS) {
		PeerIceFree(ice);
		return NULL;
	}

	return ice;
}

// Give the session the peer's credentials and candidates of its signal s. Under IceLock.
static bool PeerIceSetRemote(PEER_ICE *ice, const PEER_SIGNAL *s) {
	char sdp[JUICE_MAX_SDP_STRING_LEN];

	if (PeerIceRemoteSdp(sdp, sizeof(sdp), s) == false || juice_set_remote_description(ice->Juice, sdp) != JUICE_ERR_SUCCESS)
		return false;

	strcpy_s(ice->RemoteUfrag, sizeof(ice->RemoteUfrag), s->IceUfrag);
	return true;
}

// Put the session ice in the place of the peer of key and end the one it replaces; when the peer went meanwhile,
// ice ends. Under IceLock, without the lock of the layer.
static void PeerIceInstall(PEER_AGENT *a, const UCHAR *key, PEER_ICE *ice) {
	PEER_ICE *old = ice;

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER *p = PeerFind(a, key);

		if (p != NULL) {
			old = p->Ice;
			p->Ice = ice;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	if (old != NULL)
		PeerIceFree(old);
}

// Whether the session has a validated pair and the peer's address on it, from where the node takes the records of the
// peer as on the direct path. The caller holds the lock of the layer.
bool PeerIceValid(PEER_ICE *ice) {
	LONG state = InterlockedCompareExchange(&ice->State, 0, 0);

	return (state == PEER_ICE_CONNECTED || state == PEER_ICE_COMPLETED) && ice->Selected.Port != 0;
}

// Whether the peer is on the direct path: the controlling end nominated the pair, so both ends use the same one and
// the node sends the records of the peer there. The caller holds the lock of the layer.
bool PeerIceUp(PEER_ICE *ice) {
	return InterlockedCompareExchange(&ice->State, 0, 0) == PEER_ICE_COMPLETED && ice->Selected.Port != 0;
}

// End every ICE session of the node, then the port mapping. Each session leaves the table under the lock of the layer
// and ends without it.
void PeerIceStop(PEER_AGENT *a) {
	AcquireSRWLockExclusive(&a->IceLock);
	while (true) {
		PEER_ICE *ice = NULL;

		AcquireSRWLockExclusive(&a->Lock);
		{
			for (UINT i = 0; i < a->NumPeers && ice == NULL; i++) {
				ice = a->Peers[i].Ice;
				a->Peers[i].Ice = NULL;
			}
		}
		ReleaseSRWLockExclusive(&a->Lock);

		if (ice == NULL)
			break;

		PeerIceFree(ice);
	}
	ReleaseSRWLockExclusive(&a->IceLock);

	PeerPortMapStop(a);
}

// End the sessions of a peer table that the layer holds no more (PeerSetPeers). Under IceLock.
void PeerIceRetire(PEER *peers, UINT num) {
	for (UINT i = 0; i < num; i++) {
		if (peers[i].Ice != NULL) {
			PeerIceFree(peers[i].Ice);
			peers[i].Ice = NULL;
		}
	}
}

// Whether the session is an offer of the node that waits for the answer of the peer: controlling, without the peer's
// credentials, and not failed. Under IceLock.
static bool PeerIceWaiting(PEER_ICE *ice) {
	return ice->Controlling && ice->RemoteUfrag[0] == 0 && InterlockedCompareExchange(&ice->State, 0, 0) != PEER_ICE_FAILED;
}

// A session of the node's offer that has waited PEER_ICE_ANSWER_TIMEOUT at the clock now (PeerNow) for the answer of the
// peer fails, as when the answer was lost on the way or the peer had no session to answer with. A session that started
// after now has waited no time: its age is no difference of the two clocks, which would wrap for it and fail it at once
// (CORE-S5-6-R2, #557). Under IceLock, without the lock of the layer.
static void PeerIceExpire(PEER_AGENT *a, UINT64 now) {
	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers; i++) {
			PEER_ICE *ice = a->Peers[i].Ice;

			if (ice != NULL && PeerIceWaiting(ice) && now >= ice->Started + PEER_ICE_ANSWER_TIMEOUT)
				InterlockedCompareExchange(&ice->State, PEER_ICE_FAILED, PEER_ICE_CHECKING);
		}
	}
	ReleaseSRWLockShared(&a->Lock);
}

// The timer of the sessions, from PeerTick: a session of the node's offer that has waited PEER_ICE_ANSWER_TIMEOUT for the
// answer of the peer fails (PeerIceExpire). libjuice runs no timer of a session before it has the peer's credentials, so
// without this the session would wait for good, and the pair with it on the relay: the node offers again only after a
// failure (NodeAgent.c), and a waiting session keeps out the offers of a peer of a lower key (PeerIceRemote). The clock is
// read once IceLock is held, under which an offer makes its session, so every session here started before it, whatever
// the order of the threads. Without the lock of the layer.
void PeerIceTick(PEER_AGENT *a) {
	AcquireSRWLockShared(&a->IceLock);
	PeerIceExpire(a, PeerNow());
	ReleaseSRWLockShared(&a->IceLock);
}

// The timer of the sessions at the clock now (ms, the clock of PeerNow) in place of the one that PeerIceTick reads: a test
// gives it a clock that a session started after, as a tick that read its clock before an offer made the session would
void PeerIceTickAt(PEER_AGENT *a, UINT64 now) {
	if (a == NULL)
		return;

	AcquireSRWLockShared(&a->IceLock);
	PeerIceExpire(a, now);
	ReleaseSRWLockShared(&a->IceLock);
}

// Before the node seals an offer for the peer of key: a new session as the controlling end, unless one runs that has
// not failed and is up or knows the public port of the home gateway. Without the lock of the layer.
void PeerIceOffer(PEER_AGENT *a, const UCHAR *key) {
	PEER_ADDR mapped;
	bool start = false;
	bool has_mapped = PeerPortMapGet(a, &mapped);

	AcquireSRWLockExclusive(&a->IceLock);
	{
		AcquireSRWLockShared(&a->Lock);
		{
			PEER *p = PeerFind(a, key);
			LONG state = (p != NULL && p->Ice != NULL ? InterlockedCompareExchange(&p->Ice->State, 0, 0) : PEER_ICE_NONE);

			start = (p != NULL && (p->Ice == NULL || state == PEER_ICE_FAILED || (state == PEER_ICE_CHECKING && has_mapped && p->Ice->Mapped == false)));
		}
		ReleaseSRWLockShared(&a->Lock);

		if (start) {
			PEER_ICE *ice = PeerIceNew(a, key, true);

			if (ice != NULL && juice_gather_candidates(ice->Juice) == JUICE_ERR_SUCCESS)
				PeerIceInstall(a, key, ice);
			else if (ice != NULL)
				PeerIceFree(ice);
		}
	}
	ReleaseSRWLockExclusive(&a->IceLock);
}

// The ICE credentials and the candidates of the signal s that the peer of key sent. An offer starts a new session
// as the controlled end, unless it repeats the session there is, or it meets an offer of the node that waits for
// its answer and the node has the higher key: both ends decide alike, so the other one takes the node's offer. An
// answer gives the node's waiting offer the peer's side; to a session that has it already, an answer is a repeat,
// or a restart that libjuice cannot take, and changes nothing. An offer of the node that failed waits for nothing
// (PeerIceTick): a late answer does not bring it back, and the peer's next offer takes its place. Without the lock of
// the layer.
void PeerIceRemote(PEER_AGENT *a, const UCHAR *key, const PEER_SIGNAL *s) {
	PEER_ICE *cur = NULL;
	bool known = false;

	AcquireSRWLockExclusive(&a->IceLock);
	{
		AcquireSRWLockShared(&a->Lock);
		{
			PEER *p = PeerFind(a, key);

			known = (p != NULL);
			cur = (p != NULL ? p->Ice : NULL);
		}
		ReleaseSRWLockShared(&a->Lock);

		bool repeat = (cur != NULL && strcmp(cur->RemoteUfrag, s->IceUfrag) == 0);
		bool waiting = (cur != NULL && PeerIceWaiting(cur));

		if (known && repeat == false && s->Type == PEER_SIGNAL_OFFER && (waiting == false || memcmp(a->Key.Public, key, PEER_KEY_SIZE) < 0)) {
			PEER_ICE *ice = PeerIceNew(a, key, false);

			if (ice != NULL && PeerIceSetRemote(ice, s) && juice_gather_candidates(ice->Juice) == JUICE_ERR_SUCCESS)
				PeerIceInstall(a, key, ice);
			else if (ice != NULL)
				PeerIceFree(ice);
		} else if (known && repeat == false && s->Type == PEER_SIGNAL_ANSWER && waiting) {
			PeerIceSetRemote(cur, s);
		}
	}
	ReleaseSRWLockExclusive(&a->IceLock);
}

// Whether a datagram that came to the socket is a STUN message: a check of ICE or its answer, which PeerInput hands to
// PeerIceInput. Every other datagram of the layer starts with its kind, PEER_MSG_*, and none carries the magic cookie
// of STUN where a STUN message has it.
bool PeerIceIsStun(const UCHAR *data, UINT size) {
	return juice_peer_is_stun((const char *)data, size);
}

// The agent of the session whose username fragment is ufrag, NULL for none. Under IceLock, without the lock of the layer.
static juice_agent_t *PeerIceNamed(PEER_AGENT *a, const char *ufrag) {
	juice_agent_t *juice = NULL;

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers && juice == NULL; i++) {
			PEER_ICE *ice = a->Peers[i].Ice;

			if (ice != NULL && strcmp(ice->Ufrag, ufrag) == 0)
				juice = ice->Juice;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	return juice;
}

// A STUN message that came to the socket from the address from, which any sender can send: it is read once, whatever the
// number of the ICE sessions of the node (CORE-S5-6-R1, #537), and goes to the session that it names. A check goes to the
// session whose username fragment it names, which takes it once it has the peer's credentials; an answer goes to the
// session that sent the request of its transaction: each session looks the transaction up among its own requests, and
// none reads the message again. One that no session takes is dropped and counted. The read counts in StunMessages where
// juice_peer_read makes it, not here, so a message read again would count again (CORE-S5-6-R2, #557). Called from
// PeerInput, without the lock of the layer.
void PeerIceInput(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	juice_peer_message_t m;
	SOCKADDR_STORAGE src;
	bool taken = false;

	if (juice_peer_read(&m, (const char *)data, size, &a->StunMessages) == false) {
		PeerDrop(a, PEER_DROP_ICE);
		return;
	}

	int len = PeerIceToSockaddr(&src, from);

	// The sessions cannot end meanwhile: that takes IceLock exclusively, and so does a change of the peer table. libjuice
	// takes the message under the mutex of the agent, whose callbacks take the lock of the layer.
	AcquireSRWLockShared(&a->IceLock);
	{
		if (m.check) {
			juice_agent_t *juice = PeerIceNamed(a, m.ufrag);

			taken = (juice != NULL && juice_peer_take(juice, &m, (const struct sockaddr *)&src, len));
		}

		for (UINT i = 0; m.answer && taken == false; i++) {
			juice_agent_t *juice = NULL;
			bool more = false;

			AcquireSRWLockShared(&a->Lock);
			{
				more = (i < a->NumPeers);
				if (more && a->Peers[i].Ice != NULL)
					juice = a->Peers[i].Ice->Juice;
			}
			ReleaseSRWLockShared(&a->Lock);

			if (more == false)
				break;

			taken = (juice != NULL && juice_peer_take(juice, &m, (const struct sockaddr *)&src, len));
		}
	}
	ReleaseSRWLockShared(&a->IceLock);

	if (taken == false)
		PeerDrop(a, PEER_DROP_ICE);
}

// The candidates of the node's signals with ICE, at most max: the public port of the home gateway first, then the
// address that the home relay saw the node at, then the host addresses of the socket, each address once. Without the
// lock of the layer.
UINT PeerIceCandidates(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max) {
	PEER_ADDR mapped;
	UINT n = 0;

	if (max != 0 && PeerPortMapGet(a, &mapped)) {
		c[n].Type = PEER_CANDIDATE_MAPPED;
		c[n].Addr = mapped;
		n++;
	}

	AcquireSRWLockShared(&a->Lock);
	{
		if (a->NumRelays != 0 && a->Relays[0].Bound && n < max && PeerIceHasCandidate(c, n, &a->Relays[0].Observed) == false) {
			c[n].Type = PEER_CANDIDATE_SRFLX;
			c[n].Addr = a->Relays[0].Observed;
			n++;
		}

		for (UINT i = 0; i < a->NumHosts && n < max; i++) {
			if (PeerIceHasCandidate(c, n, &a->Hosts[i]))
				continue;

			c[n].Type = PEER_CANDIDATE_HOST;
			c[n].Addr = a->Hosts[i];
			n++;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	return n;
}
