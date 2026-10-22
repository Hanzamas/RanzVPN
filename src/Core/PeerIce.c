// PeerIce.c
// ICE of the peer layer (ADR-0015 decisions 1 and 4; CORE-S5-3, #79) on libjuice: a relayed peer pair moves to a
// direct path in the background once ICE validates one, and back to the relay when that path fails.
//
// Every ICE session of a node runs on one UDP socket, the ICE socket, in the mux mode of libjuice. A base agent
// holds the socket open for the life of the layer and gathers the node's candidates (its host addresses, and the
// server reflexive one of a STUN server), which the node's signals carry. Each peer has an agent of its own on that
// socket, which libjuice finds by the username fragment of a check and by the address of a datagram. One socket
// means one NAT mapping and one public port of the home gateway for all the peers (PeerPortMap.c).
//
// An offer of the node starts its session with the peer as the controlling end; an offer of the peer starts it as
// the controlled end, and the answer gives the offering end the peer's credentials and candidates. The checks run on
// the thread of the ICE socket while the pair stays on the relay. Once a candidate pair validates, PeerSend sends on
// the session (PeerIceSend), and what the session delivers goes through the ingress of the layer like a datagram of
// PeerInput (PeerInputDirect), so the move holds back no datagram. Consent freshness (RFC 7675) keeps the direct path
// alive and checks it: when the peer stops answering for 30 s, libjuice fails the session and the pair is on the
// relay again; a new offer starts a new session, as libjuice has no ICE restart. A pair whose NATs let no check
// through, as two symmetric NATs do, stays on the relay; port prediction and birthday punching are CORE-S5-4 (#266).
//
// Locks: libjuice calls back on the thread of the ICE socket under a mutex of its own, and the callbacks take the
// lock of the layer, so nothing here calls libjuice under that lock except juice_send, which takes only a send
// mutex. IceLock serialises the start, the remote side and the end of the sessions.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/PeerInternal.h"

#include <juice/juice.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PEER_ICE_UFRAG_LEN 8  // The username fragment of a session of the node, in ice-chars
#define PEER_ICE_PWD_LEN   24 // ... and its password
#define PEER_ICE_TOKENS    8  // The fields of a candidate line up to its type

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

// The text of the address of a as a candidate line names it: a.b.c.d for an IPv4-mapped address, else IPv6
static void PeerIceHost(char *str, UINT size, const PEER_ADDR *a) {
	static const UCHAR mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};

	if (memcmp(a->Ip, mapped, sizeof(mapped)) == 0)
		snprintf(str, size, "%u.%u.%u.%u", a->Ip[12], a->Ip[13], a->Ip[14], a->Ip[15]);
	else if (inet_ntop(AF_INET6, a->Ip, str, size) == NULL)
		str[0] = 0;
}

// The type and the address of the SDP candidate line that starts at line, as libjuice writes it (RFC 8839 section
// 5.1): "a=candidate:<foundation> <component> UDP <priority> <address> <port> typ <type>", then the rest of the line.
// A host candidate is PEER_CANDIDATE_HOST; a server reflexive and a peer reflexive one are PEER_CANDIDATE_SRFLX.
// False for any other line.
static bool PeerIceParse(const char *line, PEER_CANDIDATE *c) {
	char tok[PEER_ICE_TOKENS][PEER_HOST_SIZE];
	UINT n = 0;
	char *end = NULL;

	if (strncmp(line, "a=", 2) == 0)
		line += 2;
	if (strncmp(line, "candidate:", 10) != 0)
		return false;

	while (n < PEER_ICE_TOKENS) {
		UINT len = 0;

		while (*line == ' ')
			line++;
		while (line[len] != 0 && line[len] != ' ' && line[len] != '\r' && line[len] != '\n')
			len++;
		if (len == 0 || len >= PEER_HOST_SIZE)
			return false;

		CopyMemory(tok[n], line, len);
		tok[n][len] = 0;
		line += len;
		n++;
	}

	if (_stricmp(tok[2], "UDP") != 0 || strcmp(tok[6], "typ") != 0)
		return false;

	if (strcmp(tok[7], "host") == 0)
		c->Type = PEER_CANDIDATE_HOST;
	else if (strcmp(tok[7], "srflx") == 0 || strcmp(tok[7], "prflx") == 0)
		c->Type = PEER_CANDIDATE_SRFLX;
	else
		return false;

	unsigned long port = strtoul(tok[5], &end, 10);
	if (end == tok[5] || *end != 0 || port == 0 || port > 65535)
		return false;

	return PeerAddrFromHost(&c->Addr, tok[4], (USHORT)port);
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

// The state of a session changed: on the thread of the ICE socket, or on the one that gathers for GATHERING and
// CONNECTING. The first validated pair moves the peer to the direct path; a failure after it moves it back.
static void PeerIceOnState(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	PEER_ICE *ice = (PEER_ICE *)user_ptr;
	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	PEER_CANDIDATE selected;

	switch (state) {
	case JUICE_STATE_CONNECTED:
	case JUICE_STATE_COMPLETED:
		// The peer's address on the validated pair, for PeerGetStatus
		if (juice_get_selected_candidates(agent, local, sizeof(local), remote, sizeof(remote)) == JUICE_ERR_SUCCESS && PeerIceParse(remote, &selected)) {
			AcquireSRWLockExclusive(&ice->Agent->Lock);
			ice->Selected = selected.Addr;
			ReleaseSRWLockExclusive(&ice->Agent->Lock);
		}

		InterlockedExchange(&ice->State, (state == JUICE_STATE_CONNECTED ? PEER_ICE_CONNECTED : PEER_ICE_COMPLETED));
		if (InterlockedCompareExchange(&ice->Upgraded, 1, 0) == 0)
			PeerCount(ice->Agent, PEER_COUNT_UPGRADES);
		break;
	case JUICE_STATE_FAILED:
		InterlockedExchange(&ice->State, PEER_ICE_FAILED);
		if (InterlockedCompareExchange(&ice->Upgraded, 2, 1) == 1)
			PeerCount(ice->Agent, PEER_COUNT_FALLBACKS);
		break;
	default:
		break;
	}
}

// A datagram that the session delivered, on the thread of the ICE socket
static void PeerIceOnRecv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	PEER_ICE *ice = (PEER_ICE *)user_ptr;

	if (size > PEER_MAX_DATAGRAM) {
		PeerDrop(ice->Agent, PEER_DROP_MALFORMED);
		return;
	}

	PeerInputDirect(ice->Agent, ice->Key, (const UCHAR *)data, (UINT)size);
}

// End a session: libjuice destroys its agent once no callback of it runs any more. Without the lock of the layer.
static void PeerIceFree(PEER_ICE *ice) {
	if (ice->Juice != NULL)
		juice_destroy(ice->Juice);

	SecureZeroMemory(ice, sizeof(PEER_ICE));
	HeapFree(GetProcessHeap(), 0, ice);
}

// A new session of the node with the peer of key on the ICE socket, controlling when the node offers: an agent of
// libjuice with fresh credentials, which has not gathered yet. NULL when libjuice refuses it.
static PEER_ICE *PeerIceNew(PEER_AGENT *a, const UCHAR *key, bool controlling) {
	juice_config_t jc;

	PEER_ICE *ice = (PEER_ICE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_ICE));
	if (ice == NULL)
		return NULL;

	ice->Agent = a;
	CopyMemory(ice->Key, key, PEER_KEY_SIZE);
	ice->Controlling = controlling;
	ice->State = PEER_ICE_CHECKING;

	ZeroMemory(&jc, sizeof(jc));
	jc.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	jc.bind_address = (a->Config.IceBind[0] != 0 ? a->Config.IceBind : NULL);
	jc.local_port_range_begin = a->Ice.Port;
	jc.local_port_range_end = a->Ice.Port;
	jc.cb_state_changed = PeerIceOnState;
	jc.cb_recv = PeerIceOnRecv;
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

// Whether the session has a validated pair: the peer is on the direct path
bool PeerIceUp(PEER_ICE *ice) {
	LONG state = InterlockedCompareExchange(&ice->State, 0, 0);

	return state == PEER_ICE_CONNECTED || state == PEER_ICE_COMPLETED;
}

// Send one datagram on the direct path of the session; false when it has none (yet, or any more). Under the shared
// lock of the layer, which keeps the session from ending meanwhile.
bool PeerIceSend(PEER_ICE *ice, const void *data, UINT size) {
	return juice_send(ice->Juice, (const char *)data, size) == JUICE_ERR_SUCCESS;
}

// Open the ICE socket of the node: the base agent of libjuice in mux mode on Config.IceBind and Config.IcePort,
// which gathers the node's candidates, with the server reflexive one of Config.StunServer; then, with
// Config.PortMap, the port mapping. False when the socket cannot open.
bool PeerIceStart(PEER_AGENT *a) {
	juice_config_t jc;
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	PEER_CANDIDATE c;

	ZeroMemory(&jc, sizeof(jc));
	jc.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	jc.bind_address = (a->Config.IceBind[0] != 0 ? a->Config.IceBind : NULL);
	jc.local_port_range_begin = a->Config.IcePort;
	jc.local_port_range_end = a->Config.IcePort;
	if (a->Config.StunServer[0] != 0) {
		jc.stun_server_host = a->Config.StunServer;
		jc.stun_server_port = (a->Config.StunPort != 0 ? a->Config.StunPort : 3478);
	}

	a->Ice.Base = juice_create(&jc);
	if (a->Ice.Base == NULL || juice_gather_candidates(a->Ice.Base) != JUICE_ERR_SUCCESS)
		return false;

	// The port of the socket: the configured one, or the one of its host candidates
	a->Ice.Port = a->Config.IcePort;
	if (a->Ice.Port == 0 && juice_get_local_description(a->Ice.Base, sdp, sizeof(sdp)) == JUICE_ERR_SUCCESS) {
		for (const char *line = sdp; *line != 0 && a->Ice.Port == 0;) {
			const char *next = strchr(line, '\n');

			if (PeerIceParse(line, &c))
				a->Ice.Port = c.Addr.Port;
			line = (next != NULL ? next + 1 : line + strlen(line));
		}
	}

	if (a->Ice.Port == 0)
		return false;

	if (a->Config.PortMap)
		PeerPortMapStart(a);

	return true;
}

// End every ICE session of the node, then the port mapping and the ICE socket. Each session leaves the table under
// the lock of the layer and ends without it.
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

	if (a->Ice.Base != NULL) {
		juice_destroy(a->Ice.Base);
		a->Ice.Base = NULL;
	}
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

// Before the node seals an offer for the peer of key: a new session as the controlling end, unless one runs that
// has not failed. Without the lock of the layer.
void PeerIceOffer(PEER_AGENT *a, const UCHAR *key) {
	bool start = false;

	AcquireSRWLockExclusive(&a->IceLock);
	{
		AcquireSRWLockShared(&a->Lock);
		{
			PEER *p = PeerFind(a, key);

			start = (p != NULL && (p->Ice == NULL || InterlockedCompareExchange(&p->Ice->State, 0, 0) == PEER_ICE_FAILED));
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
// or a restart that libjuice cannot take, and changes nothing. Without the lock of the layer.
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
		bool waiting = (cur != NULL && cur->Controlling && cur->RemoteUfrag[0] == 0);

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

// The candidates of the node's signals with ICE, at most max: the public port of the home gateway first, then the
// server reflexive candidate of the STUN server, then the host addresses of the ICE socket. Without the lock of the
// layer.
UINT PeerIceCandidates(PEER_AGENT *a, PEER_CANDIDATE *c, UINT max) {
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	PEER_CANDIDATE found;
	PEER_ADDR mapped;
	UINT n = 0;

	if (max != 0 && PeerPortMapGet(a, &mapped)) {
		c[n].Type = PEER_CANDIDATE_MAPPED;
		c[n].Addr = mapped;
		n++;
	}

	if (a->Ice.Base == NULL || juice_get_local_description(a->Ice.Base, sdp, sizeof(sdp)) != JUICE_ERR_SUCCESS)
		return n;

	// The server reflexive candidates in the first pass over the lines, the host ones in the second
	for (UINT pass = 0; pass < 2; pass++) {
		UINT type = (pass == 0 ? PEER_CANDIDATE_SRFLX : PEER_CANDIDATE_HOST);

		for (const char *line = sdp; *line != 0 && n < max;) {
			const char *next = strchr(line, '\n');

			if (PeerIceParse(line, &found) && found.Type == type && PeerIceHasCandidate(c, n, &found.Addr) == false)
				c[n++] = found;
			line = (next != NULL ? next + 1 : line + strlen(line));
		}
	}

	return n;
}
