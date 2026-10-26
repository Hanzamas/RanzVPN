// PeerChallenge.c
// The bind challenge of the relay role (CORE-H2 #399; finding F3 of the second review of AUD-5, PR 405). A bind is an
// envelope sealed with the node's static key, and it holds no address, so before this a relay bound the node to the
// address that the bind came from: an attacker on the path that dropped a node's bind and sent the same envelope from
// an address of its own took the binding. Now a relay binds a node only with a cookie for the address the bind came
// from, which the relay sent to that address in a challenge sealed to the node. Only the node can open the challenge,
// and only at that address does it get it, so the same bind sent from another address draws a challenge that the
// attacker cannot read, and the binding stays where it was.
//
// The cookie is an HMAC-SHA256 under a secret of the relay, new at every start, of the node key, the address, its port
// and the period of PEER_COOKIE_PERIOD that it was made in; it is good in that period and the next. A relay keeps no
// state for a challenge. A node keeps the last cookie of each of its relays and puts it in its binds to that relay;
// a bind with no cookie, or with one that is stale or for another address, gets a challenge in place of a bound, and
// the node binds again at once with the new cookie.

#include "Core/PeerInternal.h"

#include <string.h>

#define PEER_COOKIE_INPUT (PEER_KEY_SIZE + 16 + 2 + 8) // The node key, the address, its port and the period

// The cookie of the node key at the address from in the period
static bool PeerCookieMake(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *from, UINT64 period, UCHAR *cookie) {
	UCHAR input[PEER_COOKIE_INPUT];
	UCHAR mac[CRYPTO_SHA256_SIZE];

	CopyMemory(input, key, PEER_KEY_SIZE);
	CopyMemory(input + PEER_KEY_SIZE, from->Ip, sizeof(from->Ip));
	PeerPutUint16(input + PEER_KEY_SIZE + 16, from->Port);
	PeerPutUint64(input + PEER_KEY_SIZE + 18, period);

	bool ok = CryptoHmacSha256(mac, a->CookieSecret, sizeof(a->CookieSecret), input, sizeof(input));
	if (ok)
		CopyMemory(cookie, mac, PEER_COOKIE_SIZE);

	SecureZeroMemory(mac, sizeof(mac));

	return ok;
}

// Whether cookie is the relay's cookie of the node key at the address from, of this period or the one before it. The
// comparison takes the same time whichever byte differs.
bool PeerCookieCheck(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *from, const UCHAR *cookie) {
	UCHAR expect[PEER_COOKIE_SIZE];
	UINT64 period = PeerNow() / PEER_COOKIE_PERIOD;
	bool ok = false;

	for (UINT64 i = 0; i < 2 && i <= period; i++) {
		UCHAR diff = 0;

		if (PeerCookieMake(a, key, from, period - i, expect) == false)
			break;

		for (UINT j = 0; j < PEER_COOKIE_SIZE; j++)
			diff |= (UCHAR)(expect[j] ^ cookie[j]);

		if (diff == 0)
			ok = true;
	}

	SecureZeroMemory(expect, sizeof(expect));

	return ok;
}

// Answer a bind of the node key, with the sequence seq, from the address from with a challenge: the cookie of the node
// at that address, sealed to the node and sent to that address
void PeerChallengeSend(PEER_AGENT *a, const UCHAR *key, const PEER_ADDR *from, UINT64 seq) {
	UCHAR payload[PEER_CHALLENGE_SIZE];
	UCHAR env[PEER_ENVELOPE_HEADER + PEER_CHALLENGE_SIZE + PEER_ENVELOPE_TAG];

	payload[0] = PEER_VERSION;
	PeerPutUint64(payload + 1, seq);
	if (PeerCookieMake(a, key, from, PeerNow() / PEER_COOKIE_PERIOD, payload + PEER_BIND_SIZE) == false)
		return;

	UINT size = PeerSeal(a, key, PEER_MSG_CHALLENGE, payload, sizeof(payload), env, sizeof(env));
	SecureZeroMemory(payload, sizeof(payload));

	if (size != 0 && PeerSendRaw(a, from, env, size))
		PeerCount(a, PEER_COUNT_CHALLENGES);
}

// A bind challenge, at a node: taken only from one of its relays, at that relay's address, for the last bind the node
// sent. The node keeps the cookie for its binds to that relay and binds again at once with it, unless the bind that
// the challenge answers carried a cookie of the last challenge already: then the next renewal or retry binds again,
// so a relay that challenges every bind does not keep the node in a loop.
void PeerInputChallenge(PEER_AGENT *a, const PEER_ADDR *from, const UCHAR *data, UINT size) {
	UCHAR sender[PEER_KEY_SIZE];
	UCHAR payload[PEER_CHALLENGE_SIZE];
	UINT len = 0;
	UINT reason = PEER_OK;
	bool rebind = false;

	if (PeerOpen(a, data, size, sender, payload, sizeof(payload), &len) == false)
		reason = PEER_DROP_FORGED;
	else if (len != PEER_CHALLENGE_SIZE || payload[0] != PEER_VERSION)
		reason = PEER_DROP_MALFORMED;

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	UINT64 seq = PeerGetUint64(payload + 1);

	AcquireSRWLockExclusive(&a->Lock);
	{
		PEER_RELAY *r = NULL;

		for (UINT i = 0; i < a->NumRelays && r == NULL; i++)
			if (memcmp(a->Relays[i].Info.Key, sender, PEER_KEY_SIZE) == 0)
				r = &a->Relays[i];

		if (r == NULL || PeerAddrEqual(&r->Info.Addr, from) == false) {
			reason = PEER_DROP_RELAY;
		} else if (r->Binding == false || seq != r->BindSequence) {
			reason = PEER_DROP_REPLAY;
		} else {
			CopyMemory(r->Cookie, payload + PEER_BIND_SIZE, PEER_COOKIE_SIZE);
			r->HasCookie = true;
			rebind = (r->Answered == false);
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	SecureZeroMemory(payload, sizeof(payload));

	if (reason != PEER_OK) {
		PeerDrop(a, reason);
		return;
	}

	if (rebind)
		PeerBind(a, sender, true);
}
