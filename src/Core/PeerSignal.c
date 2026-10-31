// PeerSignal.c
// The static key of a node, and the envelopes of the peer layer: binds, bounds and signals, sealed by the sending
// node's static key to the receiving node's with the Noise one-way pattern K, Noise_K_25519_AESGCM_SHA256
// (the Noise Protocol Framework, revision 34, sections 5 and 7.4). The node keys are X25519 keys (ADR-0022),
// which sign nothing, so the authentication is the static-static DH of K, as the disco messages of Tailscale
// are sealed between node keys; only the receiver can open an envelope, and only the holder of the sender's
// private key can make one.
//
// An envelope is its kind (PEER_MSG_*), the sender's static public key, then the one message of K: the
// ephemeral public key, the ciphertext of the payload and the tag. The prologue is "ranz peer 1" and the kind,
// so an envelope of one kind never opens as another. The control package of the controller seals and opens the
// same envelopes with flynn/noise (controller/internal/control/envelope.go); coretest and its tests hold one
// known answer for both.

#include "Core/PeerInternal.h"

#include <string.h>

#define PEER_NOISE_PROTOCOL "Noise_K_25519_AESGCM_SHA256"
#define PEER_NOISE_PROLOGUE "ranz peer 1"
#define PEER_HASH_SIZE      CRYPTO_SHA256_SIZE

// The symmetric state of Noise (section 5.2) for the one message of K
typedef struct PEER_NOISE {
	UCHAR Ck[PEER_HASH_SIZE]; // The chaining key
	UCHAR H[PEER_HASH_SIZE];  // The handshake hash
	UCHAR K[PEER_HASH_SIZE];  // The cipher key, after the first MixKey
} PEER_NOISE;

// MixHash: h = SHA-256(h || data)
static bool PeerNoiseMixHash(PEER_NOISE *n, const void *data, UINT size) {
	CRYPTO_SHA256 s;

	if (CryptoSha256Begin(&s) == false)
		return false;

	bool ok = CryptoSha256Update(&s, n->H, PEER_HASH_SIZE) && CryptoSha256Update(&s, data, size);
	if (CryptoSha256End(&s, n->H) == false)
		ok = false;

	return ok;
}

// MixKey: ck, k = HKDF(ck, ikm) with two outputs (section 4.3): the temporary key HMAC(ck, ikm), then the first
// output HMAC(temp, 0x01) and the second HMAC(temp, output1 || 0x02). The key of AES-256-GCM is the whole second
// output, since HASHLEN is 32.
static bool PeerNoiseMixKey(PEER_NOISE *n, const UCHAR *ikm) {
	UCHAR temp[PEER_HASH_SIZE];
	UCHAR t[PEER_HASH_SIZE + 1];

	bool ok = CryptoHmacSha256(temp, n->Ck, PEER_HASH_SIZE, ikm, CRYPTO_X25519_SIZE);

	t[0] = 0x01;
	ok = ok && CryptoHmacSha256(n->Ck, temp, PEER_HASH_SIZE, t, 1);

	CopyMemory(t, n->Ck, PEER_HASH_SIZE);
	t[PEER_HASH_SIZE] = 0x02;
	ok = ok && CryptoHmacSha256(n->K, temp, PEER_HASH_SIZE, t, sizeof(t));

	SecureZeroMemory(temp, sizeof(temp));
	SecureZeroMemory(t, sizeof(t));

	return ok;
}

// Initialize the symmetric state of K: the protocol name, shorter than HASHLEN, zero-padded as h and ck; MixHash of
// the prologue; then the pre-messages, the initiator's static key and the responder's
static bool PeerNoiseInit(PEER_NOISE *n, UINT kind, const UCHAR *initiator, const UCHAR *responder) {
	UCHAR prologue[sizeof(PEER_NOISE_PROLOGUE)];

	ZeroMemory(n, sizeof(PEER_NOISE));
	CopyMemory(n->H, PEER_NOISE_PROTOCOL, sizeof(PEER_NOISE_PROTOCOL) - 1);
	CopyMemory(n->Ck, n->H, PEER_HASH_SIZE);

	CopyMemory(prologue, PEER_NOISE_PROLOGUE, sizeof(PEER_NOISE_PROLOGUE) - 1);
	prologue[sizeof(PEER_NOISE_PROLOGUE) - 1] = (UCHAR)kind;

	return PeerNoiseMixHash(n, prologue, sizeof(prologue)) && PeerNoiseMixHash(n, initiator, PEER_KEY_SIZE) && PeerNoiseMixHash(n, responder, PEER_KEY_SIZE);
}

// The Diffie-Hellman of a node's static key with the public key peer
static bool PeerKeyDh(PEER_KEY *k, UCHAR *shared, const UCHAR *peer) {
	if (k->Identity != NULL)
		return CryptoIdentityDh(k->Identity, shared, peer);

	return CryptoX25519(shared, k->Private, peer);
}

// Whether kind is the kind of an envelope
static bool PeerIsEnvelopeKind(UINT kind) {
	return kind == PEER_MSG_BIND || kind == PEER_MSG_BOUND || kind == PEER_MSG_SIGNAL || kind == PEER_MSG_PUNCH || kind == PEER_MSG_CHALLENGE;
}

// The static key of the X25519 scalar priv, held in memory
bool PeerKeyFromScalar(PEER_KEY *k, const UCHAR *priv) {
	if (k == NULL)
		return false;

	ZeroMemory(k, sizeof(PEER_KEY));
	if (priv == NULL)
		return false;

	CopyMemory(k->Private, priv, PEER_KEY_SIZE);
	if (CryptoX25519PublicKey(k->Public, k->Private) == false) {
		SecureZeroMemory(k, sizeof(PEER_KEY));
		return false;
	}

	return true;
}

// Whether the process holds the rights of a local administrator: an elevated administrator's process, or
// LocalSystem. The ranzvpnserver service does not: it runs as its virtual account (ADR-0039 decision 3), which may
// not create machine keys. The elevation of the token does not tell the two apart: a service token counts as
// elevated.
static bool PeerAdmin() {
	BYTE sid[SECURITY_MAX_SID_SIZE];
	DWORD size = sizeof(sid);
	BOOL member = FALSE;

	if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid, &size) == FALSE)
		return false;

	if (CheckTokenMembership(NULL, sid, &member) == FALSE)
		return false;

	return (member != FALSE);
}

// The key set of the identity keys: the machine key set when the process holds the rights of a local
// administrator, else the current user's, which for the service is the key set of its virtual account
static UINT PeerKeyScope() {
	return PeerAdmin() ? CRYPTO_MACHINE : 0;
}

// The node identity key name of the software key storage provider (ADR-0022): opened, or created when it does not
// exist yet. PeerKeyClose releases it.
bool PeerKeyOpen(PEER_KEY *k, const wchar_t *name) {
	if (k == NULL)
		return false;

	ZeroMemory(k, sizeof(PEER_KEY));
	if (name == NULL || name[0] == 0 || CryptoInit() == false)
		return false;

	CRYPTO_IDENTITY *id = (CRYPTO_IDENTITY *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CRYPTO_IDENTITY));
	if (id == NULL)
		return false;

	UINT scope = PeerKeyScope();
	if ((CryptoIdentityOpen(id, name, scope) || CryptoIdentityCreate(id, name, scope)) && CryptoIdentityPublicKey(id, k->Public)) {
		k->Identity = id;
		return true;
	}

	CryptoIdentityClose(id);
	HeapFree(GetProcessHeap(), 0, id);
	ZeroMemory(k, sizeof(PEER_KEY));

	return false;
}

// Release a static key: close its identity key, or wipe its scalar
void PeerKeyClose(PEER_KEY *k) {
	if (k == NULL)
		return;

	if (k->Identity != NULL) {
		CryptoIdentityClose(k->Identity);
		HeapFree(GetProcessHeap(), 0, k->Identity);
	}

	SecureZeroMemory(k, sizeof(PEER_KEY));
}

// Remove the identity key name from the key set that PeerKeyOpen uses; false when there is none
bool PeerKeyDelete(const wchar_t *name) {
	CRYPTO_IDENTITY id;

	if (name == NULL || CryptoInit() == false || CryptoIdentityOpen(&id, name, PeerKeyScope()) == false)
		return false;

	return CryptoIdentityDelete(&id);
}

// Seal payload into an envelope of kind (PEER_MSG_BIND, PEER_MSG_BOUND or PEER_MSG_SIGNAL) from key to the node
// whose static public key is peer. ephemeral NULL draws a new ephemeral key; a fixed scalar is for known-answer
// tests only. Returns the size of the envelope in buf, 0 when it does not fit size or a step failed.
UINT PeerEnvelopeSeal(PEER_KEY *key, const UCHAR *peer, UINT kind, const UCHAR *ephemeral, const void *payload, UINT payload_size, UCHAR *buf, UINT size) {
	PEER_NOISE n;
	CRYPTO_AEAD aead;
	UCHAR e_priv[CRYPTO_X25519_SIZE];
	UCHAR e_pub[CRYPTO_X25519_SIZE];
	UCHAR shared[CRYPTO_X25519_SIZE];
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE];
	bool ok;

	if (key == NULL || peer == NULL || buf == NULL || (payload == NULL && payload_size != 0) || PeerIsEnvelopeKind(kind) == false)
		return 0;
	if (payload_size > PEER_MAX_ENVELOPE || PEER_ENVELOPE_HEADER + payload_size + PEER_ENVELOPE_TAG > size)
		return 0;

	if (ephemeral != NULL) {
		CopyMemory(e_priv, ephemeral, sizeof(e_priv));
		ok = CryptoX25519PublicKey(e_pub, e_priv);
	} else {
		ok = CryptoX25519GenerateKey(e_priv, e_pub);
	}

	// -> e, es, ss
	ok = ok && PeerNoiseInit(&n, kind, key->Public, peer) && PeerNoiseMixHash(&n, e_pub, sizeof(e_pub));
	ok = ok && CryptoX25519(shared, e_priv, peer) && PeerNoiseMixKey(&n, shared);
	ok = ok && PeerKeyDh(key, shared, peer) && PeerNoiseMixKey(&n, shared);

	// EncryptAndHash of the payload: AES-GCM with n = 0 (four zero bytes, then 0 big-endian) and h as the AAD
	ZeroMemory(nonce, sizeof(nonce));
	if (ok && CryptoAeadInit(&aead, n.K, sizeof(n.K))) {
		ok = CryptoAeadSeal(&aead, nonce, n.H, sizeof(n.H), payload, payload_size, buf + PEER_ENVELOPE_HEADER, buf + PEER_ENVELOPE_HEADER + payload_size);
		CryptoAeadFree(&aead);
	} else {
		ok = false;
	}

	buf[0] = (UCHAR)kind;
	CopyMemory(buf + 1, key->Public, PEER_KEY_SIZE);
	CopyMemory(buf + 1 + PEER_KEY_SIZE, e_pub, sizeof(e_pub));

	SecureZeroMemory(&n, sizeof(n));
	SecureZeroMemory(e_priv, sizeof(e_priv));
	SecureZeroMemory(shared, sizeof(shared));

	if (ok == false) {
		SecureZeroMemory(buf, PEER_ENVELOPE_HEADER + payload_size + PEER_ENVELOPE_TAG);
		return 0;
	}

	return PEER_ENVELOPE_HEADER + payload_size + PEER_ENVELOPE_TAG;
}

// Open the envelope env of size bytes for key: the sender's static public key into sender, the payload into
// payload (at most payload_size bytes) and its size into payload_len. False for an envelope that is malformed,
// forged, altered in any byte, or sealed for another node.
bool PeerEnvelopeOpen(PEER_KEY *key, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len) {
	PEER_NOISE n;
	CRYPTO_AEAD aead;
	UCHAR shared[CRYPTO_X25519_SIZE];
	UCHAR nonce[CRYPTO_AES_GCM_NONCE_SIZE];

	if (payload_len != NULL)
		*payload_len = 0;
	if (key == NULL || env == NULL || sender == NULL || payload_len == NULL || (payload == NULL && payload_size != 0))
		return false;
	if (size < PEER_ENVELOPE_HEADER + PEER_ENVELOPE_TAG || PeerIsEnvelopeKind(env[0]) == false)
		return false;

	UINT len = size - PEER_ENVELOPE_HEADER - PEER_ENVELOPE_TAG;
	if (len > payload_size || len > PEER_MAX_ENVELOPE)
		return false;

	const UCHAR *s = env + 1;
	const UCHAR *e = env + 1 + PEER_KEY_SIZE;

	// <- e, es (DH of the own static key and e), ss (of the own static key and the sender's)
	bool ok = PeerNoiseInit(&n, env[0], s, key->Public) && PeerNoiseMixHash(&n, e, CRYPTO_X25519_SIZE);
	ok = ok && PeerKeyDh(key, shared, e) && PeerNoiseMixKey(&n, shared);
	ok = ok && PeerKeyDh(key, shared, s) && PeerNoiseMixKey(&n, shared);

	ZeroMemory(nonce, sizeof(nonce));
	if (ok && CryptoAeadInit(&aead, n.K, sizeof(n.K))) {
		ok = CryptoAeadOpen(&aead, nonce, n.H, sizeof(n.H), env + PEER_ENVELOPE_HEADER, len, env + PEER_ENVELOPE_HEADER + len, payload);
		CryptoAeadFree(&aead);
	} else {
		ok = false;
	}

	SecureZeroMemory(&n, sizeof(n));
	SecureZeroMemory(shared, sizeof(shared));

	if (ok == false)
		return false;

	CopyMemory(sender, s, PEER_KEY_SIZE);
	*payload_len = len;

	return true;
}

// Seal an envelope with the static key of the node a
UINT PeerSeal(PEER_AGENT *a, const UCHAR *peer, UINT kind, const void *payload, UINT payload_size, UCHAR *buf, UINT size) {
	AcquireSRWLockExclusive(&a->KeyLock);
	UINT ret = PeerEnvelopeSeal(&a->Key, peer, kind, NULL, payload, payload_size, buf, size);
	ReleaseSRWLockExclusive(&a->KeyLock);

	return ret;
}

// Open an envelope with the static key of the node a
bool PeerOpen(PEER_AGENT *a, const UCHAR *env, UINT size, UCHAR *sender, void *payload, UINT payload_size, UINT *payload_len) {
	AcquireSRWLockExclusive(&a->KeyLock);
	bool ret = PeerEnvelopeOpen(&a->Key, env, size, sender, payload, payload_size, payload_len);
	ReleaseSRWLockExclusive(&a->KeyLock);

	return ret;
}

// Write one address and port of a signal: 16 address bytes, then the port big-endian
static void PeerPutAddr(UCHAR *p, const PEER_ADDR *a) {
	CopyMemory(p, a->Ip, sizeof(a->Ip));
	PeerPutUint16(p + sizeof(a->Ip), a->Port);
}

static void PeerGetAddr(PEER_ADDR *a, const UCHAR *p) {
	CopyMemory(a->Ip, p, sizeof(a->Ip));
	a->Port = PeerGetUint16(p + sizeof(a->Ip));
}

// Whether str of len characters is an ICE username fragment or password of min to max characters: ALPHA, DIGIT,
// "+" and "/" (ice-char, RFC 8839 section 5.4)
static bool PeerIceString(const char *str, UINT len, UINT min, UINT max) {
	if (len < min || len > max)
		return false;

	for (UINT i = 0; i < len; i++) {
		char c = str[i];

		if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '+' && c != '/')
			return false;
	}

	return true;
}

// Whether type is the type of a punch offer or a punch answer, which ends with the NAT of its sender
static bool PeerSignalIsPunch(UINT type) {
	return type == PEER_SIGNAL_PUNCH_OFFER || type == PEER_SIGNAL_PUNCH_ANSWER;
}

// The payload of a signal: PEER_VERSION, the type, the sequence (big-endian), the relay key, the relay address
// and port, the number of candidates, then each candidate: its type, address and port; then, when s carries the
// credentials of an ICE session, the length and the characters of its username fragment and of its password; a punch
// offer or a punch answer, which carries no credentials, ends with the NAT of its sender (PEER_NAT_*, one byte).
// Returns its size, 0 when s is not a signal or it does not fit size.
UINT PeerSignalEncode(const PEER_SIGNAL *s, UCHAR *buf, UINT size) {
	UINT ufrag = 0;
	UINT pwd = 0;

	if (s == NULL || buf == NULL || s->Type < PEER_SIGNAL_OFFER || s->Type > PEER_SIGNAL_PUNCH_ANSWER || s->NumCandidates > PEER_MAX_CANDIDATES)
		return 0;

	bool punch = PeerSignalIsPunch(s->Type);
	if (punch && (s->IceUfrag[0] != 0 || s->Nat > PEER_NAT_RANDOM))
		return 0;

	if (s->IceUfrag[0] != 0) {
		ufrag = (UINT)strnlen(s->IceUfrag, sizeof(s->IceUfrag));
		pwd = (UINT)strnlen(s->IcePwd, sizeof(s->IcePwd));
		if (PeerIceString(s->IceUfrag, ufrag, 4, PEER_ICE_UFRAG_SIZE - 1) == false || PeerIceString(s->IcePwd, pwd, 22, PEER_ICE_PWD_SIZE - 1) == false)
			return 0;
	}

	UINT total = PEER_SIGNAL_FIXED + s->NumCandidates * PEER_CANDIDATE_LEN + (ufrag != 0 ? 2 + ufrag + pwd : 0) + (punch ? 1 : 0);
	if (total > size)
		return 0;

	buf[0] = PEER_VERSION;
	buf[1] = (UCHAR)s->Type;
	PeerPutUint64(buf + 2, s->Sequence);
	CopyMemory(buf + 10, s->RelayKey, PEER_KEY_SIZE);
	PeerPutAddr(buf + 42, &s->Relay);
	buf[60] = (UCHAR)s->NumCandidates;

	for (UINT i = 0; i < s->NumCandidates; i++) {
		UCHAR *p = buf + PEER_SIGNAL_FIXED + i * PEER_CANDIDATE_LEN;

		p[0] = (UCHAR)s->Candidates[i].Type;
		PeerPutAddr(p + 1, &s->Candidates[i].Addr);
	}

	if (ufrag != 0) {
		UCHAR *p = buf + PEER_SIGNAL_FIXED + s->NumCandidates * PEER_CANDIDATE_LEN;

		p[0] = (UCHAR)ufrag;
		CopyMemory(p + 1, s->IceUfrag, ufrag);
		p[1 + ufrag] = (UCHAR)pwd;
		CopyMemory(p + 2 + ufrag, s->IcePwd, pwd);
	}

	if (punch)
		buf[total - 1] = (UCHAR)s->Nat;

	return total;
}

// Decode the payload of a signal into s. False unless it is exactly one signal of this version, with a known type,
// no more than PEER_MAX_CANDIDATES candidates of known types, a port with its relay key, and, when it carries the
// credentials of an ICE session, a username fragment of 4 to 16 and a password of 22 to 32 ice-chars; a punch offer or
// a punch answer ends with a known NAT and carries no credentials. The sender is left zero: PeerOpenSignal sets it from
// the envelope.
bool PeerSignalDecode(const UCHAR *buf, UINT size, PEER_SIGNAL *s) {
	static const UCHAR zero[PEER_KEY_SIZE] = {0};

	if (s == NULL)
		return false;

	ZeroMemory(s, sizeof(PEER_SIGNAL));
	if (buf == NULL || size < PEER_SIGNAL_FIXED || buf[0] != PEER_VERSION || buf[1] < PEER_SIGNAL_OFFER || buf[1] > PEER_SIGNAL_PUNCH_ANSWER)
		return false;

	UINT num = buf[60];
	if (num > PEER_MAX_CANDIDATES || size < PEER_SIGNAL_FIXED + num * PEER_CANDIDATE_LEN)
		return false;

	// The NAT of the sender of a punch signal, its last byte
	if (PeerSignalIsPunch(buf[1])) {
		if (size != PEER_SIGNAL_FIXED + num * PEER_CANDIDATE_LEN + 1 || buf[size - 1] > PEER_NAT_RANDOM)
			return false;

		s->Nat = buf[size - 1];
		size--;
	}

	// The credentials of an ICE session after the candidates, or nothing
	const UCHAR *ice = buf + PEER_SIGNAL_FIXED + num * PEER_CANDIDATE_LEN;
	UINT rest = size - (PEER_SIGNAL_FIXED + num * PEER_CANDIDATE_LEN);
	if (rest != 0) {
		UINT ufrag = (rest >= 2 ? ice[0] : 0);
		UINT pwd = (rest >= 2 && ufrag + 2 <= rest ? ice[1 + ufrag] : 0);

		if (rest < 2 || ufrag + 2 > rest || rest != 2 + ufrag + pwd || PeerIceString((const char *)ice + 1, ufrag, 4, PEER_ICE_UFRAG_SIZE - 1) == false || PeerIceString((const char *)ice + 2 + ufrag, pwd, 22, PEER_ICE_PWD_SIZE - 1) == false)
			return false;

		CopyMemory(s->IceUfrag, ice + 1, ufrag);
		CopyMemory(s->IcePwd, ice + 2 + ufrag, pwd);
	}

	s->Type = buf[1];
	s->Sequence = PeerGetUint64(buf + 2);
	CopyMemory(s->RelayKey, buf + 10, PEER_KEY_SIZE);
	PeerGetAddr(&s->Relay, buf + 42);

	bool has_relay = (memcmp(s->RelayKey, zero, PEER_KEY_SIZE) != 0);
	if (has_relay && s->Relay.Port == 0) {
		ZeroMemory(s, sizeof(PEER_SIGNAL));
		return false;
	}

	for (UINT i = 0; i < num; i++) {
		const UCHAR *p = buf + PEER_SIGNAL_FIXED + i * PEER_CANDIDATE_LEN;

		if (p[0] < PEER_CANDIDATE_HOST || p[0] > PEER_CANDIDATE_TOWARD || PeerGetUint16(p + 17) == 0) {
			ZeroMemory(s, sizeof(PEER_SIGNAL));
			return false;
		}

		s->Candidates[i].Type = p[0];
		PeerGetAddr(&s->Candidates[i].Addr, p + 1);
	}
	s->NumCandidates = num;

	return true;
}
