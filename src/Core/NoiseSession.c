// NoiseSession.c
// The Noise session of the session module: the handshake records with the channel binding in the
// prologue, the records of the data and control streams, keepalive, rekey on a schedule and the
// dead-peer timeout; the Login of the first control record; and the tunnel of several
// connections to one peer node.
//
// A record is its type (one byte), then its body: the payload on a bound session, or on an
// encrypted session the Noise transport message of the payload under the sender's key, with the
// type byte as associated data. The type is in clear so that a record is read without a buffer
// for it; the associated data still binds it to its record.

#include "Core/Noise.h"

#include <string.h>

// What the handshake hash keys (HMAC-SHA256) for the values derived from it
static const char noise_challenge_label[] = "ranz login challenge";
static const char noise_tunnel_label[] = "ranz tunnel id";

UINT NoisePrologue(UCHAR *dst, UINT max, UINT binding_type, const UCHAR *binding, UINT binding_size) {
	UINT label = sizeof(NOISE_PROLOGUE_LABEL) - 1;

	switch (binding_type) {
	case NOISE_BINDING_NONE:
		if (binding_size != 0)
			return 0;
		break;
	case NOISE_BINDING_EXPORTER:
		if (binding_size != NOISE_EXPORTER_SIZE)
			return 0;
		break;
	case NOISE_BINDING_SERVER_END_POINT:
		// The hash of CryptoCertEndPoint: SHA-256, SHA-384 or SHA-512
		if (binding_size != 32 && binding_size != 48 && binding_size != 64)
			return 0;
		break;
	default:
		return 0;
	}

	if (dst == NULL || (binding == NULL && binding_size != 0) || label + 1 + binding_size > max)
		return 0;

	CopyMemory(dst, NOISE_PROLOGUE_LABEL, label);
	dst[label] = (UCHAR)binding_type;
	if (binding_size != 0)
		CopyMemory(dst + label + 1, binding, binding_size);

	return label + 1 + binding_size;
}

//
// The session
//

// The session is over: its keys go, the peer's identity and the handshake hash stay for the owner
static void NoiseSessionEnd(NOISE_SESSION *s) {
	NoiseHandshakeFree(&s->Handshake);
	NoiseCipherFree(&s->Send);
	NoiseCipherFree(&s->Recv);
	s->State = NOISE_STATE_CLOSED;
}

// Start a session from its configuration: the flags, the timers and the prologue. A session is
// either bound to its outer session or encrypted, never both and never neither.
static bool NoiseSessionStart(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UCHAR *prologue, UINT *prologue_size) {
	SecureZeroMemory(s, sizeof(NOISE_SESSION));
	s->State = NOISE_STATE_CLOSED;
	s->Handshake.Failed = true;

	if (cfg == NULL || ((cfg->Flags & NOISE_SESSION_ENCRYPT) != 0) != (cfg->BindingType == NOISE_BINDING_NONE))
		return false;

	*prologue_size = NoisePrologue(prologue, NOISE_MAX_PROLOGUE, cfg->BindingType, cfg->Binding, cfg->BindingSize);
	if (*prologue_size == 0)
		return false;

	s->Flags = cfg->Flags;
	s->KeepaliveInterval = cfg->KeepaliveInterval != 0 ? cfg->KeepaliveInterval : NOISE_KEEPALIVE_INTERVAL;
	s->DeadTimeout = cfg->DeadTimeout != 0 ? cfg->DeadTimeout : NOISE_DEAD_TIMEOUT;
	s->RekeyInterval = cfg->RekeyInterval != 0 ? cfg->RekeyInterval : NOISE_REKEY_INTERVAL;
	s->RekeyRecords = cfg->RekeyRecords != 0 ? cfg->RekeyRecords : NOISE_REKEY_RECORDS;

	return true;
}

// The handshake is complete: the transport keys of an encrypted session, the handshake hash and
// the peer's static key; the handshake itself is wiped
static bool NoiseSessionOpen(NOISE_SESSION *s, UINT64 now) {
	if ((s->Flags & NOISE_SESSION_ENCRYPT) != 0 && NoiseHandshakeSplit(&s->Handshake, &s->Send, &s->Recv) == false)
		return false;

	CopyMemory(s->HandshakeHash, s->Handshake.H, NOISE_KEY_SIZE);
	CopyMemory(s->RemoteStatic, s->Handshake.RemoteStatic, NOISE_KEY_SIZE);
	NoiseHandshakeFree(&s->Handshake);

	s->State = NOISE_STATE_OPEN;
	s->LastSent = now;
	s->LastReceived = now;
	s->LastRekey = now;
	s->SentUnderKey = 0;

	return true;
}

bool NoiseSessionConnect(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UINT64 now, UCHAR *record, UINT max, UINT *record_size) {
	UCHAR prologue[NOISE_MAX_PROLOGUE];
	UINT prologue_size = 0;
	UINT size = 0;

	if (record_size != NULL)
		*record_size = 0;
	if (s == NULL)
		return false;
	if (NoiseSessionStart(s, cfg, prologue, &prologue_size) == false || record == NULL || record_size == NULL || max < 2)
		return false;

	if (NoiseHandshakeInit(&s->Handshake, cfg->Suite, true, prologue, prologue_size, cfg->StaticKey, cfg->Identity, cfg->RemoteStatic) == false)
		return false;
	if (cfg->Ephemeral != NULL)
		NoiseHandshakeSetEphemeral(&s->Handshake, cfg->Ephemeral);

	record[0] = NOISE_RECORD_HANDSHAKE;
	record[1] = (UCHAR)cfg->Suite;
	if (NoiseHandshakeWrite(&s->Handshake, NULL, 0, record + 2, max - 2, &size) == false) {
		NoiseSessionEnd(s);
		return false;
	}

	s->Initiator = true;
	s->State = NOISE_STATE_HANDSHAKE;
	s->LastSent = now;
	s->LastReceived = now;
	*record_size = 2 + size;

	return true;
}

bool NoiseSessionAccept(NOISE_SESSION *s, const NOISE_SESSION_CONFIG *cfg, UINT64 now, const UCHAR *record, UINT record_size,
                        UCHAR *reply, UINT max, UINT *reply_size) {
	UCHAR prologue[NOISE_MAX_PROLOGUE];
	UINT prologue_size = 0;
	UINT payload_size = 0;
	UINT size = 0;

	if (reply_size != NULL)
		*reply_size = 0;
	if (s == NULL)
		return false;
	if (NoiseSessionStart(s, cfg, prologue, &prologue_size) == false || record == NULL || reply == NULL || reply_size == NULL || max < 2)
		return false;

	// The first record: the suite the initiator chose, which the responder runs if it can
	if (record_size < 2 || record[0] != NOISE_RECORD_HANDSHAKE || NoiseSuiteAvailable(record[1]) == false)
		return false;

	if (NoiseHandshakeInit(&s->Handshake, record[1], false, prologue, prologue_size, cfg->StaticKey, cfg->Identity, NULL) == false)
		return false;
	if (cfg->Ephemeral != NULL)
		NoiseHandshakeSetEphemeral(&s->Handshake, cfg->Ephemeral);

	// The handshake payloads are empty: the Login follows in the first control record, under the
	// forward secrecy of the complete handshake
	reply[0] = NOISE_RECORD_HANDSHAKE;
	reply[1] = record[1];
	if (NoiseHandshakeRead(&s->Handshake, record + 2, record_size - 2, NULL, 0, &payload_size) == false ||
	    NoiseHandshakeWrite(&s->Handshake, NULL, 0, reply + 2, max - 2, &size) == false || NoiseSessionOpen(s, now) == false) {
		NoiseSessionEnd(s);
		return false;
	}

	*reply_size = 2 + size;
	return true;
}

bool NoiseSessionFinish(NOISE_SESSION *s, UINT64 now, const UCHAR *record, UINT record_size) {
	UINT payload_size = 0;

	if (s == NULL || s->State != NOISE_STATE_HANDSHAKE || s->Initiator == false)
		return false;

	if (record == NULL || record_size < 2 || record[0] != NOISE_RECORD_HANDSHAKE || record[1] != s->Handshake.Suite ||
	    NoiseHandshakeRead(&s->Handshake, record + 2, record_size - 2, NULL, 0, &payload_size) == false || NoiseSessionOpen(s, now) == false) {
		NoiseSessionEnd(s);
		return false;
	}

	return true;
}

// Whether this side takes its next key now: after the rekey interval, or on an encrypted session
// with the last record that one key may protect
static bool NoiseSessionRekeyDue(const NOISE_SESSION *s, UINT64 now) {
	if (now >= s->LastRekey + s->RekeyInterval)
		return true;

	return (s->Flags & NOISE_SESSION_ENCRYPT) != 0 && s->SentUnderKey + 1 >= s->RekeyRecords;
}

// Write one record. On an encrypted session the record that is due to rekey carries
// NOISE_RECORD_REKEYED, and the sender takes its next key after it.
static bool NoiseSessionWriteRecord(NOISE_SESSION *s, UINT64 now, UINT type, const void *data, UINT size, UCHAR *record, UINT max, UINT *record_size) {
	if ((s->Flags & NOISE_SESSION_ENCRYPT) == 0) {
		if (1 + size > max)
			return false;

		if (size != 0)
			MoveMemory(record + 1, data, size);
		record[0] = (UCHAR)type;
		*record_size = 1 + size;
	} else {
		if (1 + size + NOISE_TAG_SIZE > max)
			return false;

		bool rekey = NoiseSessionRekeyDue(s, now);

		if (size != 0)
			MoveMemory(record + 1, data, size);
		record[0] = (UCHAR)(type | (rekey ? NOISE_RECORD_REKEYED : 0));
		if (NoiseCipherEncrypt(&s->Send, record, 1, record + 1, size, record + 1) == false) {
			SecureZeroMemory(record, max);
			NoiseSessionEnd(s);
			return false;
		}
		*record_size = 1 + size + NOISE_TAG_SIZE;
		s->SentUnderKey++;

		if (rekey) {
			if (NoiseCipherRekey(&s->Send) == false) {
				SecureZeroMemory(record, max);
				*record_size = 0;
				NoiseSessionEnd(s);
				return false;
			}
			s->LastRekey = now;
			s->SentUnderKey = 0;
			s->NumRekeys++;
		}
	}

	s->LastSent = now;
	return true;
}

bool NoiseSessionSend(NOISE_SESSION *s, UINT64 now, UINT type, const void *data, UINT size, UCHAR *record, UINT max, UINT *record_size) {
	if (record_size != NULL)
		*record_size = 0;
	if (s == NULL || s->State != NOISE_STATE_OPEN || record == NULL || record_size == NULL || (data == NULL && size != 0) || size > NOISE_MAX_PAYLOAD)
		return false;
	// Keepalives come from NoiseSessionPoll; a close has no payload
	if ((type != NOISE_RECORD_DATA && type != NOISE_RECORD_CONTROL && type != NOISE_RECORD_CLOSE) || (type == NOISE_RECORD_CLOSE && size != 0))
		return false;

	if (NoiseSessionWriteRecord(s, now, type, data, size, record, max, record_size) == false)
		return false;

	if (type == NOISE_RECORD_CLOSE)
		NoiseSessionEnd(s);

	return true;
}

UINT NoiseSessionReceive(NOISE_SESSION *s, UINT64 now, const UCHAR *record, UINT record_size, void *data, UINT max, UINT *data_size) {
	UINT ret = NOISE_RECEIVE_ERROR;
	UINT size = 0;

	if (data_size != NULL)
		*data_size = 0;
	if (s == NULL || s->State != NOISE_STATE_OPEN || data_size == NULL || (data == NULL && max != 0))
		return NOISE_RECEIVE_ERROR;
	if (record == NULL || record_size < 1 || record_size > NOISE_MAX_RECORD)
		goto FAIL;

	UINT type = record[0] & NOISE_RECORD_TYPE_MASK;
	bool rekeyed = (record[0] & NOISE_RECORD_REKEYED) != 0;

	// The payload: in clear on a bound session, decrypted on an encrypted one, where the record must
	// also be the next one under the peer's key
	if ((s->Flags & NOISE_SESSION_ENCRYPT) == 0) {
		size = record_size - 1;
		if (rekeyed || size > max)
			goto FAIL;
		if (size != 0)
			CopyMemory(data, record + 1, size);
	} else {
		if (record_size < 1 + NOISE_TAG_SIZE)
			goto FAIL;
		size = record_size - 1 - NOISE_TAG_SIZE;
		if (size > max || NoiseCipherDecrypt(&s->Recv, record, 1, record + 1, record_size - 1, size != 0 ? data : NULL) == false)
			goto FAIL;
	}

	switch (type) {
	case NOISE_RECORD_DATA:
		// No data before the Login is accepted
		if (s->Initiator == false && s->LoggedIn == false)
			goto FAIL;
		ret = NOISE_RECEIVE_DATA;
		break;
	case NOISE_RECORD_CONTROL:
		ret = NOISE_RECEIVE_CONTROL;
		break;
	case NOISE_RECORD_KEEPALIVE:
		if (size != 0)
			goto FAIL;
		ret = NOISE_RECEIVE_NONE;
		break;
	case NOISE_RECORD_CLOSE:
		if (size != 0)
			goto FAIL;
		ret = NOISE_RECEIVE_CLOSE;
		break;
	default:
		goto FAIL;
	}

	if (rekeyed) {
		if (NoiseCipherRekey(&s->Recv) == false)
			goto FAIL;
		s->NumPeerRekeys++;
	}

	s->LastReceived = now;
	if (ret == NOISE_RECEIVE_CLOSE)
		NoiseSessionEnd(s);

	*data_size = size;
	return ret;

FAIL:
	if (data != NULL && max != 0)
		SecureZeroMemory(data, max);
	NoiseSessionEnd(s);

	return NOISE_RECEIVE_ERROR;
}

UINT NoiseSessionPoll(NOISE_SESSION *s, UINT64 now, UCHAR *record, UINT max, UINT *record_size) {
	if (record_size != NULL)
		*record_size = 0;
	if (s == NULL || (s->State != NOISE_STATE_OPEN && s->State != NOISE_STATE_HANDSHAKE))
		return NOISE_POLL_IDLE;

	// The initiator's handshake times out the same way
	if (now >= s->LastReceived + s->DeadTimeout) {
		NoiseSessionEnd(s);
		return NOISE_POLL_DEAD;
	}
	if (s->State != NOISE_STATE_OPEN)
		return NOISE_POLL_IDLE;

	// A bound session: the outer session holds the keys, and its owner updates them
	if ((s->Flags & NOISE_SESSION_ENCRYPT) == 0 && NoiseSessionRekeyDue(s, now)) {
		s->LastRekey = now;
		s->NumRekeys++;
		return NOISE_POLL_REKEY;
	}

	// A keepalive when this side has been quiet, or the rekey of an encrypted session that is due
	// while it sends nothing
	if (now >= s->LastSent + s->KeepaliveInterval || ((s->Flags & NOISE_SESSION_ENCRYPT) != 0 && NoiseSessionRekeyDue(s, now))) {
		if (record == NULL || record_size == NULL || NoiseSessionWriteRecord(s, now, NOISE_RECORD_KEEPALIVE, NULL, 0, record, max, record_size) == false)
			return NOISE_POLL_IDLE;
		return NOISE_POLL_SEND;
	}

	return NOISE_POLL_IDLE;
}

void NoiseSessionAcceptLogin(NOISE_SESSION *s) {
	if (s != NULL && s->State == NOISE_STATE_OPEN)
		s->LoggedIn = true;
}

// HMAC-SHA256 of label under the handshake hash, cut to size bytes
static bool NoiseSessionDerive(const NOISE_SESSION *s, const char *label, UCHAR *dst, UINT size) {
	UCHAR mac[CRYPTO_SHA256_SIZE];

	if (dst == NULL)
		return false;
	if (s == NULL || s->State != NOISE_STATE_OPEN || size == 0 || size > sizeof(mac) ||
	    CryptoHmacSha256(mac, s->HandshakeHash, NOISE_KEY_SIZE, label, (UINT)strlen(label)) == false) {
		if (size != 0 && size <= sizeof(mac))
			SecureZeroMemory(dst, size);
		return false;
	}

	CopyMemory(dst, mac, size);
	SecureZeroMemory(mac, sizeof(mac));

	return true;
}

bool NoiseSessionChallenge(const NOISE_SESSION *s, UCHAR *challenge, UINT size) {
	return NoiseSessionDerive(s, noise_challenge_label, challenge, size);
}

void NoiseSessionFree(NOISE_SESSION *s) {
	if (s == NULL)
		return;

	NoiseSessionEnd(s);
	SecureZeroMemory(s, sizeof(NOISE_SESSION));
	s->Handshake.Failed = true;
}

//
// The Login
//

// The size of a string field of the Login, at most limit bytes, or limit + 1 when it is longer
static UINT NoiseLoginStrSize(const char *s, UINT limit) {
	UINT n = 0;

	while (n <= limit && s[n] != 0)
		n++;

	return n;
}

bool NoiseLoginEncode(const NOISE_LOGIN *l, UCHAR *buf, UINT max, UINT *size) {
	const UCHAR *secret = NULL;
	UINT secret_size = 0;
	UINT sign_size = 0;

	if (size != NULL)
		*size = 0;
	if (l == NULL || buf == NULL || size == NULL)
		return false;

	UINT hub = NoiseLoginStrSize(l->HubName, NOISE_LOGIN_MAX_NAME);
	UINT user = NoiseLoginStrSize(l->UserName, NOISE_LOGIN_MAX_NAME);
	if (hub == 0 || hub > NOISE_LOGIN_MAX_NAME || user == 0 || user > NOISE_LOGIN_MAX_NAME)
		return false;

	switch (l->Method) {
	case NOISE_LOGIN_ANONYMOUS:
		break;
	case NOISE_LOGIN_PASSWORD:
		secret = (const UCHAR *)l->Password;
		secret_size = NoiseLoginStrSize(l->Password, NOISE_LOGIN_MAX_PASSWORD);
		if (secret_size > NOISE_LOGIN_MAX_PASSWORD)
			return false;
		break;
	case NOISE_LOGIN_CERT:
		secret = l->Cert;
		secret_size = l->CertSize;
		sign_size = l->SignSize;
		if (secret == NULL || secret_size == 0 || secret_size > NOISE_LOGIN_MAX_CERT || l->Sign == NULL || sign_size == 0 || sign_size > NOISE_LOGIN_MAX_SIGN)
			return false;
		break;
	case NOISE_LOGIN_JOIN:
		secret = l->TunnelId;
		secret_size = NOISE_TUNNEL_ID_SIZE;
		break;
	default:
		return false;
	}

	UINT total = 2 + 1 + hub + 1 + user + 2 + secret_size + 2 + sign_size;
	if (total > max)
		return false;

	UCHAR *p = buf;
	*p++ = NOISE_LOGIN_VERSION;
	*p++ = (UCHAR)l->Method;
	*p++ = (UCHAR)hub;
	CopyMemory(p, l->HubName, hub);
	p += hub;
	*p++ = (UCHAR)user;
	CopyMemory(p, l->UserName, user);
	p += user;
	*p++ = (UCHAR)(secret_size >> 8);
	*p++ = (UCHAR)secret_size;
	if (secret_size != 0)
		CopyMemory(p, secret, secret_size);
	p += secret_size;
	*p++ = (UCHAR)(sign_size >> 8);
	*p++ = (UCHAR)sign_size;
	if (sign_size != 0)
		CopyMemory(p, l->Sign, sign_size);

	*size = total;
	return true;
}

// One string field of the Login: size bytes at most limit, none of them zero, then a terminator
static bool NoiseLoginReadStr(char *dst, const UCHAR *src, UINT size, UINT limit) {
	if (size > limit || memchr(src, 0, size) != NULL)
		return false;

	CopyMemory(dst, src, size);
	dst[size] = 0;

	return true;
}

bool NoiseLoginParse(NOISE_LOGIN *l, const UCHAR *buf, UINT size) {
	UINT pos = 0;

	if (l == NULL)
		return false;

	SecureZeroMemory(l, sizeof(NOISE_LOGIN));
	if (buf == NULL || size < 2 || buf[0] != NOISE_LOGIN_VERSION || buf[1] > NOISE_LOGIN_JOIN)
		return false;
	l->Method = buf[1];
	pos = 2;

	// The hub name and the user name
	for (UINT i = 0; i < 2; i++) {
		char *dst = i == 0 ? l->HubName : l->UserName;
		if (pos >= size)
			goto FAIL;
		UINT n = buf[pos++];
		if (n == 0 || n > size - pos || NoiseLoginReadStr(dst, buf + pos, n, NOISE_LOGIN_MAX_NAME) == false)
			goto FAIL;
		pos += n;
	}

	// The secret and the signature, with the sizes their method allows
	if (size - pos < 2)
		goto FAIL;
	UINT secret_size = ((UINT)buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (secret_size > size - pos)
		goto FAIL;
	const UCHAR *secret = buf + pos;
	pos += secret_size;

	if (size - pos < 2)
		goto FAIL;
	UINT sign_size = ((UINT)buf[pos] << 8) | buf[pos + 1];
	pos += 2;
	if (sign_size != size - pos)
		goto FAIL;
	const UCHAR *sign = buf + pos;

	switch (l->Method) {
	case NOISE_LOGIN_ANONYMOUS:
		if (secret_size != 0 || sign_size != 0)
			goto FAIL;
		break;
	case NOISE_LOGIN_PASSWORD:
		if (sign_size != 0 || NoiseLoginReadStr(l->Password, secret, secret_size, NOISE_LOGIN_MAX_PASSWORD) == false)
			goto FAIL;
		break;
	case NOISE_LOGIN_CERT:
		if (secret_size == 0 || secret_size > NOISE_LOGIN_MAX_CERT || sign_size == 0 || sign_size > NOISE_LOGIN_MAX_SIGN)
			goto FAIL;
		l->Cert = secret;
		l->CertSize = secret_size;
		l->Sign = sign;
		l->SignSize = sign_size;
		break;
	case NOISE_LOGIN_JOIN:
		if (secret_size != NOISE_TUNNEL_ID_SIZE || sign_size != 0)
			goto FAIL;
		CopyMemory(l->TunnelId, secret, NOISE_TUNNEL_ID_SIZE);
		break;
	}

	return true;

FAIL:
	SecureZeroMemory(l, sizeof(NOISE_LOGIN));
	return false;
}

//
// The tunnel
//

bool NoiseTunnelId(const NOISE_SESSION *s, UCHAR *id) {
	return NoiseSessionDerive(s, noise_tunnel_label, id, NOISE_TUNNEL_ID_SIZE);
}

// A connection that carries flows: present and open
static bool NoiseTunnelAlive(const NOISE_TUNNEL *t, UINT i) {
	return t->Connections[i] != NULL && t->Connections[i]->State == NOISE_STATE_OPEN;
}

bool NoiseTunnelInit(NOISE_TUNNEL *t, NOISE_SESSION *first, UINT num) {
	if (t == NULL)
		return false;

	ZeroMemory(t, sizeof(NOISE_TUNNEL));
	if (first == NULL || first->State != NOISE_STATE_OPEN || num == 0 || num > NOISE_TUNNEL_MAX_CONNECTIONS || NoiseTunnelId(first, t->Id) == false)
		return false;

	CopyMemory(t->RemoteStatic, first->RemoteStatic, NOISE_KEY_SIZE);
	t->NumConnections = num;
	t->Connections[0] = first;

	return true;
}

bool NoiseTunnelJoin(NOISE_TUNNEL *t, UINT index, NOISE_SESSION *s) {
	if (t == NULL || s == NULL || index >= t->NumConnections || t->Connections[index] != NULL || s->State != NOISE_STATE_OPEN)
		return false;

	// Only a connection to the same peer node, and only once
	if (memcmp(s->RemoteStatic, t->RemoteStatic, NOISE_KEY_SIZE) != 0)
		return false;
	for (UINT i = 0; i < t->NumConnections; i++)
		if (t->Connections[i] == s)
			return false;

	t->Connections[index] = s;
	return true;
}

void NoiseTunnelLose(NOISE_TUNNEL *t, UINT index) {
	if (t != NULL && index < t->NumConnections)
		t->Connections[index] = NULL;
}

UINT NoiseTunnelNumAlive(const NOISE_TUNNEL *t) {
	UINT num = 0;

	if (t == NULL)
		return 0;

	for (UINT i = 0; i < t->NumConnections; i++)
		if (NoiseTunnelAlive(t, i))
			num++;

	return num;
}

// A flow goes over its home connection, flow_hash mod N. While that one is lost, the flow goes
// over one of the others, chosen by the rest of the hash, so the flows of a lost connection
// spread over the ones left and no other flow moves.
NOISE_SESSION *NoiseTunnelRoute(const NOISE_TUNNEL *t, UINT flow_hash) {
	UINT alive = NoiseTunnelNumAlive(t);

	if (alive == 0)
		return NULL;

	UINT home = flow_hash % t->NumConnections;
	if (NoiseTunnelAlive(t, home))
		return t->Connections[home];

	UINT k = (flow_hash / t->NumConnections) % alive;
	for (UINT i = 0; i < t->NumConnections; i++) {
		if (NoiseTunnelAlive(t, i) == false)
			continue;
		if (k == 0)
			return t->Connections[i];
		k--;
	}

	return NULL;
}
