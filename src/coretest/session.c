// session.c
// Tests of the Noise session and the tunnel of the session module (src/Core/Noise.h; CORE-F2,
// #62): a fixed golden transcript of a bound and of an encrypted session, the channel binding
// (TLS exporter and tls-server-end-point), the Login and its gate, keepalive and the dead-peer
// timeout, rekey on a schedule, and the tunnel's flows over N = 1 and N = 4 connections with a
// lost connection. Time is a simulated clock, so the timers run in milliseconds of test time.

#include "coretest.h"

#include "Core/Noise.h"

#include <string.h>

// The keys of the cacophony IK vector (noise.c), as client node and server node
static const char ses_client_static[] = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
static const char ses_client_ephemeral[] = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
static const char ses_client_public[] = "6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a";
static const char ses_server_static[] = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
static const char ses_server_ephemeral[] = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
static const char ses_server_public[] = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";

// The golden transcript of one session, from the reference model: the two handshake records, the
// handshake hash, the challenge and the tunnel id it gives, the Login of the user alice to the hub
// HUB with the password "secret", then the records of the scenario of ses_golden()
typedef struct SES_GOLDEN {
	const char *Handshake1;
	const char *Handshake2;
	const char *Hash;
	const char *Challenge;
	const char *TunnelId;
	const char *Login;
	const char *Reply;
	const char *Data;
	const char *Keepalive;
	const char *Rekey1;
	const char *Rekey2;
	const char *Close;
} SES_GOLDEN;

static const char ses_login[] = "01010348554205616c69636500067365637265740000";

// Bound to the TLS exporter 00 01 .. 1f: the records in clear
static const SES_GOLDEN ses_golden_bound = {
    "0001ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddb50901f6c0fe1e7ad5e23084c93002377d265fcde584d2a7bee488866fe3d6a96",
    "000195ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435e02bac3ee97e3ac27fdd5f32aad4e05",
    "a709437a24035a5468cef619d28c6f7f7c27e93c6c23ada1d26c329c5a95f355",
    "43a69ef95b8676d9c5f409e54b30c28dc104636d",
    "6e9a0c6db4c4ea0c70e51bd37c4e295d",
    "0201010348554205616c69636500067365637265740000",
    "026c6f67696e206f6b",
    "01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b",
    "03",
    "0172656b65792031",
    "0172656b65792032",
    "04",
};

// Encrypted (no binding, the CDN path), four records under one key: the fourth record of the client
// carries the rekey flag (0x81), the fifth is under its next key
static const SES_GOLDEN ses_golden_encrypted = {
    "0001ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444e417bc55c7a8166c993356c1be41ef67818a292426f301556c7f26b21d25ddbab78f691bedb2016cad0d55ed4bc463368c1ed3ba8c9906fedeb321c1431d854",
    "000195ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843369f326da14e1d270d0629a34a4a68e5",
    "ae43a4eb560b2f4e489d10dd186be8c218ea5636a0e81ae1905aab5eec076286",
    "50d64e0b5278e6ac3c206909ce91468611685a06",
    "03ac5c8f92f53f0445efe4c4e8231b93",
    "022183df9b987b30e1738c9674856828c0538701253acadf7ad43a1e13c85906b77531983c9a40",
    "025ef68fa31d5767e281cf8ade222e41ef1d8a1c94078c708f",
    "010df1c02f1c17afc87c5812abff8ebfa905eeb568befbed9f5459d37710a31dacd0ab6e18b17f6a80c0461d63b8f1bc4d306340776a6b80186c7d0decd694ee2765af5683a494d6387cdc6c84",
    "037910fa9329022aa1d6d5c94aba0eadf8",
    "81862aea81d5cff4afc5fdc3684e80756a8700f0a2852641",
    "01e9cb26864bae94ffc40a1aa46694bff1c6508fbdb27285",
    "04795896313c9804601a8fb9cf8654be0d",
};

#define SES_BUF 4096

// The two ends of a session under test and their buffers
typedef struct SES_PAIR {
	NOISE_SESSION_CONFIG ClientConfig;
	NOISE_SESSION_CONFIG ServerConfig;
	NOISE_SESSION Client;
	NOISE_SESSION Server;
	UCHAR ClientKey[NOISE_KEY_SIZE];
	UCHAR ServerKey[NOISE_KEY_SIZE];
	UCHAR ServerPub[NOISE_KEY_SIZE];
	UCHAR ClientEphemeral[NOISE_KEY_SIZE];
	UCHAR ServerEphemeral[NOISE_KEY_SIZE];
	UCHAR Binding[NOISE_MAX_BINDING];
	UCHAR Record[SES_BUF];
	UCHAR Reply[SES_BUF];
	UCHAR Data[SES_BUF];
} SES_PAIR;

static SES_PAIR *ses_new() {
	return (SES_PAIR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SES_PAIR));
}

static void ses_free(SES_PAIR *p) {
	if (p == NULL)
		return;

	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);
	SecureZeroMemory(p, sizeof(SES_PAIR));
	HeapFree(GetProcessHeap(), 0, p);
}

// The configurations of a pair with the golden keys: bound to the exporter 00 .. 1f, or encrypted
static void ses_configure(SES_PAIR *p, bool encrypt, bool fixed_ephemeral) {
	coretest_unhex(p->ClientKey, NOISE_KEY_SIZE, ses_client_static);
	coretest_unhex(p->ServerKey, NOISE_KEY_SIZE, ses_server_static);
	coretest_unhex(p->ServerPub, NOISE_KEY_SIZE, ses_server_public);
	coretest_unhex(p->ClientEphemeral, NOISE_KEY_SIZE, ses_client_ephemeral);
	coretest_unhex(p->ServerEphemeral, NOISE_KEY_SIZE, ses_server_ephemeral);
	for (UINT i = 0; i < NOISE_EXPORTER_SIZE; i++)
		p->Binding[i] = (UCHAR)i;

	NOISE_SESSION_CONFIG *c = &p->ClientConfig;
	ZeroMemory(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->Flags = encrypt ? NOISE_SESSION_ENCRYPT : 0;
	c->StaticKey = p->ClientKey;
	c->RemoteStatic = p->ServerPub;
	c->BindingType = encrypt ? NOISE_BINDING_NONE : NOISE_BINDING_EXPORTER;
	c->Binding = encrypt ? NULL : p->Binding;
	c->BindingSize = encrypt ? 0 : NOISE_EXPORTER_SIZE;
	c->Ephemeral = fixed_ephemeral ? p->ClientEphemeral : NULL;

	p->ServerConfig = *c;
	p->ServerConfig.StaticKey = p->ServerKey;
	p->ServerConfig.RemoteStatic = NULL;
	p->ServerConfig.Ephemeral = fixed_ephemeral ? p->ServerEphemeral : NULL;
}

// The handshake of a pair at now: the client connects, the server accepts, the client finishes
static bool ses_handshake(SES_PAIR *p, UINT64 now) {
	UINT size = 0, reply_size = 0;

	return NoiseSessionConnect(&p->Client, &p->ClientConfig, now, p->Record, SES_BUF, &size) &&
	       NoiseSessionAccept(&p->Server, &p->ServerConfig, now, p->Record, size, p->Reply, SES_BUF, &reply_size) &&
	       NoiseSessionFinish(&p->Client, now, p->Reply, reply_size);
}

// One record from one end to the other: what the receiver found, with its payload in p->Data
static UINT ses_send(SES_PAIR *p, NOISE_SESSION *from, NOISE_SESSION *to, UINT64 now, UINT type, const void *data, UINT size, UINT *data_size) {
	UINT record_size = 0;

	*data_size = 0;
	if (NoiseSessionSend(from, now, type, data, size, p->Record, SES_BUF, &record_size) == false)
		return NOISE_RECEIVE_ERROR;

	return NoiseSessionReceive(to, now, p->Record, record_size, p->Data, SES_BUF, data_size);
}

// What the polls of one end at now did: the records sent, the outer rekeys asked for, death
typedef struct SES_POLL {
	UINT Sent;
	UINT Rekeys;
	bool Dead;
	bool Error; // A sent record that the other end refused
} SES_POLL;

// Poll from until it is idle; its records reach to when deliver is set, else they are lost
static void ses_poll(SES_PAIR *p, NOISE_SESSION *from, NOISE_SESSION *to, UINT64 now, bool deliver, SES_POLL *r) {
	UINT record_size = 0, data_size = 0;

	for (UINT i = 0; i < 16; i++) {
		UINT ret = NoiseSessionPoll(from, now, p->Record, SES_BUF, &record_size);
		if (ret == NOISE_POLL_IDLE)
			return;
		if (ret == NOISE_POLL_DEAD) {
			r->Dead = true;
			return;
		}
		if (ret == NOISE_POLL_REKEY) {
			r->Rekeys++;
			continue;
		}
		r->Sent++;
		if (deliver && NoiseSessionReceive(to, now, p->Record, record_size, p->Data, SES_BUF, &data_size) != NOISE_RECEIVE_NONE)
			r->Error = true;
	}
}

// The scenario of the goldens on a pair with the golden keys and ephemerals
static void ses_golden(bool encrypt) {
	const SES_GOLDEN *g = encrypt ? &ses_golden_encrypted : &ses_golden_bound;
	SES_PAIR *p = ses_new();
	UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE], challenge2[NOISE_LOGIN_CHALLENGE_SIZE], id[NOISE_TUNNEL_ID_SIZE];
	UCHAR frame[60];
	UCHAR login[64];
	NOISE_LOGIN l;
	UINT size = 0, reply_size = 0, data_size = 0, login_size = 0;
	UINT64 now = 1000;

	printf("  %s session (%s):\n", encrypt ? "encrypted" : "bound", encrypt ? "records under the Noise keys, rekey after 4" : "TLS exporter 00 01 .. 1f, records in clear");
	if (coretest_check(p != NULL, "allocated") == false)
		return;
	ses_configure(p, encrypt, true);
	p->ClientConfig.RekeyRecords = 4;
	p->ServerConfig.RekeyRecords = 4;

	coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, now, p->Record, SES_BUF, &size) && p->Client.State == NOISE_STATE_HANDSHAKE, "the client connects");
	coretest_check_hex(p->Record, size, g->Handshake1, "handshake record 1 is the golden one");
	coretest_check(NoiseSessionAccept(&p->Server, &p->ServerConfig, now, p->Record, size, p->Reply, SES_BUF, &reply_size) && p->Server.State == NOISE_STATE_OPEN, "the server accepts");
	coretest_check_hex(p->Reply, reply_size, g->Handshake2, "handshake record 2 is the golden one");
	coretest_check(NoiseSessionFinish(&p->Client, now, p->Reply, reply_size) && p->Client.State == NOISE_STATE_OPEN, "the client finishes");
	coretest_check_hex(p->Client.HandshakeHash, NOISE_KEY_SIZE, g->Hash, "the handshake hash is the golden one");
	coretest_check(memcmp(p->Client.HandshakeHash, p->Server.HandshakeHash, NOISE_KEY_SIZE) == 0, "both ends hold the same handshake hash");
	coretest_check_hex(p->Server.RemoteStatic, NOISE_KEY_SIZE, ses_client_public, "the server learnt the client node's static key");
	coretest_check_hex(p->Client.RemoteStatic, NOISE_KEY_SIZE, ses_server_public, "the client holds the server node's static key");
	coretest_check(p->Client.Handshake.Messages == 0 && p->Server.Handshake.Ck[0] == 0, "the handshake is wiped once the session is open");

	coretest_check(NoiseSessionChallenge(&p->Client, challenge, sizeof(challenge)) && NoiseSessionChallenge(&p->Server, challenge2, sizeof(challenge2)) &&
	                   memcmp(challenge, challenge2, sizeof(challenge)) == 0,
	               "both ends derive the same challenge");
	coretest_check_hex(challenge, sizeof(challenge), g->Challenge, "the challenge is the golden one");
	coretest_check(NoiseTunnelId(&p->Server, id), "the tunnel id");
	coretest_check_hex(id, sizeof(id), g->TunnelId, "the tunnel id is the golden one");

	// The Login is the first control record
	ZeroMemory(&l, sizeof(l));
	l.Method = NOISE_LOGIN_PASSWORD;
	strcpy_s(l.HubName, sizeof(l.HubName), "HUB");
	strcpy_s(l.UserName, sizeof(l.UserName), "alice");
	strcpy_s(l.Password, sizeof(l.Password), "secret");
	coretest_check(NoiseLoginEncode(&l, login, sizeof(login), &login_size), "the Login encoded");
	coretest_check_hex(login, login_size, ses_login, "the Login is the golden one");
	UINT record_size = 0;
	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_CONTROL, login, login_size, p->Record, SES_BUF, &record_size), "the client sends the Login");
	coretest_check_hex(p->Record, record_size, g->Login, "the Login record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_CONTROL && data_size == login_size &&
	                   NoiseLoginParse(&l, p->Data, data_size) && l.Method == NOISE_LOGIN_PASSWORD && strcmp(l.HubName, "HUB") == 0 && strcmp(l.UserName, "alice") == 0 &&
	                   strcmp(l.Password, "secret") == 0,
	               "the server reads the Login");
	NoiseSessionAcceptLogin(&p->Server);

	coretest_check(NoiseSessionSend(&p->Server, now, NOISE_RECORD_CONTROL, "login ok", 8, p->Record, SES_BUF, &record_size), "the server answers on the control stream");
	coretest_check_hex(p->Record, record_size, g->Reply, "the answer record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Client, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_CONTROL && data_size == 8 &&
	                   memcmp(p->Data, "login ok", 8) == 0,
	               "the client reads it");

	for (UINT i = 0; i < sizeof(frame); i++)
		frame[i] = (UCHAR)i;
	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_DATA, frame, sizeof(frame), p->Record, SES_BUF, &record_size), "a 60-byte frame on the data stream");
	coretest_check_hex(p->Record, record_size, g->Data, "the data record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_DATA && data_size == sizeof(frame) &&
	                   memcmp(p->Data, frame, sizeof(frame)) == 0,
	               "the server receives the frame");

	// One keepalive interval later the quiet client sends a keepalive
	now += NOISE_KEEPALIVE_INTERVAL;
	coretest_check(NoiseSessionPoll(&p->Client, now - 1, p->Record, SES_BUF, &record_size) == NOISE_POLL_IDLE, "no keepalive before the interval");
	coretest_check(NoiseSessionPoll(&p->Client, now, p->Record, SES_BUF, &record_size) == NOISE_POLL_SEND, "a keepalive after it");
	coretest_check_hex(p->Record, record_size, g->Keepalive, "the keepalive record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_NONE && data_size == 0, "the server takes it");

	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_DATA, "rekey 1", 7, p->Record, SES_BUF, &record_size), "the fourth record");
	coretest_check_hex(p->Record, record_size, g->Rekey1, encrypt ? "it carries the rekey flag, as in the golden one" : "the record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_DATA && data_size == 7, "the server receives it");
	coretest_check(p->Client.NumRekeys == (encrypt ? 1 : 0) && p->Server.NumPeerRekeys == (encrypt ? 1 : 0), encrypt ? "the client took its next key, and the server too" : "a bound session keeps no keys of its own");
	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_DATA, "rekey 2", 7, p->Record, SES_BUF, &record_size), "the fifth record");
	coretest_check_hex(p->Record, record_size, g->Rekey2, encrypt ? "it is under the next key, as in the golden one" : "the record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_DATA && data_size == 7 &&
	                   memcmp(p->Data, "rekey 2", 7) == 0,
	               "the server receives it under its next key");

	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_CLOSE, NULL, 0, p->Record, SES_BUF, &record_size) && p->Client.State == NOISE_STATE_CLOSED, "the client closes");
	coretest_check_hex(p->Record, record_size, g->Close, "the close record is the golden one");
	coretest_check(NoiseSessionReceive(&p->Server, now, p->Record, record_size, p->Data, SES_BUF, &data_size) == NOISE_RECEIVE_CLOSE && p->Server.State == NOISE_STATE_CLOSED,
	               "the server reads the close and is closed");
	coretest_check(NoiseSessionSend(&p->Client, now, NOISE_RECORD_DATA, "x", 1, p->Record, SES_BUF, &record_size) == false, "nothing goes out of a closed session");

	ses_free(p);
}

// The channel binding: a binding that differs fails the handshake
static void ses_binding() {
	SES_PAIR *p = ses_new();
	UCHAR hash[CRYPTO_END_POINT_MAX_SIZE], hash2[CRYPTO_END_POINT_MAX_SIZE], sha[CRYPTO_SHA256_SIZE];
	UINT hash_size = 0, hash2_size = 0;
	UINT scope = coretest_scope();

	printf("  channel binding:\n");
	if (coretest_check(p != NULL, "allocated") == false)
		return;

	ses_configure(p, false, false);
	coretest_check(ses_handshake(p, 0), "the same exporter on both ends: the handshake completes");
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	// A party in the middle that terminates TLS has two TLS sessions, so two exporters
	UCHAR other[NOISE_EXPORTER_SIZE];
	for (UINT i = 0; i < sizeof(other); i++)
		other[i] = (UCHAR)i;
	other[31] ^= 0x01;
	p->ServerConfig.Binding = other;
	coretest_check(ses_handshake(p, 0) == false && p->Server.State == NOISE_STATE_CLOSED && p->Client.State == NOISE_STATE_HANDSHAKE,
	               "another exporter on the server: the server refuses the handshake, so the connection closes");
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	p->ServerConfig.Binding = p->Binding;
	p->ServerConfig.BindingType = NOISE_BINDING_SERVER_END_POINT;
	coretest_check(ses_handshake(p, 0) == false, "the same bytes as another binding type fail");
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	ses_configure(p, false, false);
	p->ServerConfig.Flags = NOISE_SESSION_ENCRYPT;
	p->ServerConfig.BindingType = NOISE_BINDING_NONE;
	p->ServerConfig.BindingSize = 0;
	coretest_check(ses_handshake(p, 0) == false, "a bound client and an unbound server fail");
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	UINT size = 0;
	ses_configure(p, false, false);
	p->ClientConfig.Flags = NOISE_SESSION_ENCRYPT;
	coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size) == false, "an encrypted session with a binding is refused");
	p->ClientConfig.Flags = 0;
	p->ClientConfig.BindingType = NOISE_BINDING_NONE;
	p->ClientConfig.BindingSize = 0;
	coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size) == false, "a session in clear without a binding is refused");
	p->ClientConfig.BindingType = NOISE_BINDING_EXPORTER;
	p->ClientConfig.BindingSize = 16;
	coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size) == false, "an exporter of 16 bytes is refused");
	NoiseSessionFree(&p->Client);

	// tls-server-end-point (RFC 5929): the hash of the pinned server certificate
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(L"CN=noise.coretest", NULL, NULL, 1, scope);
	PCCERT_CONTEXT cert2 = CryptoCertCreateSelfSigned(L"CN=noise.coretest", NULL, NULL, 1, scope);
	if (coretest_check(cert != NULL && cert2 != NULL, "two self-signed ECDSA P-256 certificates")) {
		coretest_check(CryptoCertEndPoint(cert, hash, &hash_size) && hash_size == 32 && CryptoSha256(sha, cert->pbCertEncoded, cert->cbCertEncoded) &&
		                   memcmp(hash, sha, sizeof(sha)) == 0,
		               "ecdsa-with-SHA256: tls-server-end-point is the SHA-256 of the certificate");
		coretest_check(CryptoCertEndPoint(cert2, hash2, &hash2_size) && hash2_size == 32 && memcmp(hash, hash2, 32) != 0, "the other certificate has another");

		ses_configure(p, false, false);
		p->ClientConfig.BindingType = NOISE_BINDING_SERVER_END_POINT;
		p->ClientConfig.Binding = hash;
		p->ClientConfig.BindingSize = hash_size;
		p->ServerConfig.BindingType = NOISE_BINDING_SERVER_END_POINT;
		p->ServerConfig.Binding = hash;
		p->ServerConfig.BindingSize = hash_size;
		coretest_check(ses_handshake(p, 0), "bound to the end point of the same certificate: the handshake completes");
		NoiseSessionFree(&p->Client);
		NoiseSessionFree(&p->Server);
		p->ServerConfig.Binding = hash2;
		coretest_check(ses_handshake(p, 0) == false, "a server presenting another certificate fails the client's binding");
		NoiseSessionFree(&p->Client);
		NoiseSessionFree(&p->Server);
	}
	if (cert != NULL)
		CryptoCertDeleteKey(cert);
	if (cert2 != NULL)
		CryptoCertDeleteKey(cert2);
	CryptoCertFree(cert);
	CryptoCertFree(cert2);

	cert = CryptoCertImportPfx(coretest_pfx, coretest_pfx_size, CORETEST_PFX_PASSWORD, scope);
	if (coretest_check(cert != NULL, "the certificate of the OpenSSL 3 PFX (ECDSA P-256)")) {
		coretest_info("its signature algorithm: %s", cert->pCertInfo->SignatureAlgorithm.pszObjId);
		coretest_check(CryptoCertEndPoint(cert, hash, &hash_size) && hash_size == 32 && CryptoSha256(sha, cert->pbCertEncoded, cert->cbCertEncoded) &&
		                   memcmp(hash, sha, sizeof(sha)) == 0,
		               "its tls-server-end-point is the SHA-256 of the certificate");
		CryptoCertDeleteKey(cert);
	}
	CryptoCertFree(cert);
	coretest_check(CryptoCertEndPoint(NULL, hash, &hash_size) == false && hash_size == 0, "no certificate: no end point");

	ses_free(p);
}

// The Login: its encoding, what Parse refuses, and the gate on data before it is accepted
static void ses_login_tests() {
	SES_PAIR *p = ses_new();
	NOISE_LOGIN l, r;
	UCHAR buf[1024], cert[300], sign[256];
	UINT size = 0, data_size = 0;

	printf("  Login:\n");
	if (coretest_check(p != NULL, "allocated") == false)
		return;

	for (UINT i = 0; i < sizeof(cert); i++)
		cert[i] = (UCHAR)(i * 7);
	for (UINT i = 0; i < sizeof(sign); i++)
		sign[i] = (UCHAR)(i * 13);

	UINT methods[] = {NOISE_LOGIN_ANONYMOUS, NOISE_LOGIN_PASSWORD, NOISE_LOGIN_CERT, NOISE_LOGIN_JOIN};
	for (UINT m = 0; m < 4; m++) {
		ZeroMemory(&l, sizeof(l));
		l.Method = methods[m];
		strcpy_s(l.HubName, sizeof(l.HubName), "DEFAULT");
		strcpy_s(l.UserName, sizeof(l.UserName), "user@example.com");
		strcpy_s(l.Password, sizeof(l.Password), "p\xc3\xa4ss");
		l.Cert = cert;
		l.CertSize = sizeof(cert);
		l.Sign = sign;
		l.SignSize = sizeof(sign);
		FillMemory(l.TunnelId, sizeof(l.TunnelId), 0x5a);
		bool ok = NoiseLoginEncode(&l, buf, sizeof(buf), &size) && NoiseLoginParse(&r, buf, size) && r.Method == l.Method && strcmp(r.HubName, l.HubName) == 0 &&
		          strcmp(r.UserName, l.UserName) == 0;
		if (l.Method == NOISE_LOGIN_PASSWORD)
			ok = ok && strcmp(r.Password, l.Password) == 0;
		if (l.Method == NOISE_LOGIN_CERT)
			ok = ok && r.CertSize == sizeof(cert) && memcmp(r.Cert, cert, sizeof(cert)) == 0 && r.SignSize == sizeof(sign) && memcmp(r.Sign, sign, sizeof(sign)) == 0;
		if (l.Method == NOISE_LOGIN_JOIN)
			ok = ok && memcmp(r.TunnelId, l.TunnelId, sizeof(l.TunnelId)) == 0;
		coretest_check(ok, m == 0 ? "anonymous Login: encoded and parsed back" : m == 1 ? "password Login: encoded and parsed back" : m == 2 ? "certificate Login: encoded and parsed back" : "join Login: encoded and parsed back");
		if (m == 2) {
			// Every truncation of a valid Login fails, and so does a byte more
			bool all = true;
			for (UINT cut = 0; cut < size; cut++)
				all = all && NoiseLoginParse(&r, buf, cut) == false;
			buf[size] = 0;
			coretest_check(all && NoiseLoginParse(&r, buf, size + 1) == false && r.Method == 0, "every truncated certificate Login, and one with a byte more, fails");
		}
	}

	// What Parse refuses
	static const char *bad[] = {
	    "02010348554205616c69636500067365637265740000",   // version 2
	    "01090348554205616c69636500067365637265740000",   // method 9
	    "01010005616c69636500067365637265740000",         // empty hub name
	    "0101034800554205616c69636500067365637265740000", // NUL in the hub name
	    "01010348554205616c69636500067365637265740001aa", // a signature on a password Login
	    "01020348554205616c6963650001010000",             // a certificate Login without signature
	    "01030348554205616c6963650004010203040000",       // a tunnel id of 4 bytes
	    "01000348554205616c6963650001610000",             // a secret on an anonymous Login
	};
	bool refused = true;
	for (UINT i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		UINT n = coretest_unhex(buf, sizeof(buf), bad[i]);
		if (NoiseLoginParse(&r, buf, n)) {
			coretest_info("parsed, but should not: %s", bad[i]);
			refused = false;
		}
	}
	coretest_check(refused, "malformed Logins are refused");
	ZeroMemory(&l, sizeof(l));
	l.Method = NOISE_LOGIN_PASSWORD;
	strcpy_s(l.UserName, sizeof(l.UserName), "u");
	coretest_check(NoiseLoginEncode(&l, buf, sizeof(buf), &size) == false, "a Login without a hub is not encoded");
	strcpy_s(l.HubName, sizeof(l.HubName), "H");
	coretest_check(NoiseLoginEncode(&l, buf, 9, &size) == false && NoiseLoginEncode(&l, buf, 10, &size) && size == 10, "a buffer one byte short is refused");

	// The server refuses data before its owner accepted the Login, and closes the session
	ses_configure(p, false, false);
	if (coretest_check(ses_handshake(p, 0), "a bound session")) {
		coretest_check(ses_send(p, &p->Client, &p->Server, 0, NOISE_RECORD_DATA, "early", 5, &data_size) == NOISE_RECEIVE_ERROR && p->Server.State == NOISE_STATE_CLOSED,
		               "data before the Login is accepted closes the server's session");
		coretest_check(ses_send(p, &p->Client, &p->Server, 0, NOISE_RECORD_CONTROL, "x", 1, &data_size) == NOISE_RECEIVE_ERROR, "a closed session reads nothing");
	}
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	// Challenges differ from session to session
	UCHAR c1[NOISE_LOGIN_CHALLENGE_SIZE], c2[NOISE_LOGIN_CHALLENGE_SIZE];
	ses_configure(p, false, false);
	bool ok = ses_handshake(p, 0) && NoiseSessionChallenge(&p->Server, c1, sizeof(c1));
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);
	ok = ok && ses_handshake(p, 0) && NoiseSessionChallenge(&p->Server, c2, sizeof(c2));
	coretest_check(ok && memcmp(c1, c2, sizeof(c1)) != 0, "two sessions of the same nodes have different challenges (fresh ephemeral keys)");

	ses_free(p);
}

// Keepalive and the dead-peer timeout on a bound session, then on an encrypted one
static void ses_timers(bool encrypt) {
	SES_PAIR *p = ses_new();
	SES_POLL cr, sr;
	UINT64 now = 0, last_from_client = 0;
	UINT64 step = 500;
	bool open = true;

	printf("  timers, %s session (keepalive %u ms, dead %u ms):\n", encrypt ? "encrypted" : "bound", NOISE_KEEPALIVE_INTERVAL, NOISE_DEAD_TIMEOUT);
	if (coretest_check(p != NULL, "allocated") == false)
		return;
	ses_configure(p, encrypt, false);
	if (coretest_check(ses_handshake(p, now), "the session is open") == false) {
		ses_free(p);
		return;
	}
	NoiseSessionAcceptLogin(&p->Server);

	// Ten dead timeouts without a payload: both ends poll every step, keepalives keep it open
	ZeroMemory(&cr, sizeof(cr));
	ZeroMemory(&sr, sizeof(sr));
	for (now = step; now <= 10 * (UINT64)NOISE_DEAD_TIMEOUT; now += step) {
		ses_poll(p, &p->Client, &p->Server, now, true, &cr);
		ses_poll(p, &p->Server, &p->Client, now, true, &sr);
		if (cr.Dead || sr.Dead || cr.Error || sr.Error)
			open = false;
	}
	UINT expect = (UINT)(10 * (UINT64)NOISE_DEAD_TIMEOUT / NOISE_KEEPALIVE_INTERVAL);
	coretest_info("idle for %u ms: %u keepalives from the client, %u from the server", 10 * NOISE_DEAD_TIMEOUT, cr.Sent, sr.Sent);
	coretest_check(open && p->Client.State == NOISE_STATE_OPEN && p->Server.State == NOISE_STATE_OPEN, "keepalive holds the idle session open for ten dead timeouts");
	coretest_check(cr.Sent == expect && sr.Sent == expect, "one keepalive per interval from each end");

	// The client's records are lost from now on: the server declares it dead after the timeout
	last_from_client = p->Server.LastReceived;
	UINT64 dead_at = 0;
	for (; now <= last_from_client + 2 * (UINT64)NOISE_DEAD_TIMEOUT && dead_at == 0; now += step) {
		ses_poll(p, &p->Client, &p->Server, now, false, &cr);
		ZeroMemory(&sr, sizeof(sr));
		ses_poll(p, &p->Server, &p->Client, now, true, &sr);
		if (sr.Dead)
			dead_at = now;
	}
	coretest_info("the client's last record reached the server at %llu ms; the server declared it dead at %llu ms", last_from_client, dead_at);
	coretest_check(dead_at >= last_from_client + NOISE_DEAD_TIMEOUT && dead_at < last_from_client + NOISE_DEAD_TIMEOUT + step && p->Server.State == NOISE_STATE_CLOSED,
	               "a silent peer is dead after the dead timeout, at the first poll past it");
	coretest_check(p->Client.State == NOISE_STATE_OPEN && cr.Dead == false, "the client, which still heard the server, is open");

	// A handshake that gets no answer times out the same way
	UINT size = 0;
	NoiseSessionFree(&p->Client);
	coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size) &&
	                   NoiseSessionPoll(&p->Client, NOISE_DEAD_TIMEOUT - 1, p->Record, SES_BUF, &size) == NOISE_POLL_IDLE &&
	                   NoiseSessionPoll(&p->Client, NOISE_DEAD_TIMEOUT, p->Record, SES_BUF, &size) == NOISE_POLL_DEAD,
	               "a handshake without an answer is dead after the dead timeout");

	ses_free(p);
}

// Rekey on a schedule: by time and by records on an encrypted session, by time on a bound one
static void ses_rekey() {
	SES_PAIR *p = ses_new();
	SES_POLL cr, sr;
	UINT data_size = 0;
	bool ok = true;

	printf("  rekey:\n");
	if (coretest_check(p != NULL, "allocated") == false)
		return;

	// Encrypted, rekey every second: 10.5 s of a frame every 500 ms and polls every 100 ms
	ses_configure(p, true, false);
	p->ClientConfig.RekeyInterval = 1000;
	p->ServerConfig.RekeyInterval = 1000;
	ZeroMemory(&cr, sizeof(cr));
	ZeroMemory(&sr, sizeof(sr));
	if (coretest_check(ses_handshake(p, 0), "an encrypted session, rekey interval 1000 ms")) {
		NoiseSessionAcceptLogin(&p->Server);
		for (UINT64 now = 100; now <= 10500; now += 100) {
			if (now % 500 == 0)
				ok = ok && ses_send(p, &p->Client, &p->Server, now, NOISE_RECORD_DATA, "frame", 5, &data_size) == NOISE_RECEIVE_DATA;
			ses_poll(p, &p->Client, &p->Server, now, true, &cr);
			ses_poll(p, &p->Server, &p->Client, now, true, &sr);
		}
		coretest_info("in 10500 ms: the client rekeyed %llu times, the server %llu times", p->Client.NumRekeys, p->Server.NumRekeys);
		coretest_check(ok && cr.Error == false && sr.Error == false, "every record decrypts across the rekeys");
		coretest_check(p->Client.NumRekeys == 10 && p->Server.NumPeerRekeys == 10, "the client takes a new key every second, and the server follows");
		coretest_check(p->Server.NumRekeys == 10 && p->Client.NumPeerRekeys == 10, "so does the server, though it sends keepalives only");
	}
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	// Encrypted, 50 records under one key: 500 records give 10 rekeys
	ses_configure(p, true, false);
	p->ClientConfig.RekeyRecords = 50;
	ok = true;
	if (coretest_check(ses_handshake(p, 0), "an encrypted session, 50 records under one key")) {
		NoiseSessionAcceptLogin(&p->Server);
		for (UINT i = 0; i < 500; i++)
			ok = ok && ses_send(p, &p->Client, &p->Server, 0, NOISE_RECORD_DATA, &i, sizeof(i), &data_size) == NOISE_RECEIVE_DATA && data_size == sizeof(i) &&
			     memcmp(p->Data, &i, sizeof(i)) == 0;
		coretest_check(ok && p->Client.NumRekeys == 10 && p->Server.NumPeerRekeys == 10 && p->Client.SentUnderKey == 0, "500 records: a new key after every 50th");

		// A lost record: the next one is under another nonce and fails
		UINT record_size = 0;
		NoiseSessionSend(&p->Client, 0, NOISE_RECORD_DATA, "lost", 4, p->Record, SES_BUF, &record_size);
		coretest_check(ses_send(p, &p->Client, &p->Server, 0, NOISE_RECORD_DATA, "next", 4, &data_size) == NOISE_RECEIVE_ERROR && p->Server.State == NOISE_STATE_CLOSED,
		               "after a lost record the next one fails: an encrypted session needs its records in order");
	}
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);

	// Bound: the owner is told to update the outer keys every second
	ses_configure(p, false, false);
	p->ClientConfig.RekeyInterval = 1000;
	ZeroMemory(&cr, sizeof(cr));
	ZeroMemory(&sr, sizeof(sr));
	if (coretest_check(ses_handshake(p, 0), "a bound session, rekey interval 1000 ms")) {
		for (UINT64 now = 100; now <= 10500; now += 100) {
			ses_poll(p, &p->Client, &p->Server, now, true, &cr);
			ses_poll(p, &p->Server, &p->Client, now, true, &sr);
		}
		coretest_check(cr.Rekeys == 10 && p->Client.NumRekeys == 10, "NOISE_POLL_REKEY every second: ten outer key updates in 10500 ms");
		coretest_check(sr.Rekeys == 0, "the server, on the default interval, none yet");
		UINT record_size = 0;
		p->Record[0] = NOISE_RECORD_DATA | NOISE_RECORD_REKEYED;
		NoiseSessionAcceptLogin(&p->Server);
		coretest_check(NoiseSessionReceive(&p->Server, 10500, p->Record, 2, p->Data, SES_BUF, &record_size) == NOISE_RECEIVE_ERROR, "a rekey flag on a bound session is refused");
	}

	ses_free(p);
}

// An IKhfs session, where CNG has ML-KEM
static void ses_hfs() {
	SES_PAIR *p = ses_new();
	UINT data_size = 0;

	printf("  IKhfs session:\n");
	if (coretest_check(p != NULL, "allocated") == false)
		return;

	ses_configure(p, false, false);
	p->ClientConfig.Suite = NOISE_SUITE_IKHFS;
	if (CryptoMlKemAvailable()) {
		coretest_check(ses_handshake(p, 0) && p->Client.State == NOISE_STATE_OPEN && p->Server.State == NOISE_STATE_OPEN, "the client chose IKhfs, the server followed");
		NoiseSessionAcceptLogin(&p->Server);
		coretest_check(ses_send(p, &p->Client, &p->Server, 0, NOISE_RECORD_DATA, "pq", 2, &data_size) == NOISE_RECEIVE_DATA, "records flow");
	} else {
		UINT size = 0;
		coretest_check(NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size) == false, "without ML-KEM, IKhfs is refused");
	}

	// A suite the server does not know, and a second record that names another suite
	NoiseSessionFree(&p->Client);
	NoiseSessionFree(&p->Server);
	ses_configure(p, false, false);
	UINT size = 0, reply_size = 0;
	if (NoiseSessionConnect(&p->Client, &p->ClientConfig, 0, p->Record, SES_BUF, &size)) {
		p->Record[1] = 9;
		coretest_check(NoiseSessionAccept(&p->Server, &p->ServerConfig, 0, p->Record, size, p->Reply, SES_BUF, &reply_size) == false, "a suite the server does not know is refused");
		p->Record[1] = NOISE_SUITE_IK;
		if (NoiseSessionAccept(&p->Server, &p->ServerConfig, 0, p->Record, size, p->Reply, SES_BUF, &reply_size)) {
			p->Reply[1] = NOISE_SUITE_IKHFS;
			coretest_check(NoiseSessionFinish(&p->Client, 0, p->Reply, reply_size) == false && p->Client.State == NOISE_STATE_CLOSED, "an answer that names another suite is refused");
		}
	}

	ses_free(p);
}

void noisesession_test() {
	ses_golden(false);
	ses_golden(true);
	ses_binding();
	ses_login_tests();
	ses_timers(false);
	ses_timers(true);
	ses_rekey();
	ses_hfs();
}

//
// The tunnel
//

#define TUN_FLOWS 1000

// N sessions of the client node to the server node, each with its own binding (its own TLS
// session), and the client's tunnel over them
static bool tun_open(SES_PAIR **pairs, UINT n) {
	for (UINT i = 0; i < n; i++) {
		pairs[i] = ses_new();
		if (pairs[i] == NULL)
			return false;
		ses_configure(pairs[i], false, false);
		pairs[i]->Binding[0] = (UCHAR)(0xA0 + i);
		if (ses_handshake(pairs[i], 0) == false)
			return false;
		NoiseSessionAcceptLogin(&pairs[i]->Server);
	}

	return true;
}

// The connection index of every flow hash 0 .. TUN_FLOWS - 1, or n for none
static void tun_map(const NOISE_TUNNEL *t, SES_PAIR **pairs, UINT n, UINT *map) {
	for (UINT f = 0; f < TUN_FLOWS; f++) {
		NOISE_SESSION *s = NoiseTunnelRoute(t, f * 2654435761u);
		map[f] = n;
		for (UINT i = 0; i < n; i++)
			if (s == &pairs[i]->Client)
				map[f] = i;
	}
}

void noisetunnel_test() {
	SES_PAIR *pairs[5];
	NOISE_TUNNEL t, t1;
	UINT *map = (UINT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 3 * TUN_FLOWS * sizeof(UINT));
	UINT count[5];
	UCHAR id[NOISE_TUNNEL_ID_SIZE];

	ZeroMemory(pairs, sizeof(pairs));
	if (coretest_check(map != NULL && tun_open(pairs, 4), "four connections of one client node to one server node, each bound to its own TLS session") == false)
		goto END;
	UINT *before = map, *after = map + TUN_FLOWS, *back = map + 2 * TUN_FLOWS;

	// N = 1
	coretest_check(NoiseTunnelInit(&t1, &pairs[0]->Client, 1) && NoiseTunnelNumAlive(&t1) == 1, "a tunnel of one connection");
	bool all = true;
	for (UINT f = 0; f < TUN_FLOWS; f++)
		all = all && NoiseTunnelRoute(&t1, f * 2654435761u) == &pairs[0]->Client;
	coretest_check(all, "N = 1: every flow goes over the one connection");
	coretest_check(NoiseTunnelJoin(&t1, 1, &pairs[1]->Client) == false, "N = 1: no second connection joins");

	// N = 4: the id of the first connection's handshake, the same on both nodes
	coretest_check(NoiseTunnelInit(&t, &pairs[0]->Client, 4) && NoiseTunnelId(&pairs[0]->Server, id) && memcmp(id, t.Id, sizeof(id)) == 0,
	               "a tunnel of four connections; the server derives the same tunnel id");
	coretest_check(NoiseTunnelId(&pairs[1]->Client, id) && memcmp(id, t.Id, sizeof(id)) != 0, "another connection's handshake gives another id: only the first names the tunnel");
	coretest_check(NoiseTunnelJoin(&t, 1, &pairs[1]->Client) && NoiseTunnelJoin(&t, 2, &pairs[2]->Client) && NoiseTunnelJoin(&t, 3, &pairs[3]->Client) &&
	                   NoiseTunnelNumAlive(&t) == 4,
	               "three more connections join");
	coretest_check(NoiseTunnelJoin(&t, 3, &pairs[3]->Client) == false && NoiseTunnelJoin(&t, 4, &pairs[3]->Client) == false, "a taken or out-of-range index is refused");

	tun_map(&t, pairs, 4, before);
	ZeroMemory(count, sizeof(count));
	for (UINT f = 0; f < TUN_FLOWS; f++)
		count[before[f]]++;
	coretest_info("N = 4: flows per connection %u %u %u %u", count[0], count[1], count[2], count[3]);
	coretest_check(count[0] == 250 && count[1] == 250 && count[2] == 250 && count[3] == 250, "N = 4: the flows spread evenly over the four");
	tun_map(&t, pairs, 4, after);
	coretest_check(memcmp(before, after, TUN_FLOWS * sizeof(UINT)) == 0, "a flow keeps its connection, so its packets keep their order");

	// Connection 2 is lost: only its flows move, over the three left
	NoiseTunnelLose(&t, 2);
	tun_map(&t, pairs, 4, after);
	UINT moved = 0, kept = 0;
	ZeroMemory(count, sizeof(count));
	for (UINT f = 0; f < TUN_FLOWS; f++) {
		if (before[f] == 2) {
			moved++;
			count[after[f]]++;
		} else if (after[f] == before[f]) {
			kept++;
		}
	}
	coretest_info("connection 2 lost: its %u flows went %u, %u, %u over connections 0, 1, 3", moved, count[0], count[1], count[3]);
	coretest_check(NoiseTunnelNumAlive(&t) == 3 && kept == TUN_FLOWS - 250 && moved == 250 && count[2] == 0 && count[4] == 0,
	               "a lost connection's flows move, every other flow stays, and the tunnel stays up");
	coretest_check(count[0] > 50 && count[1] > 50 && count[3] > 50, "the moved flows spread over the connections left");

	// It joins again: every flow is back where it was
	coretest_check(NoiseTunnelJoin(&t, 2, &pairs[2]->Client), "connection 2 joins again");
	tun_map(&t, pairs, 4, back);
	coretest_check(memcmp(before, back, TUN_FLOWS * sizeof(UINT)) == 0, "its flows come back to it");

	// A connection that died (dead timeout) counts as lost
	pairs[1]->Client.State = NOISE_STATE_CLOSED;
	tun_map(&t, pairs, 4, after);
	all = NoiseTunnelNumAlive(&t) == 3;
	for (UINT f = 0; f < TUN_FLOWS; f++)
		all = all && after[f] != 1 && (before[f] == 1 || after[f] == before[f]);
	coretest_check(all, "a closed session carries no flow, without a Lose");
	pairs[1]->Client.State = NOISE_STATE_OPEN;

	// Down to none
	NoiseTunnelLose(&t, 0);
	NoiseTunnelLose(&t, 1);
	NoiseTunnelLose(&t, 3);
	coretest_check(NoiseTunnelNumAlive(&t) == 1 && NoiseTunnelRoute(&t, 12345) == &pairs[2]->Client, "one connection left carries every flow");
	NoiseTunnelLose(&t, 2);
	coretest_check(NoiseTunnelNumAlive(&t) == 0 && NoiseTunnelRoute(&t, 12345) == NULL, "no connection left: no route");

	// Only the same peer node joins: a connection of another client node is refused
	pairs[4] = ses_new();
	if (pairs[4] != NULL) {
		UCHAR other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE];
		NOISE_TUNNEL ts;

		ses_configure(pairs[4], false, false);
		CryptoX25519GenerateKey(other, other_pub);
		CopyMemory(pairs[4]->ClientKey, other, sizeof(other));
		coretest_check(ses_handshake(pairs[4], 0) && NoiseTunnelInit(&ts, &pairs[0]->Server, 2) &&
		                   NoiseTunnelJoin(&ts, 1, &pairs[4]->Server) == false && NoiseTunnelJoin(&ts, 1, &pairs[1]->Server),
		               "the server's tunnel takes a second connection of the same client node, not one of another node");
		SecureZeroMemory(other, sizeof(other));
	}
	coretest_check(NoiseTunnelInit(&t, &pairs[0]->Client, 0) == false && NoiseTunnelInit(&t, &pairs[0]->Client, NOISE_TUNNEL_MAX_CONNECTIONS + 1) == false,
	               "a tunnel of 0 or of more than 16 connections is refused");

	// Each connection rekeys on its own schedule
	SES_POLL r[3];
	ZeroMemory(r, sizeof(r));
	pairs[0]->Client.RekeyInterval = 1000;
	pairs[1]->Client.RekeyInterval = 3000;
	for (UINT64 now = 100; now <= 6500; now += 100)
		for (UINT i = 0; i < 3; i++) {
			ses_poll(pairs[i], &pairs[i]->Client, &pairs[i]->Server, now, true, &r[i]);
			SES_POLL ignore;
			ZeroMemory(&ignore, sizeof(ignore));
			ses_poll(pairs[i], &pairs[i]->Server, &pairs[i]->Client, now, true, &ignore);
		}
	coretest_check(r[0].Rekeys == 6 && r[1].Rekeys == 2 && r[2].Rekeys == 0, "in 6500 ms: connection 0 rekeys 6 times (1 s), connection 1 twice (3 s), connection 2 not yet");

END:
	for (UINT i = 0; i < 5; i++)
		ses_free(pairs[i]);
	if (map != NULL)
		HeapFree(GetProcessHeap(), 0, map);
}
