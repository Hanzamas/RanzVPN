// fallback.c
// The fallback after a handshake (CORE-H5-R, #443; src/Core/TransportFallback.c). A server that refuses the Noise
// handshake over QUIC, as a node of the build before CORE-H5 refuses one of this build, and takes it over TLS-443: the
// client's race wins over QUIC, whose stream connects first, the handshake fails there, and the next dial races the rest
// of the fallback list and comes up over TLS-443. The transport taken out comes back after TRANSPORT_FALLBACK_HOLD. The
// two transports are loopback transports of their own named "quic" and "tls", the QUIC one the faster, and the server
// behind "quic" answers with another static key than the one the client expects, so its handshake fails as that of the
// old node does: the responder cannot read message 1 and closes the stream.

#include "coretest.h"

#include "Core/Transport.h"

#include <string.h>

// The address of the server on both transports, and the fallback list of the client
#define FALLBACK_ADDRESS "server"
#define FALLBACK_LIST    "quic:" FALLBACK_ADDRESS ", tls:" FALLBACK_ADDRESS
// ms that a dial of the "tls" transport takes, so that "quic" wins a race of both
#define FALLBACK_TLS_DIAL 100
// ms for a race, a handshake or a record
#define FALLBACK_TIMEOUT 10000
// ms that an accept of a server waits before it looks at its stop flag
#define FALLBACK_POLL 200
// The record that a session echoes
#define FALLBACK_ECHO "fallback"

// The server behind one transport: it accepts each stream, runs the responder with its static key and echoes the records
// of each session that comes up
typedef struct FALLBACK_SERVER {
	TRANSPORT_LISTENER *Listener; // Its listener
	const UCHAR *Key;             // Its static key
	volatile LONG Stop;           // The test is over
	volatile LONG Sessions;       // Handshakes that completed
	volatile LONG Refused;        // ... and that failed
	HANDLE Thread;                // Its thread
} FALLBACK_SERVER;

// The configuration of an end of a session
static void fallback_noise(NOISE_SESSION_CONFIG *c, const UCHAR *key, const UCHAR *remote) {
	ZeroMemory(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 1000;
	c->DeadTimeout = FALLBACK_TIMEOUT;
	c->RekeyInterval = 60000;
}

static DWORD WINAPI fallback_server(LPVOID param) {
	FALLBACK_SERVER *v = (FALLBACK_SERVER *)param;
	UCHAR *buf = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, NOISE_MAX_PAYLOAD);
	NOISE_SESSION_CONFIG c;

	while (buf != NULL && InterlockedCompareExchange(&v->Stop, 0, 0) == 0) {
		TRANSPORT_STREAM *s = TransportAccept(v->Listener, FALLBACK_POLL);
		if (s == NULL)
			continue;

		TRANSPORT_NOISE *t = (TRANSPORT_NOISE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_NOISE));
		if (t == NULL) {
			TransportClose(s);
			continue;
		}

		fallback_noise(&c, v->Key, NULL);
		if (TransportNoiseAccept(t, s, &c, FALLBACK_TIMEOUT)) {
			TransportNoiseAcceptLogin(t);
			InterlockedIncrement(&v->Sessions);

			while (true) {
				UINT size = 0;
				UINT r = TransportNoiseReceive(t, buf, NOISE_MAX_PAYLOAD, &size, FALLBACK_TIMEOUT);

				if (r != NOISE_RECEIVE_DATA && r != NOISE_RECEIVE_CONTROL)
					break;
				TransportNoiseSend(t, (r == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
			}
		} else {
			InterlockedIncrement(&v->Refused);
		}

		TransportNoiseClose(t);
		HeapFree(GetProcessHeap(), 0, t);
	}

	if (buf != NULL)
		HeapFree(GetProcessHeap(), 0, buf);

	return 0;
}

// One dial of the client, as the client role of a node dials a server: the race of the entries that the fallback gives,
// then the handshake on the stream that won, which tells the fallback when it fails. The name of the transport that won
// goes into winner (empty when none did), the entries raced into *raced; true when the session came up and echoed a
// record.
static bool fallback_dial(TRANSPORT_FALLBACK *f, const TRANSPORT_TARGET *targets, UINT num, UINT64 now, const UCHAR *key, const UCHAR *server,
                          char *winner, UINT size, UINT *raced) {
	TRANSPORT_TARGET list[TRANSPORT_MAX_TARGETS];
	NOISE_SESSION_CONFIG c;
	TRANSPORT_RACE race;
	UCHAR buf[64];
	UINT got = 0;

	winner[0] = 0;
	*raced = TransportFallbackTargets(f, targets, num, now, list, TRANSPORT_MAX_TARGETS);

	TRANSPORT_STREAM *s = TransportRace(list, *raced, TRANSPORT_RACE_DELAY, FALLBACK_TIMEOUT, &race);
	if (s == NULL)
		return false;

	TransportFallbackWon(f, list[race.Winner].Transport);
	strncpy_s(winner, size, list[race.Winner].Transport->Name, _TRUNCATE);

	TRANSPORT_NOISE *n = (TRANSPORT_NOISE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_NOISE));
	if (n == NULL) {
		TransportClose(s);
		return false;
	}

	fallback_noise(&c, key, server);
	bool ok = TransportNoiseConnect(n, s, &c, FALLBACK_TIMEOUT);
	if (ok == false) {
		TransportFallbackRefused(f, now);
	} else {
		ok = TransportNoiseSend(n, NOISE_RECORD_DATA, FALLBACK_ECHO, sizeof(FALLBACK_ECHO) - 1) &&
		     TransportNoiseReceive(n, buf, sizeof(buf), &got, FALLBACK_TIMEOUT) == NOISE_RECEIVE_DATA && got == sizeof(FALLBACK_ECHO) - 1 &&
		     memcmp(buf, FALLBACK_ECHO, got) == 0;
	}

	TransportNoiseClose(n);
	HeapFree(GetProcessHeap(), 0, n);

	return ok;
}

// Whether the counter of a server reaches want within FALLBACK_TIMEOUT: the server counts a handshake after it closed
// the stream, which the client may see first
static bool fallback_count(volatile LONG *counter, LONG want) {
	UINT64 end = GetTickCount64() + FALLBACK_TIMEOUT;

	while (InterlockedCompareExchange(counter, 0, 0) < want && GetTickCount64() < end)
		Sleep(10);

	return (InterlockedCompareExchange(counter, 0, 0) == want);
}

// Start a server on a listener of t with its static key
static bool fallback_start(FALLBACK_SERVER *v, TRANSPORT *t, const UCHAR *key) {
	ZeroMemory(v, sizeof(FALLBACK_SERVER));
	v->Key = key;
	v->Listener = (t != NULL ? TransportListen(t, FALLBACK_ADDRESS) : NULL);
	v->Thread = (v->Listener != NULL ? CreateThread(NULL, 0, fallback_server, v, 0, NULL) : NULL);

	return (v->Thread != NULL);
}

static void fallback_stop(FALLBACK_SERVER *v) {
	InterlockedExchange(&v->Stop, 1);
	if (v->Thread != NULL) {
		WaitForSingleObject(v->Thread, INFINITE);
		CloseHandle(v->Thread);
	}
	if (v->Listener != NULL)
		TransportCloseListener(v->Listener);
}

// The fallback on its own: a refusal without a race before it takes nothing out, and with every transport out the race
// dials them all
static void fallback_rules(TRANSPORT *quic, TRANSPORT *tls, const TRANSPORT_TARGET *targets, UINT num) {
	TRANSPORT_FALLBACK f;
	TRANSPORT_TARGET list[TRANSPORT_MAX_TARGETS];

	ZeroMemory(&f, sizeof(f));
	coretest_check(TransportFallbackRefused(&f, 0) == NULL && TransportFallbackTargets(&f, targets, num, 0, list, TRANSPORT_MAX_TARGETS) == num,
	               "a refusal without a race before it takes no transport out");

	TransportFallbackWon(&f, quic);
	coretest_check(TransportFallbackRefused(&f, 0) == quic && TransportFallbackRefused(&f, 0) == NULL, "a refusal takes out the transport of the last race, once");
	TransportFallbackWon(&f, tls);
	TransportFallbackRefused(&f, 0);
	UINT n = TransportFallbackTargets(&f, targets, num, 0, list, TRANSPORT_MAX_TARGETS);
	coretest_check(n == num && list[0].Transport == quic && list[1].Transport == tls, "with every transport of the list out, the race dials them all, in their order");
	coretest_check(TransportFallbackTargets(&f, targets, num, 0, list, 1) == 1 && TransportFallbackTargets(NULL, targets, num, 0, list, TRANSPORT_MAX_TARGETS) == 0,
	               "the entries stop at the room of the output, and no fallback gives none");
}

void fallback_test() {
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	UCHAR server[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE];
	UCHAR other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE];
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS], list[TRANSPORT_MAX_TARGETS];
	FALLBACK_SERVER old_quic, tls_server;
	TRANSPORT_FALLBACK f;
	char winner[TRANSPORT_NAME_SIZE];
	UINT raced = 0;

	TRANSPORT *quic = TransportLoopbackNew("quic", 0, false);
	TRANSPORT *tls = TransportLoopbackNew("tls", FALLBACK_TLS_DIAL, false);
	TRANSPORT *known[2] = {quic, tls};
	bool keys = CryptoX25519GenerateKey(key, pub) && CryptoX25519GenerateKey(server, server_pub) && CryptoX25519GenerateKey(other, other_pub);

	// The server: over "quic" it answers with another static key, as the old node whose binding differs refuses the
	// handshake; over "tls" with the key that the client expects
	ZeroMemory(&old_quic, sizeof(old_quic));
	ZeroMemory(&tls_server, sizeof(tls_server));
	bool started = keys && quic != NULL && tls != NULL && fallback_start(&old_quic, quic, other);
	started = started && fallback_start(&tls_server, tls, server);
	UINT num = (started ? TransportParseList(FALLBACK_LIST, known, 2, targets, TRANSPORT_MAX_TARGETS) : 0);

	if (coretest_check(started && num == 2, "a server that refuses the handshake over QUIC and takes it over TLS-443, and the list \"" FALLBACK_LIST "\"")) {
		UINT64 now = GetTickCount64();

		ZeroMemory(&f, sizeof(f));
		bool up = fallback_dial(&f, targets, num, now, key, server_pub, winner, sizeof(winner), &raced);
		coretest_check(up == false && raced == 2 && strcmp(winner, "quic") == 0 && fallback_count(&old_quic.Refused, 1),
		               "the first dial races both transports, QUIC wins, and the server refuses the handshake over it");

		up = fallback_dial(&f, targets, num, now, key, server_pub, winner, sizeof(winner), &raced);
		coretest_check(up && raced == 1 && strcmp(winner, "tls") == 0 && fallback_count(&tls_server.Sessions, 1) && fallback_count(&old_quic.Refused, 1),
		               "the next dial races the rest of the list: the session comes up over TLS-443 and echoes a record");

		coretest_check(TransportFallbackTargets(&f, targets, num, now + TRANSPORT_FALLBACK_HOLD - 1, list, TRANSPORT_MAX_TARGETS) == 1 && list[0].Transport == tls,
		               "QUIC stays out of the races until its hold is over");
		coretest_check(TransportFallbackTargets(&f, targets, num, now + TRANSPORT_FALLBACK_HOLD, list, TRANSPORT_MAX_TARGETS) == 2 && list[0].Transport == quic &&
		                   list[1].Transport == tls,
		               "... and comes back first after it, for a server that may have been upgraded");

		fallback_rules(quic, tls, targets, num);
	}

	fallback_stop(&old_quic);
	fallback_stop(&tls_server);
	TransportLoopbackFree(quic);
	TransportLoopbackFree(tls);
	SecureZeroMemory(key, sizeof(key));
	SecureZeroMemory(server, sizeof(server));
	SecureZeroMemory(other, sizeof(other));
}
