// fuzz_noise.c
// libFuzzer target: the parsers of the session module of the new core (src/Core/Noise.h, CORE-F2 #62), which read
// what a peer sends before and after the Noise handshake. Every input runs as:
// - the first handshake record that a server node reads (NoiseSessionAccept), on a session bound to a TLS exporter
//   and on an encrypted one, with the static key of the cacophony vector (coretest noise): a seed made with the
//   vector's keys gets through the whole message, its tokens and its payload;
// - the second handshake record that a client node reads (NoiseSessionFinish), after a first record of the
//   vector's keys and ephemeral key, so that a seed of the matching second record completes the handshake;
// - a stream of records into an open session, bound and encrypted, on both nodes: each record a 2-byte
//   big-endian size and the record; a control record that holds a Login is checked as the server's owner
//   checks it (NoiseLoginParse) and opens the data stream;
// - a Login (NoiseLoginParse).
// The sessions are those of the golden transcripts of coretest noisesession, so that their seeds decrypt.

#include "fuzz_common.h"

#include "Mayaqua/Memory.h"

#include "Core/Noise.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted (run_fuzzers.ps1 -max_len): longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		4096

// The keys of the cacophony IK vector: the client node and the server node of the goldens
static const char fuzz_client_static[] = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
static const char fuzz_client_ephemeral[] = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
static const char fuzz_server_static[] = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
static const char fuzz_server_ephemeral[] = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";
static const char fuzz_server_public[] = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";

// The keys and buffers of one run
typedef struct FUZZ_NOISE
{
	UCHAR ClientKey[NOISE_KEY_SIZE];
	UCHAR ClientEphemeral[NOISE_KEY_SIZE];
	UCHAR ServerKey[NOISE_KEY_SIZE];
	UCHAR ServerEphemeral[NOISE_KEY_SIZE];
	UCHAR ServerPub[NOISE_KEY_SIZE];
	UCHAR Exporter[NOISE_EXPORTER_SIZE];
	UCHAR Record[NOISE_MAX_RECORD];
	UCHAR Reply[NOISE_MAX_RECORD];
	UCHAR Data[NOISE_MAX_RECORD];
} FUZZ_NOISE;

static void FuzzUnhex(UCHAR *dst, const char *hex, UINT size)
{
	for (UINT i = 0;i < size;i++)
	{
		char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
		dst[i] = (UCHAR)strtoul(pair, NULL, 16);
	}
}

// The configuration of the client or the server node of the goldens: bound to the exporter 00 .. 1f, or encrypted
static void FuzzConfig(FUZZ_NOISE *f, NOISE_SESSION_CONFIG *c, bool server, bool encrypt)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->Flags = (encrypt ? NOISE_SESSION_ENCRYPT : 0);
	c->StaticKey = (server ? f->ServerKey : f->ClientKey);
	c->RemoteStatic = (server ? NULL : f->ServerPub);
	c->BindingType = (encrypt ? NOISE_BINDING_NONE : NOISE_BINDING_EXPORTER);
	c->Binding = (encrypt ? NULL : f->Exporter);
	c->BindingSize = (encrypt ? 0 : NOISE_EXPORTER_SIZE);
	c->RekeyRecords = 4;
	c->Ephemeral = (server ? f->ServerEphemeral : f->ClientEphemeral);
}

// The input as the first handshake record of a server node
static void FuzzAccept(FUZZ_NOISE *f, const UCHAR *data, UINT size, bool encrypt)
{
	NOISE_SESSION_CONFIG c;
	NOISE_SESSION s;
	UINT reply_size = 0;

	FuzzConfig(f, &c, true, encrypt);
	NoiseSessionAccept(&s, &c, 0, data, size, f->Reply, sizeof(f->Reply), &reply_size);
	NoiseSessionFree(&s);
}

// The input as the second handshake record of a client node
static void FuzzFinish(FUZZ_NOISE *f, const UCHAR *data, UINT size, bool encrypt)
{
	NOISE_SESSION_CONFIG c;
	NOISE_SESSION s;
	UINT record_size = 0;

	FuzzConfig(f, &c, false, encrypt);
	if (NoiseSessionConnect(&s, &c, 0, f->Record, sizeof(f->Record), &record_size))
	{
		NoiseSessionFinish(&s, 0, data, size);
	}
	NoiseSessionFree(&s);
}

// The input as a stream of records into one end of an open session
static void FuzzRecords(FUZZ_NOISE *f, NOISE_SESSION *s, const UCHAR *data, UINT size)
{
	UINT pos = 0;

	while (size - pos >= 2 && s->State == NOISE_STATE_OPEN)
	{
		UINT n = ((UINT)data[pos] << 8) | data[pos + 1];
		UINT data_size = 0;
		NOISE_LOGIN l;

		pos += 2;
		if (n > size - pos)
		{
			break;
		}

		// A copy of exactly n bytes: AddressSanitizer reports a read past the record
		UCHAR *record = malloc(n != 0 ? n : 1);
		if (record == NULL)
		{
			break;
		}
		memcpy(record, data + pos, n);
		pos += n;

		UINT ret = NoiseSessionReceive(s, 1000, record, n, f->Data, sizeof(f->Data), &data_size);
		free(record);

		if (ret == NOISE_RECEIVE_CONTROL && NoiseLoginParse(&l, f->Data, data_size))
		{
			NoiseSessionAcceptLogin(s);
		}
	}
}

// An open session of the goldens: the client node and the server node in memory
static bool FuzzOpen(FUZZ_NOISE *f, NOISE_SESSION *client, NOISE_SESSION *server, bool encrypt)
{
	NOISE_SESSION_CONFIG cc, sc;
	UINT size = 0, reply_size = 0;

	FuzzConfig(f, &cc, false, encrypt);
	FuzzConfig(f, &sc, true, encrypt);

	return NoiseSessionConnect(client, &cc, 0, f->Record, sizeof(f->Record), &size) &&
		NoiseSessionAccept(server, &sc, 0, f->Record, size, f->Reply, sizeof(f->Reply), &reply_size) &&
		NoiseSessionFinish(client, 0, f->Reply, reply_size);
}

// One input: the handshake records, the record streams and the Login
static void FuzzNoise(const uint8_t *data, size_t size)
{
	FUZZ_NOISE *f;
	NOISE_LOGIN l;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past the
	// end of the input
	UCHAR *in = malloc(size);
	f = calloc(1, sizeof(FUZZ_NOISE));
	if (in == NULL || f == NULL)
	{
		free(in);
		free(f);
		return;
	}
	memcpy(in, data, size);

	FuzzUnhex(f->ClientKey, fuzz_client_static, NOISE_KEY_SIZE);
	FuzzUnhex(f->ClientEphemeral, fuzz_client_ephemeral, NOISE_KEY_SIZE);
	FuzzUnhex(f->ServerKey, fuzz_server_static, NOISE_KEY_SIZE);
	FuzzUnhex(f->ServerEphemeral, fuzz_server_ephemeral, NOISE_KEY_SIZE);
	FuzzUnhex(f->ServerPub, fuzz_server_public, NOISE_KEY_SIZE);
	for (UINT i = 0;i < NOISE_EXPORTER_SIZE;i++)
	{
		f->Exporter[i] = (UCHAR)i;
	}

	for (UINT e = 0;e < 2;e++)
	{
		NOISE_SESSION client, server;

		Zero(&client, sizeof(client));
		Zero(&server, sizeof(server));
		FuzzAccept(f, in, (UINT)size, e != 0);
		FuzzFinish(f, in, (UINT)size, e != 0);

		if (FuzzOpen(f, &client, &server, e != 0))
		{
			FuzzRecords(f, &server, in, (UINT)size);
			FuzzRecords(f, &client, in, (UINT)size);
		}
		NoiseSessionFree(&client);
		NoiseSessionFree(&server);
	}

	NoiseLoginParse(&l, in, (UINT)size);

	SecureZeroMemory(f, sizeof(FUZZ_NOISE));
	free(f);
	free(in);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNoise, data, size);

	return 0;
}
