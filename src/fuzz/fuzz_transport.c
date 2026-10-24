// fuzz_transport.c
// libFuzzer target: the parsers of the transport module of the new core (src/Core/Transport.h, CORE-F4 #64), which
// read the configured fallback list of a client and what a peer sends on a stream. Every input runs as:
// - the text of a fallback list (TransportParseList), with the transports of ADR-0005 known: "quic", "tls" and
//   "cdn";
// - the bytes that a server node reads from a stream without a channel binding, once as they come and once a byte at
//   a time: the frame of the first handshake record (TransportNoiseAccept), then the frames of the records of the
//   session, which the stream's lack of a binding encrypts (TransportNoiseReceive), each frame the size of its record
//   in 4 bytes (big-endian) and the record. A control record that holds a Login is checked as the server's owner
//   checks it (NoiseLoginParse) and opens the data stream;
// - the first records that a TLS client of the TLS transport reads from a server (TransportTlsParseHello, CORE-S2-1
//   #69): what it takes from a ServerHello must be a version it knows;
// - the first bytes that a server with a decoy reads after the TLS handshake (TransportDecoyIsHandshake and
//   TransportDecoyAuthenticate, CORE-S2-2 #70), and a client's ClientHello whose server name a split cuts
//   (TransportTlsHelloName): a frame that authenticates has the shape of one, and a name lies within the bytes.
// The server node has the static key and the ephemeral key of the cacophony IK vector, as in fuzz_noise.c, so that
// the frames of the encrypted golden records of coretest noisesession get through the handshake and decrypt.
//
// fuzz-max-len: 4096
// fuzz-libs: coretransport corenoise corecrypto

#include "fuzz_common.h"

#include "Core/Transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Largest input accepted (fuzz-max-len above, for run_fuzzers.ps1): longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		4096

// The keys of the server node of the cacophony IK vector (fuzz_noise.c)
static const char fuzz_server_static[] = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
static const char fuzz_server_ephemeral[] = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

// The stream that the server node reads: the bytes of the input, Step at a time at most, then its end
typedef struct FUZZ_STREAM
{
	const UCHAR *Data;
	UINT Size;
	UINT Pos;
	UINT Step;
} FUZZ_STREAM;

// The keys and the payload buffer of one run
typedef struct FUZZ_TRANSPORT
{
	UCHAR ServerKey[NOISE_KEY_SIZE];
	UCHAR ServerEphemeral[NOISE_KEY_SIZE];
	UCHAR Data[NOISE_MAX_PAYLOAD];
} FUZZ_TRANSPORT;

static void FuzzUnhex(UCHAR *dst, const char *hex, UINT size)
{
	for (UINT i = 0;i < size;i++)
	{
		char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
		dst[i] = (UCHAR)strtoul(pair, NULL, 16);
	}
}

// A property of the module that does not hold: libFuzzer saves the input, with no abort message box and no Windows
// Error Reporting (as FuzzRun in fuzz_common.c)
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// The procedures of the stream's transport: Dial gives the stream of its Param, Read the next bytes of the input or
// the end, Write takes the records of the server node and sends them nowhere
static bool FuzzStreamDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	*stream = param;

	return true;
}

static UINT FuzzStreamRead(void *stream, void *buf, UINT size, UINT timeout)
{
	FUZZ_STREAM *s = (FUZZ_STREAM *)stream;
	UINT n = s->Size - s->Pos;

	if (n == 0)
	{
		return 0;
	}
	if (n > size)
	{
		n = size;
	}
	if (n > s->Step)
	{
		n = s->Step;
	}

	memcpy(buf, s->Data + s->Pos, n);
	s->Pos += n;

	return n;
}

static bool FuzzStreamWrite(void *stream, const void *buf, UINT size)
{
	return true;
}

static void FuzzStreamClose(void *stream)
{
}

// The input as the text of a fallback list
static void FuzzList(const UCHAR *data, UINT size)
{
	static TRANSPORT quic = {"quic"};
	static TRANSPORT tls = {"tls"};
	static TRANSPORT cdn = {"cdn"};
	TRANSPORT *known[3] = {&quic, &tls, &cdn};
	TRANSPORT_TARGET targets[TRANSPORT_MAX_TARGETS];

	// A copy of exactly the input and its terminator: AddressSanitizer reports a read past the end of the text
	char *list = malloc(size + 1);
	if (list == NULL)
	{
		return;
	}
	memcpy(list, data, size);
	list[size] = 0;

	UINT num = TransportParseList(list, known, 3, targets, TRANSPORT_MAX_TARGETS);
	free(list);

	// Every entry it gives is one of the known transports and an address with its terminator
	if (num > TRANSPORT_MAX_TARGETS)
	{
		FuzzFail("TransportParseList gave more entries than it may");
	}
	for (UINT i = 0;i < num;i++)
	{
		if (targets[i].Transport == NULL || memchr(targets[i].Address, 0, sizeof(targets[i].Address)) == NULL)
		{
			FuzzFail("TransportParseList gave an entry without a transport or an unterminated address");
		}
	}
}

// The input as the first records that a TLS client reads from a server: a ServerHello it takes has a version it knows,
// and a group only with TLS 1.3
static void FuzzHello(const UCHAR *data, UINT size)
{
	TRANSPORT_TLS_INFO info;

	memset(&info, 0, sizeof(info));
	if (TransportTlsParseHello(data, size, &info) == false)
	{
		return;
	}

	if (info.Version != TRANSPORT_TLS_12 && info.Version != TRANSPORT_TLS_13)
	{
		FuzzFail("TransportTlsParseHello took a ServerHello of a version it does not know");
	}
	if (info.Version == TRANSPORT_TLS_12 && info.Group != 0)
	{
		FuzzFail("TransportTlsParseHello gave a group of TLS 1.2");
	}
}

// The input as the first bytes a server with a decoy reads after the TLS handshake: TransportDecoyIsHandshake tells a
// valid Ranz handshake frame from a prober's first bytes, and reads no further than size bytes; TransportDecoyAuthenticate
// reads the Noise message of such a frame with the server node's key and a binding of zeros
static void FuzzDecoy(FUZZ_TRANSPORT *f, const UCHAR *data, UINT size)
{
	UCHAR binding[NOISE_EXPORTER_SIZE];
	bool shape = TransportDecoyIsHandshake(data, size);

	memset(binding, 0, sizeof(binding));
	if (TransportDecoyAuthenticate(data, size, f->ServerKey, NULL, NOISE_BINDING_EXPORTER, binding, sizeof(binding)) && shape == false)
	{
		FuzzFail("TransportDecoyAuthenticate took a frame that TransportDecoyIsHandshake does not");
	}

	if (shape == false)
	{
		return;
	}

	// A frame it takes has at least a header, a record type and a suite, and a length no bigger than the bytes read
	if (size < TRANSPORT_FRAME_HEADER + 2)
	{
		FuzzFail("TransportDecoyIsHandshake took fewer bytes than a frame header and a record type and suite");
	}
	else
	{
		UINT length = ((UINT)data[0] << 24) | ((UINT)data[1] << 16) | ((UINT)data[2] << 8) | data[3];

		if ((UINT64)TRANSPORT_FRAME_HEADER + length > size)
		{
			FuzzFail("TransportDecoyIsHandshake took a frame whose record is not all there");
		}
	}
}

// The input as a client's first token, a ClientHello in a TLS record: the server name that TransportTlsHelloName finds
// has at least one byte and lies within the input
static void FuzzHelloName(const UCHAR *data, UINT size)
{
	UINT offset = 0, length = 0;

	if (TransportTlsHelloName(data, size, &offset, &length) == false)
	{
		return;
	}

	if (length == 0 || (UINT64)offset + length > size)
	{
		FuzzFail("TransportTlsHelloName gave a server name that is empty or not within the ClientHello");
	}
}

// The input as what a server node reads from a stream, step bytes at a time at most
static void FuzzStream(FUZZ_TRANSPORT *f, const UCHAR *data, UINT size, UINT step)
{
	FUZZ_STREAM stream;
	TRANSPORT t;
	TRANSPORT_NOISE n;
	NOISE_SESSION_CONFIG c;
	NOISE_LOGIN l;

	memset(&stream, 0, sizeof(stream));
	stream.Data = data;
	stream.Size = size;
	stream.Step = step;

	memset(&t, 0, sizeof(t));
	strcpy_s(t.Name, sizeof(t.Name), "fuzz");
	t.Param = &stream;
	t.Dial = FuzzStreamDial;
	t.Read = FuzzStreamRead;
	t.Write = FuzzStreamWrite;
	t.Close = FuzzStreamClose;

	// The server node of the goldens, rekey after 4 records as there
	memset(&c, 0, sizeof(c));
	c.Suite = NOISE_SUITE_IK;
	c.StaticKey = f->ServerKey;
	c.RekeyRecords = 4;
	c.Ephemeral = f->ServerEphemeral;

	// A failed handshake closes the stream
	if (TransportNoiseAccept(&n, TransportDial(&t, "client", NULL), &c, 0) == false)
	{
		return;
	}

	while (true)
	{
		UINT data_size = 0;
		UINT ret = TransportNoiseReceive(&n, f->Data, sizeof(f->Data), &data_size, 0);

		if (ret == NOISE_RECEIVE_ERROR || ret == NOISE_RECEIVE_CLOSE)
		{
			break;
		}
		if (ret == NOISE_RECEIVE_CONTROL && NoiseLoginParse(&l, f->Data, data_size))
		{
			TransportNoiseAcceptLogin(&n);
		}
	}

	TransportNoiseClose(&n);
}

// One input: the fallback list, the stream as it comes and a byte at a time, then the records of a TLS server
static void FuzzTransport(const uint8_t *data, size_t size)
{
	FUZZ_TRANSPORT *f;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past the
	// end of the input
	UCHAR *in = malloc(size);
	f = calloc(1, sizeof(FUZZ_TRANSPORT));
	if (in == NULL || f == NULL)
	{
		free(in);
		free(f);
		return;
	}
	memcpy(in, data, size);

	FuzzUnhex(f->ServerKey, fuzz_server_static, NOISE_KEY_SIZE);
	FuzzUnhex(f->ServerEphemeral, fuzz_server_ephemeral, NOISE_KEY_SIZE);

	FuzzList(in, (UINT)size);
	FuzzStream(f, in, (UINT)size, (UINT)size);
	FuzzStream(f, in, (UINT)size, 1);
	FuzzHello(in, (UINT)size);
	FuzzDecoy(f, in, (UINT)size);
	FuzzHelloName(in, (UINT)size);

	SecureZeroMemory(f, sizeof(FUZZ_TRANSPORT));
	free(f);
	free(in);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzTransport, data, size);

	return 0;
}
