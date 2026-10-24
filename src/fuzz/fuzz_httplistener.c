// fuzz_httplistener.c
// libFuzzer target: the HTTP responder of the HTTP listener (Cedar/HttpListener.c, REL-6 #51).
//
// The input is the bytes a client sends on one connection. As the listener answers it: HttpListenerParse (the header
// reader of Mayaqua, HttpParseHeaderLines), then HttpListenerRespond and HttpListenerResponseToBuf. The challenge lookup
// serves one fixed token from memory, the VPN listener ports are fixed. The answer must keep its shape whatever the
// request holds: one status line and the header lines of the responder only, so that no request adds a header line
// (abort() otherwise). Seeds: the requests of the vpntest test httplistener.
//
// The largest input is above HTTP_LISTENER_MAX_REQUEST (16384), so that a request over that limit is reached
// fuzz-max-len: 20480

#include "fuzz_common.h"

#include "Cedar/HttpListener.h"

#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"

#include <stdlib.h>
#include <string.h>

#define	FUZZ_HTTPLISTENER_TOKEN		"fuzz-token_0123456789abcdef"	// The token of the one challenge
#define	FUZZ_HTTPLISTENER_BODY		"fuzz-token_0123456789abcdef.thumbprint"

// The header lines an answer may have after its status line
static const char *fuzz_httplistener_headers[] =
{
	"Location: ",
	"Allow: ",
	"Content-Type: ",
	"Content-Length: ",
	"Connection: ",
};

// The challenge lookup of the target: one token with a fixed body, every other token unknown
static BUF *FuzzHttpListenerLookup(void *param, char *token)
{
	if (strcmp(token, FUZZ_HTTPLISTENER_TOKEN) != 0)
	{
		return NULL;
	}

	return NewBufFromMemory(FUZZ_HTTPLISTENER_BODY, (UINT)strlen(FUZZ_HTTPLISTENER_BODY));
}

// Whether a header line of an answer starts with one of the header names of the responder
static bool FuzzHttpListenerKnownHeader(const char *line, size_t len)
{
	for (size_t i = 0;i < sizeof(fuzz_httplistener_headers) / sizeof(fuzz_httplistener_headers[0]);i++)
	{
		size_t n = strlen(fuzz_httplistener_headers[i]);

		if (len >= n && memcmp(line, fuzz_httplistener_headers[i], n) == 0)
		{
			return true;
		}
	}

	return false;
}

// The shape of an answer: "HTTP/1.1 " and a status line, then known header lines up to the blank line, each line ended
// by CR LF with no other CR, LF or NUL in the header part
static void FuzzHttpListenerCheck(BUF *b)
{
	const char *data = (const char *)b->Buf;
	size_t size = b->Size;
	size_t start = 0;
	bool first = true;

	if (size < 9 || memcmp(data, "HTTP/1.1 ", 9) != 0)
	{
		abort();
	}

	while (true)
	{
		size_t end = start;

		while (end + 1 < size && (data[end] != '\r' || data[end + 1] != '\n'))
		{
			if (data[end] == '\r' || data[end] == '\n' || data[end] == 0)
			{
				abort();
			}

			end++;
		}

		if (end + 1 >= size)
		{
			// No blank line ends the header part
			abort();
		}

		if (end == start)
		{
			break;
		}

		if (first == false && FuzzHttpListenerKnownHeader(data + start, end - start) == false)
		{
			abort();
		}

		first = false;
		start = end + 2;
	}
}

// One input: the bytes of a connection
static void FuzzHttpListener(const uint8_t *data, size_t size)
{
	BUF *b = FuzzNewBuf(data, size);
	HTTP_HEADER *request = NULL;
	UINT ports[] = {39555, 5555};

	if (HttpListenerParse(b, &request) == HTTP_LISTENER_PARSE_DONE)
	{
		HTTP_LISTENER_RESPONSE *r = HttpListenerRespond(request, FuzzHttpListenerLookup, NULL, ports, 2);
		BUF *out = HttpListenerResponseToBuf(r);

		FuzzHttpListenerCheck(out);

		FreeBuf(out);
		FreeHttpListenerResponse(r);
	}

	FreeHttpHeader(request);
	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzHttpListener, data, size);

	return 0;
}
