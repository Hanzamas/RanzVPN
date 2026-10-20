// fuzz_http.c
// libFuzzer target: HTTP header parsing of the SE-VPN handshake.
//
// RecvHttpHeader() (Mayaqua/HTTP.c) is HttpParseHeaderLines() over a SOCK line source. This
// target runs the same HttpParseHeaderLines() over the input with the BUF line source
// HttpBufLineSource(), which splits lines exactly like RecvLine(). The socket reads themselves
// are not covered.

#include "fuzz_common.h"

#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"

// One HTTP header input
static void FuzzHttp(const uint8_t *data, size_t size)
{
	BUF *b = FuzzNewBuf(data, size);
	HTTP_HEADER *header;

	header = HttpParseHeaderLines(HttpBufLineSource, b);

	FreeBuf(b);

	if (header != NULL)
	{
		// What the server and the client read from a received header, then the encoder
		char *s;

		GetContentLength(header);
		GetHttpValue(header, "Content-Type");
		GetHttpValue(header, "Connection");

		s = HttpHeaderToStr(header);
		Free(s);

		FreeHttpHeader(header);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzHttp, data, size);

	return 0;
}
