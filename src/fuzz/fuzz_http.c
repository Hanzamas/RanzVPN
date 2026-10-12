// fuzz_http.c
// libFuzzer target: HTTP header parsing of the SE-VPN handshake.
//
// RecvHttpHeader() (Mayaqua/HTTP.c) reads its lines from a SOCK with RecvLine() and has no
// buffer-based variant. This target runs the same steps over the input instead: FuzzRecvLine()
// splits lines exactly like RecvLine(), and the loop below is RecvHttpHeader()'s loop, calling
// the same buffer-level parsers (ParseToken, NewHttpHeader, AddHttpValueStr). The socket reads
// themselves are not covered. This copy must change with RecvHttpHeader() (a note there points
// here) until RecvHttpHeader() reads its lines through a callback that a BUF can also serve.

#include "fuzz_common.h"

#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

// One line as RecvLine(s, max_size) returns it: the bytes up to '\n', without the '\n' and
// without one '\r' before it, in a Malloc() block. NULL at the end of the input (RecvLine()
// fails when the peer closes before '\n') and when more than max_size bytes, '\n' included,
// were consumed without completing the line.
static char *FuzzRecvLine(const uint8_t *data, size_t size, size_t *pos, UINT max_size)
{
	size_t start = *pos;
	size_t i;

	for (i = start;i < size;i++)
	{
		UINT consumed = (UINT)(i - start + 1);

		if (consumed > max_size)
		{
			*pos = i + 1;
			return NULL;
		}

		if (data[i] == '\n')
		{
			UINT len = consumed - 1;
			char *str;

			if (len >= 1 && data[start + len - 1] == '\r')
			{
				len--;
			}

			str = Malloc(len + 1);
			Copy(str, (void *)(data + start), len);
			str[len] = 0;

			*pos = i + 1;
			return str;
		}
	}

	*pos = size;
	return NULL;
}

// One HTTP header input
static void FuzzHttp(const uint8_t *data, size_t size)
{
	size_t pos = 0;
	char *str;
	TOKEN_LIST *token;
	HTTP_HEADER *header;

	// RecvHttpHeader(): request or status line
	str = FuzzRecvLine(data, size, &pos, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		return;
	}

	token = ParseToken(str, " ");
	Free(str);

	if (token == NULL)
	{
		return;
	}

	if (token->NumTokens < 3)
	{
		FreeToken(token);
		return;
	}

	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);
	FreeToken(token);

	// RecvHttpHeader(): header lines up to the empty line, except for HTTP/0.9
	if (StrCmpi(header->Version, "HTTP/0.9") != 0)
	{
		while (true)
		{
			str = FuzzRecvLine(data, size, &pos, HTTP_HEADER_LINE_MAX_SIZE);
			Trim(str);
			if (IsEmptyStr(str))
			{
				Free(str);
				break;
			}

			if (AddHttpValueStr(header, str) == false)
			{
				Free(str);
				FreeHttpHeader(header);
				header = NULL;
				break;
			}

			Free(str);
		}
	}

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
