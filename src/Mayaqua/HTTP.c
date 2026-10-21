#include "HTTP.h"

#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

#include <winhttp.h>

HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version)
{
	HTTP_HEADER *header;
	if (method == NULL || target == NULL || version == NULL)
	{
		return NULL;
	}

	header = ZeroMalloc(sizeof(HTTP_HEADER));

	header->Method = CopyStr(method);
	header->Target = CopyStr(target);
	header->Version = CopyStr(version);
	header->ValueList = NewListFast(CompareHttpValue);

	return header;
}

void FreeHttpHeader(HTTP_HEADER *header)
{
	UINT i;
	HTTP_VALUE **values;
	if (header == NULL)
	{
		return;
	}

	Free(header->Method);
	Free(header->Target);
	Free(header->Version);

	values = ToArray(header->ValueList);
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		FreeHttpValue(values[i]);
	}
	Free(values);

	ReleaseList(header->ValueList);

	Free(header);
}

HTTP_VALUE *NewHttpValue(char *name, char *data)
{
	HTTP_VALUE *v;
	if (name == NULL || data == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(HTTP_VALUE));

	v->Name = CopyStr(name);
	v->Data = CopyStr(data);

	Trim(v->Name);
	Trim(v->Data);

	return v;
}

void FreeHttpValue(HTTP_VALUE *value)
{
	if (value == NULL)
	{
		return;
	}

	Free(value->Data);
	Free(value->Name);

	Free(value);
}

int CompareHttpValue(void *p1, void *p2)
{
	HTTP_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(HTTP_VALUE **)p1;
	v2 = *(HTTP_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name)
{
	HTTP_VALUE *v, t;
	if (header == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	v = Search(header->ValueList, &t);
	if (v == NULL)
	{
		return NULL;
	}

	return v;
}

void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value)
{
	if (header == NULL || value == NULL)
	{
		return;
	}

	if (LIST_NUM(header->ValueList) < HTTP_HEADER_MAX_LINES)
	{
		Insert(header->ValueList, value);
	}
	else
	{
		FreeHttpValue(value);
	}
}

bool AddHttpValueStr(HTTP_HEADER* header, char *string)
{
	HTTP_VALUE *value = NULL;
	UINT pos = 0;
	char *value_name = NULL;
	char *value_data = NULL;

	if (header == NULL || IsEmptyStr(string))
	{
		return false;
	}

	EnSafeHttpHeaderValueStr(string, ' ');

	pos = SearchStr(string, ":", 0);
	if (pos == INFINITE)
	{
		return false;
	}

	if ((pos + 1) >= StrLen(string))
	{
		return false;
	}

	value_name = Malloc(pos + 1);
	Copy(value_name, string, pos);
	value_name[pos] = 0;
	value_data = &string[pos + 1];

	value = NewHttpValue(value_name, value_data);
	if (value == NULL)
	{
		Free(value_name);
		return false;
	}

	Free(value_name);

	AddHttpValue(header, value);

	return true;
}

UINT GetContentLength(HTTP_HEADER *header)
{
	UINT ret;
	HTTP_VALUE *v;
	if (header == NULL)
	{
		return 0;
	}

	v = GetHttpValue(header, "Content-Length");
	if (v == NULL)
	{
		return 0;
	}

	ret = ToInt(v->Data);

	return ret;
}

bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size)
{
	char *header_str;
	BUF *b;
	bool ret;
	if (s == NULL || header == NULL || (post_size != 0 && post_data == NULL))
	{
		return false;
	}

	if (GetHttpValue(header, "Content-Length") == NULL)
	{
		char tmp[MAX_SIZE];
		ToStr(tmp, post_size);
		AddHttpValue(header, NewHttpValue("Content-Length", tmp));
	}

	header_str = HttpHeaderToStr(header);
	if (header_str == NULL)
	{
		return false;
	}
	b = NewBuf();
	WriteBuf(b, header_str, StrLen(header_str));
	Free(header_str);

	WriteBuf(b, post_data, post_size);

	ret = SendAll(s, b->Buf, b->Size, s->SecureMode);

	FreeBuf(b);

	return ret;
}

char *HttpHeaderToStr(HTTP_HEADER *header)
{
	BUF *b;
	char *tmp;
	UINT i;
	char *s;
	if (header == NULL)
	{
		return NULL;
	}

	tmp = Malloc(HTTP_HEADER_LINE_MAX_SIZE);
	b = NewBuf();

	Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
		"%s %s %s\r\n", header->Method, header->Target, header->Version);
	WriteBuf(b, tmp, StrLen(tmp));

	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		HTTP_VALUE *v = (HTTP_VALUE *)LIST_DATA(header->ValueList, i);
		Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
			"%s: %s\r\n", v->Name, v->Data);
		WriteBuf(b, tmp, StrLen(tmp));
	}

	WriteBuf(b, "\r\n", 2);
	s = Malloc(b->Size + 1);
	Copy(s, b->Buf, b->Size);
	s[b->Size] = 0;

	FreeBuf(b);
	Free(tmp);

	return s;
}

bool SendHttpHeader(SOCK *s, HTTP_HEADER *header)
{
	char *str;
	bool ret;
	if (s == NULL || header == NULL)
	{
		return false;
	}

	str = HttpHeaderToStr(header);

	ret = SendAll(s, str, StrLen(str), s->SecureMode);

	Free(str);

	return ret;
}

// Line source over a SOCK (param): RecvLine()
static char *HttpSockLineSource(void *param, UINT max_size)
{
	return RecvLine((SOCK *)param, max_size);
}

// Line source over a BUF (param), read from b->Current on: the next line exactly as RecvLine()
// returns it when the peer sends the remaining bytes and then closes. The bytes up to '\n',
// without the '\n' and without one '\r' before it, in a Malloc() block. NULL at the end of the
// buffer before '\n', and when more than max_size bytes, '\n' included, were consumed without
// completing the line.
char *HttpBufLineSource(void *param, UINT max_size)
{
	BUF *b = (BUF *)param;
	UCHAR *data;
	UINT start;
	UINT i;
	if (b == NULL || max_size == 0)
	{
		return NULL;
	}

	data = (UCHAR *)b->Buf;
	start = b->Current;

	for (i = start;i < b->Size;i++)
	{
		UINT consumed = i - start + 1;

		if (consumed > max_size)
		{
			b->Current = i + 1;
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
			Copy(str, data + start, len);
			str[len] = 0;

			b->Current = i + 1;
			return str;
		}
	}

	b->Current = b->Size;
	return NULL;
}

// Parses an HTTP header from the lines that source returns: the request or status line, then
// the header lines up to the blank line (none for HTTP/0.9). NULL when a line cannot be read
// (a NULL line is not the blank line that ends the header) or does not parse.
HTTP_HEADER *HttpParseHeaderLines(HTTP_LINE_SOURCE *source, void *param)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	if (source == NULL)
	{
		return NULL;
	}

	str = source(param, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		return NULL;
	}

	token = ParseToken(str, " ");

	FreeSafe(PTR_TO_PTR(str));

	if (token == NULL)
	{
		return NULL;
	}

	if (token->NumTokens < 3)
	{
		FreeToken(token);
		return NULL;
	}

	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);
	FreeToken(token);

	if (StrCmpi(header->Version, "HTTP/0.9") == 0)
	{
		return header;
	}

	while (true)
	{
		str = source(param, HTTP_HEADER_LINE_MAX_SIZE);
		if (str == NULL)
		{
			// Socket error, timeout or an oversized line: not the blank line that ends the header
			FreeHttpHeader(header);
			return NULL;
		}

		Trim(str);
		if (IsEmptyStr(str))
		{
			FreeSafe(PTR_TO_PTR(str));
			break;
		}

		if (AddHttpValueStr(header, str) == false)
		{
			FreeSafe(PTR_TO_PTR(str));
			FreeHttpHeader(header);
			header = NULL;
			break;
		}

		FreeSafe(PTR_TO_PTR(str));
	}

	return header;
}

HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	if (s == NULL)
	{
		return NULL;
	}

	return HttpParseHeaderLines(HttpSockLineSource, s);
}

char *RecvLine(SOCK *s, UINT max_size)
{
	BUF *b;
	char c;
	char *str;
	if (s == NULL || max_size == 0)
	{
		return NULL;
	}

	b = NewBuf();
	while (true)
	{
		UCHAR *buf;
		if (RecvAll(s, &c, sizeof(c), s->SecureMode) == false)
		{
			FreeBuf(b);
			return NULL;
		}
		WriteBuf(b, &c, sizeof(c));
		buf = (UCHAR *)b->Buf;
		if (b->Size > max_size)
		{
			FreeBuf(b);
			return NULL;
		}
		if (b->Size >= 1)
		{
			if (buf[b->Size - 1] == '\n')
			{
				b->Size--;
				if (b->Size >= 1)
				{
					if (buf[b->Size - 1] == '\r')
					{
						b->Size--;
					}
				}
				str = Malloc(b->Size + 1);
				Copy(str, b->Buf, b->Size);
				str[b->Size] = 0;
				FreeBuf(b);

				return str;
			}
		}
	}
}
