#include "HTTP.h"

#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

#include <winhttp.h>

static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";

// A decoy page: what a plain web server answers to an HTTP client that is not a VPN client
typedef struct HTTP_DECOY_PAGE
{
	UINT Code;
	char *Reason;
	char *Template;
	bool NamesMethod;		// The page names the method and the version of the request
} HTTP_DECOY_PAGE;

static HTTP_DECOY_PAGE http_decoy_pages[] =
{
	{403, "Forbidden", http_403_str, false},
	{404, "Not Found", http_404_str, false},
	{501, "Method Not Implemented", http_501_str, true},
};

// The HTTP date of t (system time) for a Date header, as "Sun, 06 Nov 1994 08:49:37 GMT"
static void GetHttpDateStr(char *str, UINT size, UINT64 t)
{
	SYSTEMTIME st;
	wchar_t tmp[WINHTTP_TIME_FORMAT_BUFSIZE / sizeof(wchar_t)];

	UINT64ToSystem(&st, t);
	if (WinHttpTimeFromSystemTime(&st, tmp) == FALSE)
	{
		StrCpy(str, size, "");
		return;
	}

	UniToStr(str, size, tmp);
}

// A new HTTP header with the given start line and the headers every message of the VPN server and client
// carries: Date, Host when host is not NULL, Keep-Alive, Connection and Content-Type
static HTTP_HEADER *NewHttpHeaderKeepAlive(char *method, char *target, char *version, char *host, char *content_type)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];

	h = NewHttpHeader(method, target, version);

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	if (host != NULL)
	{
		AddHttpValue(h, NewHttpValue("Host", host));
	}
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", content_type));

	return h;
}

static void ReplaceUnsafeCharInHttpTarget(char *target)
{
	UINT i;
	for(i = 0; target[i] ; i++) {
		if(target[i] == '<')
			target[i] = '(';
		else if(target[i] == '>')
			target[i] = ')';
	}
}

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

// Send p as the body of an HTTP message with the given start line; host, when not NULL, goes in a Host header
static bool HttpSendPack(SOCK *s, PACK *p, char *method, char *target, char *version, char *host)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeaderKeepAlive(method, target, version, host, HTTP_CONTENT_TYPE2);

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// Read the Pack body of a received HTTP message whose start line the caller has checked, and free h. A
// Content-Type other than HTTP_CONTENT_TYPE2, an empty body or a Content-Length above max_data_size is
// refused before the body is read or anything is allocated for it.
static PACK *HttpRecvPackBody(SOCK *s, HTTP_HEADER *h, UINT max_data_size)
{
	BUF *b;
	PACK *p;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	size = GetContentLength(h);
	FreeHttpHeader(h);
	if (size == 0 || size > max_data_size)
	{
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	return p;
}

bool HttpClientSend(SOCK *s, PACK *p)
{
	char ip_str[MAX_SIZE];

	if (s == NULL || p == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	return HttpSendPack(s, p, "POST", HTTP_VPN_TARGET, "HTTP/1.1", ip_str);
}

// Receive a Pack of up to MAX_PACK_SIZE from the server (the answer to the admin RPC login)
PACK *HttpClientRecv(SOCK *s)
{
	return HttpClientRecvEx(s, MAX_PACK_SIZE);
}

// Receive a Pack from the server. A Content-Length above max_data_size is refused before the body is
// read or anything is allocated for it.
PACK *HttpClientRecvEx(SOCK *s, UINT max_data_size)
{
	PACK *p;
	HTTP_HEADER *h;
	UINT num_noop = 0;
	if (s == NULL)
	{
		return NULL;
	}

START:
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return NULL;
	}

	if (StrCmpi(h->Method, "HTTP/1.1") != 0 ||
		StrCmpi(h->Target, "200") != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	p = HttpRecvPackBody(s, h, max_data_size);
	if (p == NULL)
	{
		return NULL;
	}

	// Client shouldn't receive a noop other than NOOP_IGNORE
	// because it can't respond without a full new HTTP request
	UINT noop = PackGetInt(p, "noop");
	if (noop == NOOP_IGNORE) {
		FreePack(p);

		num_noop++;

		if (num_noop > MAX_NOOP_PER_SESSION)
		{
			return NULL;
		}

		goto START;
	}
	return p;
}

bool HttpServerSend(SOCK *s, PACK *p)
{
	if (s == NULL || p == NULL)
	{
		return false;
	}

	return HttpSendPack(s, p, "HTTP/1.1", "200", "OK", NULL);
}

// Receive a Pack of up to HTTP_PACK_MAX_SIZE from the client
PACK *HttpServerRecv(SOCK *s)
{
	PACK *p;
	HTTP_HEADER *h;
	UINT num_noop = 0;
	if (s == NULL)
	{
		return NULL;
	}

START:
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return NULL;
	}

	if (StrCmpi(h->Method, "POST") != 0 ||
		StrCmpi(h->Target, HTTP_VPN_TARGET) != 0 ||
		StrCmpi(h->Version, "HTTP/1.1") != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	p = HttpRecvPackBody(s, h, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
	{
		return NULL;
	}

	UINT noop = PackGetInt(p, "noop");
	if (noop == NOOP)
	{
		FreePack(p);

		p = PackError(0);
		PackAddInt(p, "noop", NOOP_IGNORE);
		if (HttpServerSend(s, p) == false)
		{
			FreePack(p);
			return NULL;
		}

		FreePack(p);

		num_noop++;

		if (num_noop > MAX_NOOP_PER_SESSION)
		{
			return NULL;
		}

		goto START;
	} else if (noop == NOOP_IGNORE) {
		FreePack(p);

		goto START;
	}

	return p;
}

// Send the decoy page of the given status code (403, 404 or 501) as the answer to request. The page names
// the requested target, with its '<' and '>' replaced in request, and the 501 page also the method and
// the version.
bool HttpSendDecoyPage(SOCK *s, UINT code, HTTP_HEADER *request)
{
	HTTP_DECOY_PAGE *page = NULL;
	HTTP_HEADER *h;
	char code_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT i;
	if (s == NULL || request == NULL)
	{
		return false;
	}

	for (i = 0; i < sizeof(http_decoy_pages) / sizeof(http_decoy_pages[0]); i++)
	{
		if (http_decoy_pages[i].Code == code)
		{
			page = &http_decoy_pages[i];
			break;
		}
	}
	if (page == NULL)
	{
		return false;
	}

	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);

	ToStr(code_str, code);
	h = NewHttpHeaderKeepAlive("HTTP/1.1", code_str, page->Reason, NULL, HTTP_CONTENT_TYPE);

	str_size = (StrLen(page->Template) + 1) * 2 + StrLen(request->Target) + StrLen(host);
	if (page->NamesMethod)
	{
		str_size += StrLen(request->Method) + StrLen(request->Version);
	}
	str = Malloc(str_size);
	StrCpy(str, str_size, page->Template);

	ReplaceUnsafeCharInHttpTarget(request->Target);
	ReplaceStri(str, str_size, str, "$TARGET$", request->Target);

	ReplaceStri(str, str_size, str, "$HOST$", host);

	ToStr(port_str, s->LocalPort);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	if (page->NamesMethod)
	{
		ReplaceStri(str, str_size, str, "$METHOD$", request->Method);

		ReplaceStri(str, str_size, str, "$VERSION$", request->Version);
	}

	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
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
