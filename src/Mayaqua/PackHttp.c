

#include "HTTP.h"

#include "Internat.h"
#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

#include <winhttp.h>
#include "HTTPInternal.h"

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
	for(UINT i = 0; target[i] ; i++) {
		if(target[i] == '<')
			target[i] = '(';
		else if(target[i] == '>')
			target[i] = ')';
	}
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
	if (s == NULL || request == NULL)
	{
		return false;
	}

	for (UINT i = 0; i < sizeof(http_decoy_pages) / sizeof(http_decoy_pages[0]); i++)
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
