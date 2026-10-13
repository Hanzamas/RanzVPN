#include "HTTP.h"

#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";

void GetHttpDateStr(char *str, UINT size, UINT64 t)
{
	SYSTEMTIME s;
	static char *wday[] =
	{
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
	};
	static char *month[] =
	{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
		"Nov", "Dec",
	};
	if (str == NULL)
	{
		return;
	}
	UINT64ToSystem(&s, t);

	Format(str, size, "%s, %02u %s %04u %02u:%02u:%02u GMT",
		wday[s.wDayOfWeek], s.wDay, month[s.wMonth - 1], s.wYear,
		s.wHour, s.wMinute, s.wSecond);
}

void ReplaceUnsafeCharInHttpTarget(char *target)
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
	return NewHttpHeaderEx(method, target, version, false);
}
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort)
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
	header->ValueList = NewListFast(no_sort ? NULL : CompareHttpValue);

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

// src/fuzz/fuzz_http.c repeats this loop (and RecvLine) over a buffer: change it with this function
HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	if (s == NULL)
	{
		return NULL;
	}

	str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		return NULL;
	}

	token = ParseToken(str, " ");

	FreeSafe(PTR_TO_PTR(str));

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
		str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
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

bool HttpClientSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char ip_str[MAX_SIZE];

	if (s == NULL || p == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_VPN_TARGET, "HTTP/1.1");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

PACK *HttpClientRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
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

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	size = GetContentLength(h);
	if (size == 0 || size > MAX_PACK_SIZE)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

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
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	if (s == NULL || p == NULL)
	{
		return false;
	}

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("HTTP/1.1", "200", "OK");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

PACK *HttpServerRecv(SOCK *s)
{
	return HttpServerRecvEx(s, 0);
}
PACK *HttpServerRecvEx(SOCK *s, UINT max_data_size)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	UINT num_noop = 0;
	if (max_data_size == 0) max_data_size = HTTP_PACK_MAX_SIZE;
	if (s == NULL)
	{
		return NULL;
	}

START:
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		goto BAD_REQUEST;
	}

	if (StrCmpi(h->Method, "POST") != 0 ||
		StrCmpi(h->Target, HTTP_VPN_TARGET) != 0 ||
		StrCmpi(h->Version, "HTTP/1.1") != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	size = GetContentLength(h);
	if (size == 0 || (size > max_data_size))
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

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

BAD_REQUEST:
	return NULL;
}

bool HttpSendForbidden(SOCK *s, char *target, char *server_id)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	if (s == NULL || target == NULL)
	{
		return false;
	}

	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	port = s->LocalPort;

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "403", "Forbidden");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	str_size = sizeof(http_403_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_403_str);

	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	ReplaceStri(str, str_size, str, "$HOST$", host);

	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

bool HttpSendNotFound(SOCK *s, char *target)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	if (s == NULL || target == NULL)
	{
		return false;
	}

	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	port = s->LocalPort;

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "404", "Not Found");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	str_size = sizeof(http_404_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_404_str);

	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	ReplaceStri(str, str_size, str, "$HOST$", host);

	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	if (s == NULL || target == NULL)
	{
		return false;
	}

	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	port = s->LocalPort;

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "501", "Method Not Implemented");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	str_size = sizeof(http_501_str) * 2 + StrLen(target) + StrLen(host) + StrLen(method) + StrLen(version);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_501_str);

	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	ReplaceStri(str, str_size, str, "$HOST$", host);

	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	ReplaceStri(str, str_size, str, "$METHOD$", method);

	ReplaceStri(str, str_size, str, "$VERSION$", version);

	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}
