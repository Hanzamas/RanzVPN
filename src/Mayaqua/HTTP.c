#include "HTTP.h"

#include "Kernel.h"
#include "Memory.h"
#include "Network.h"
#include "Pack.h"
#include "Str.h"

static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";

// Generate the date and time string for the HTTP header
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
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	UINT64ToSystem(&s, t);

	Format(str, size, "%s, %02u %s %04u %02u:%02u:%02u GMT",
		wday[s.wDayOfWeek], s.wDay, month[s.wMonth - 1], s.wYear,
		s.wHour, s.wMinute, s.wSecond);
}

// Replace unsafe characters in target
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

// Create an HTTP header
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version)
{
	return NewHttpHeaderEx(method, target, version, false);
}
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort)
{
	HTTP_HEADER *header;
	// Validate arguments
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

// Release the HTTP header
void FreeHttpHeader(HTTP_HEADER *header)
{
	UINT i;
	HTTP_VALUE **values;
	// Validate arguments
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

// Create a new HTTP value
HTTP_VALUE *NewHttpValue(char *name, char *data)
{
	HTTP_VALUE *v;
	// Validate arguments
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

// Release the HTTP value
void FreeHttpValue(HTTP_VALUE *value)
{
	// Validate arguments
	if (value == NULL)
	{
		return;
	}

	Free(value->Data);
	Free(value->Name);

	Free(value);
}

// Comparison function of the HTTP value
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

// Look for an HTTP value in an HTTP header
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name)
{
	HTTP_VALUE *v, t;
	// Validate arguments
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

// Add an HTTP value to the HTTP header
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value)
{
	// Validate arguments
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

// Adds the HTTP value contained in the string to the HTTP header
bool AddHttpValueStr(HTTP_HEADER* header, char *string)
{
	HTTP_VALUE *value = NULL;
	UINT pos = 0;
	char *value_name = NULL;
	char *value_data = NULL;

	// Validate arguments
	if (header == NULL || IsEmptyStr(string))
	{
		return false;
	}

	// Sanitize string
	EnSafeHttpHeaderValueStr(string, ' ');

	// Get the position of the colon
	pos = SearchStr(string, ":", 0);
	if (pos == INFINITE)
	{
		// The colon does not exist
		return false;
	}

	if ((pos + 1) >= StrLen(string))
	{
		// There is no data
		return false;
	}

	// Divide into the name and the data
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

// Get the Content-Length value from the HTTP header
UINT GetContentLength(HTTP_HEADER *header)
{
	UINT ret;
	HTTP_VALUE *v;
	// Validate arguments
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

// Send HTTP data
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size)
{
	char *header_str;
	BUF *b;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL || (post_size != 0 && post_data == NULL))
	{
		return false;
	}

	// Check whether the Content-Length exists?
	if (GetHttpValue(header, "Content-Length") == NULL)
	{
		char tmp[MAX_SIZE];
		// Add because it does not exist
		ToStr(tmp, post_size);
		AddHttpValue(header, NewHttpValue("Content-Length", tmp));
	}

	// Convert the header to string
	header_str = HttpHeaderToStr(header);
	if (header_str == NULL)
	{
		return false;
	}
	b = NewBuf();
	WriteBuf(b, header_str, StrLen(header_str));
	Free(header_str);

	// Append the data
	WriteBuf(b, post_data, post_size);

	// Send
	ret = SendAll(s, b->Buf, b->Size, s->SecureMode);

	FreeBuf(b);

	return ret;
}

// Convert an HTTP header to a string
char *HttpHeaderToStr(HTTP_HEADER *header)
{
	BUF *b;
	char *tmp;
	UINT i;
	char *s;
	// Validate arguments
	if (header == NULL)
	{
		return NULL;
	}

	tmp = Malloc(HTTP_HEADER_LINE_MAX_SIZE);
	b = NewBuf();

	// Header
	Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
		"%s %s %s\r\n", header->Method, header->Target, header->Version);
	WriteBuf(b, tmp, StrLen(tmp));

	// Value
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		HTTP_VALUE *v = (HTTP_VALUE *)LIST_DATA(header->ValueList, i);
		Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
			"%s: %s\r\n", v->Name, v->Data);
		WriteBuf(b, tmp, StrLen(tmp));
	}

	// Trailing newline
	WriteBuf(b, "\r\n", 2);
	s = Malloc(b->Size + 1);
	Copy(s, b->Buf, b->Size);
	s[b->Size] = 0;

	FreeBuf(b);
	Free(tmp);

	return s;
}

// Send the HTTP header
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header)
{
	char *str;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL)
	{
		return false;
	}

	// Convert to string
	str = HttpHeaderToStr(header);

	// Transmission
	ret = SendAll(s, str, StrLen(str), s->SecureMode);

	Free(str);

	return ret;
}

// Receive an HTTP header
// src/fuzz/fuzz_http.c repeats this loop (and RecvLine) over a buffer: change it with this function
HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	// Get the first line
	str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		return NULL;
	}

	// Split into tokens
	token = ParseToken(str, " ");

	FreeSafe(PTR_TO_PTR(str));

	if (token->NumTokens < 3)
	{
		FreeToken(token);
		return NULL;
	}

	// Creating a header object
	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);
	FreeToken(token);

	if (StrCmpi(header->Version, "HTTP/0.9") == 0)
	{
		// The header ends with this line
		return header;
	}

	// Get the subsequent lines
	while (true)
	{
		str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
		Trim(str);
		if (IsEmptyStr(str))
		{
			// End of header
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

// Send a PACK to the server
bool HttpClientSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char ip_str[MAX_SIZE];

	// Validate arguments
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

// Receive a PACK from the server
PACK *HttpClientRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	UINT num_noop = 0;
	// Validate arguments
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
		Debug("recv: noop ignore\n");
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

// Send a PACK to the client
bool HttpServerSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	// Validate arguments
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

// Receive a PACK from the client
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
	// Validate arguments
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

	// Determine whether it's a NOOP
	UINT noop = PackGetInt(p, "noop");
	if (noop == NOOP)
	{
		Debug("recv: noop\n");
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
		Debug("recv: noop ignore\n");
		FreePack(p);

		goto START;
	}

	return p;

BAD_REQUEST:
	// Return an error
	return NULL;
}

// Send "403 Forbidden" error
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
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "403", "Forbidden");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_403_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_403_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Send "404 Not Found" error
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
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "404", "Not Found");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_404_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_404_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Send "501 Not Implemented" error
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
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "501", "Method Not Implemented");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_501_str) * 2 + StrLen(target) + StrLen(host) + StrLen(method) + StrLen(version);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_501_str);

	// TARGET
	ReplaceUnsafeCharInHttpTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// METHOD
	ReplaceStri(str, str_size, str, "$METHOD$", method);

	// VERSION
	ReplaceStri(str, str_size, str, "$VERSION$", version);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}
