// HttpListener.c
// HTTP listener: the HTTP responder (a redirect to HTTPS, ACME HTTP-01 challenges) and the one request of a connection

#include "HttpListener.h"

#include "Cedar.h"
#include "HubLog.h"
#include "Server.h"

#include "Mayaqua/HTTP.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

// The characters of a method besides letters and digits (tchar of RFC 9110)
#define HTTP_LISTENER_TCHARS "!#$%&'*+-.^_`|~"

// Line source of HttpListenerParse: the lines of the bytes received so far as HttpBufLineSource cuts them, the request
// line, and why a line was missing
typedef struct HTTP_LISTENER_LINES {
	BUF *Buf;
	char *RequestLine; // Copy of the first line
	UINT NumLines;
	bool Missing; // A line runs to the end of the bytes: more bytes may complete it
	bool Over;    // A line or the number of lines went over the limits of the reader
} HTTP_LISTENER_LINES;

static char *HttpListenerLineSource(void *param, UINT max_size) {
	HTTP_LISTENER_LINES *l = (HTTP_LISTENER_LINES *)param;
	UINT start = l->Buf->Current;

	// The request line, the header lines of HTTP_HEADER_MAX_LINES values and the blank line
	if (l->NumLines >= HTTP_HEADER_MAX_LINES + 2) {
		l->Over = true;
		return NULL;
	}

	char *line = HttpBufLineSource(l->Buf, max_size);
	if (line == NULL) {
		// HttpBufLineSource gives up after max_size bytes without a line end: that line can never complete
		if (l->Buf->Size - start > max_size)
			l->Over = true;
		else
			l->Missing = true;

		return NULL;
	}

	if (l->NumLines == 0)
		l->RequestLine = CopyStr(line);
	l->NumLines++;

	return line;
}

// Whether c is one of the characters of set
static bool HttpListenerCharIn(char c, const char *set) {
	for (UINT i = 0; set[i] != 0; i++)
		if (set[i] == c)
			return true;

	return false;
}

// Whether str is not empty and holds only letters, digits and characters of extra
static bool HttpListenerIsWord(const char *str, const char *extra) {
	if (str == NULL || str[0] == 0)
		return false;

	for (UINT i = 0; str[i] != 0; i++) {
		char c = str[i];

		if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && HttpListenerCharIn(c, extra) == false)
			return false;
	}

	return true;
}

// The request line, as HttpParseHeaderLines split it, is exactly "method SP target SP version": a token for the method,
// visible ASCII characters for the target, HTTP/1.0 or HTTP/1.1
static bool HttpListenerIsRequestLine(const HTTP_HEADER *h, const char *line) {
	if (h == NULL || line == NULL)
		return false;

	if (StrLen(line) != StrLen(h->Method) + StrLen(h->Target) + StrLen(h->Version) + 2)
		return false;

	if (HttpListenerIsWord(h->Method, HTTP_LISTENER_TCHARS) == false)
		return false;

	for (UINT i = 0; h->Target[i] != 0; i++) {
		UCHAR c = (UCHAR)h->Target[i];

		if (c < 0x21 || c > 0x7e)
			return false;
	}

	return (StrCmp(h->Version, "HTTP/1.0") == 0 || StrCmp(h->Version, "HTTP/1.1") == 0);
}

// Parse the bytes received so far as one request with the header reader of Mayaqua (HttpParseHeaderLines).
// HTTP_LISTENER_PARSE_DONE: *request is the request, or NULL when it is malformed. HTTP_LISTENER_PARSE_MORE: more bytes
// may complete it. HTTP_LISTENER_PARSE_OVER: it went over the limits of the reader or HTTP_LISTENER_MAX_REQUEST bytes
UINT HttpListenerParse(BUF *b, HTTP_HEADER **request) {
	HTTP_LISTENER_LINES l;
	UINT ret = HTTP_LISTENER_PARSE_DONE;
	if (request == NULL)
		return HTTP_LISTENER_PARSE_OVER;

	*request = NULL;
	if (b == NULL)
		return HTTP_LISTENER_PARSE_OVER;

	Zero(&l, sizeof(l));
	l.Buf = b;
	SeekBufToBegin(b);

	HTTP_HEADER *h = HttpParseHeaderLines(HttpListenerLineSource, &l);

	if (l.Over || (l.Missing && b->Size >= HTTP_LISTENER_MAX_REQUEST)) {
		ret = HTTP_LISTENER_PARSE_OVER;
	} else if (l.Missing) {
		ret = HTTP_LISTENER_PARSE_MORE;
	} else if (HttpListenerIsRequestLine(h, l.RequestLine)) {
		*request = h;
		h = NULL;
	}

	FreeHttpHeader(h);
	Free(l.RequestLine);

	return ret;
}

// Whether str is 1 to max_len decimal digits
static bool HttpListenerIsDigits(const char *str, UINT max_len) {
	UINT len = StrLen(str);

	if (len == 0 || len > max_len)
		return false;

	for (UINT i = 0; i < len; i++)
		if (str[i] < '0' || str[i] > '9')
			return false;

	return true;
}

// Whether str, the part of a Host value between the brackets, is an IPv6 literal
static bool HttpListenerIsIpv6Literal(const char *str) {
	IP ip;

	for (UINT i = 0; str[i] != 0; i++) {
		char c = str[i];

		if ((c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != ':' && c != '.')
			return false;
	}

	return (SearchStr(str, ":", 0) != INFINITE && StrToIP6(&ip, str));
}

// The host of the one Host header of a request, without its port, into host (size bytes, more than
// HTTP_LISTENER_HOST_MAX_LEN): a DNS name (letters, digits, minus, dot) or a bracketed IPv6 literal, then an optional
// :port. False for a missing or repeated Host header and for any other value, which keeps a header line or another host
// out of the redirect
static bool HttpListenerGetHost(const HTTP_HEADER *request, char *host, UINT size) {
	HTTP_VALUE *v = NULL;
	UINT num = 0;
	UINT len;
	bool ok;

	for (UINT i = 0; i < LIST_NUM(request->ValueList); i++) {
		HTTP_VALUE *x = LIST_DATA(request->ValueList, i);

		if (StrCmpi(x->Name, "Host") == 0) {
			v = x;
			num++;
		}
	}

	if (num != 1 || StrLen(v->Data) > HTTP_LISTENER_HOST_MAX_LEN || size <= HTTP_LISTENER_HOST_MAX_LEN)
		return false;

	char *value = v->Data;

	if (value[0] == '[') {
		len = SearchStr(value, "]", 0);
		if (len == INFINITE)
			return false;

		StrCpy(host, len, value + 1);
		ok = HttpListenerIsIpv6Literal(host);
		len++;
	} else {
		len = SearchStr(value, ":", 0);
		if (len == INFINITE)
			len = StrLen(value);

		StrCpy(host, len + 1, value);
		ok = HttpListenerIsWord(host, "-.");
	}

	if (ok == false)
		return false;

	// After the host: nothing, or a port
	if (value[len] != 0) {
		char *port = value + len + 1;

		if (value[len] != ':' || HttpListenerIsDigits(port, 5) == false || ToInt(port) > 65535)
			return false;
	}

	StrCpy(host, len + 1, value);

	return true;
}

// An ACME token: 1 to HTTP_LISTENER_TOKEN_MAX_LEN characters of the base64url alphabet, and not a name that Windows opens
// as a device in every folder (CON, PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9)
static bool HttpListenerIsToken(const char *token) {
	if (StrLen(token) > HTTP_LISTENER_TOKEN_MAX_LEN || HttpListenerIsWord(token, "-_") == false)
		return false;

	if (StrCmpi(token, "CON") == 0 || StrCmpi(token, "PRN") == 0 || StrCmpi(token, "AUX") == 0 || StrCmpi(token, "NUL") == 0)
		return false;

	if (StrLen(token) == 4 && (StartWith(token, "COM") || StartWith(token, "LPT")) && token[3] >= '0' && token[3] <= '9')
		return false;

	return true;
}

// The answer to a request under the challenge prefix, rest being the target after it: 200 with the challenge of the
// token, else 404. The token ends at the query, which is ignored
static void HttpListenerChallenge(HTTP_LISTENER_RESPONSE *r, const char *rest, HTTP_CHALLENGE_LOOKUP *lookup, void *param) {
	char token[HTTP_LISTENER_TOKEN_MAX_LEN + 1];
	UINT len = 0;

	r->Challenge = true;
	r->Status = 404;

	while (rest[len] != 0 && rest[len] != '?')
		len++;

	if (len == 0 || len > HTTP_LISTENER_TOKEN_MAX_LEN || lookup == NULL)
		return;

	Copy(token, rest, len);
	token[len] = 0;

	if (HttpListenerIsToken(token) == false)
		return;

	BUF *b = lookup(param, token);
	if (b == NULL)
		return;

	if (b->Size > HTTP_LISTENER_CHALLENGE_MAX_SIZE) {
		FreeBuf(b);
		return;
	}

	r->Status = 200;
	r->Body = b;
	r->Token = CopyStr(token);
}

// The port of a redirect: none (0) when an enabled VPN listener has HTTP_LISTENER_HTTPS_PORT or none is enabled, else
// the lowest enabled VPN listener port
static UINT HttpListenerRedirectPort(const UINT *ports, UINT num_ports) {
	UINT lowest = 0;

	for (UINT i = 0; i < num_ports; i++) {
		if (ports[i] == HTTP_LISTENER_HTTPS_PORT)
			return 0;

		if (lowest == 0 || ports[i] < lowest)
			lowest = ports[i];
	}

	return lowest;
}

// The Location of a redirect: https://, the host, :port unless port is 0, then the target as received
static char *HttpListenerLocation(const char *host, UINT port, const char *target) {
	char port_str[16];

	port_str[0] = 0;
	if (port != 0)
		Format(port_str, sizeof(port_str), ":%u", port);

	UINT size = StrLen("https://") + StrLen(host) + StrLen(port_str) + StrLen(target) + 1;
	char *location = Malloc(size);

	StrCpy(location, size, "https://");
	StrCat(location, size, host);
	StrCat(location, size, port_str);
	StrCat(location, size, target);

	return location;
}

// The HTTP responder, a pure function: lookup is the only way it reads anything. request is a request that
// HttpListenerParse returned (NULL: a malformed one), ports the enabled VPN listener ports. 400 for a malformed request,
// a target not in origin form or a bad Host header; 405 for a method other than GET and HEAD; under the challenge prefix
// 200 with the challenge, else 404; every other request 301 to HTTPS on the same host and target
HTTP_LISTENER_RESPONSE *HttpListenerRespond(HTTP_HEADER *request, HTTP_CHALLENGE_LOOKUP *lookup, void *param, const UINT *ports, UINT num_ports) {
	char host[HTTP_LISTENER_HOST_MAX_LEN + 1];
	UINT prefix_len = StrLen(HTTP_LISTENER_CHALLENGE_PREFIX);

	HTTP_LISTENER_RESPONSE *r = ZeroMalloc(sizeof(HTTP_LISTENER_RESPONSE));
	r->Status = 400;

	if (request == NULL || request->Target[0] != '/' || HttpListenerGetHost(request, host, sizeof(host)) == false)
		return r;

	if (StrCmp(request->Method, "GET") != 0 && StrCmp(request->Method, "HEAD") != 0) {
		r->Status = 405;
		return r;
	}

	r->NoBody = (StrCmp(request->Method, "HEAD") == 0);

	if (StrLen(request->Target) >= prefix_len && Cmp(request->Target, HTTP_LISTENER_CHALLENGE_PREFIX, prefix_len) == 0) {
		HttpListenerChallenge(r, request->Target + prefix_len, lookup, param);
		return r;
	}

	r->Status = 301;
	r->Location = HttpListenerLocation(host, HttpListenerRedirectPort(ports, num_ports), request->Target);

	return r;
}

static char *HttpListenerReason(UINT status) {
	switch (status) {
	case 200:
		return "OK";

	case 301:
		return "Moved Permanently";

	case 404:
		return "Not Found";

	case 405:
		return "Method Not Allowed";

	default:
		return "Bad Request";
	}
}

static void HttpListenerPut(BUF *b, const char *str) {
	WriteBuf(b, str, StrLen(str));
}

// The bytes of an answer: the status line, the headers and, unless NoBody, the body. Content-Length always, Content-Type
// with a body, Connection: close; no Server header, and nothing names the product
BUF *HttpListenerResponseToBuf(const HTTP_LISTENER_RESPONSE *r) {
	char tmp[MAX_SIZE];
	BUF *b = NewBuf();
	if (r == NULL)
		return b;

	Format(tmp, sizeof(tmp), "HTTP/1.1 %u %s\r\n", r->Status, HttpListenerReason(r->Status));
	HttpListenerPut(b, tmp);

	if (r->Location != NULL) {
		HttpListenerPut(b, "Location: ");
		HttpListenerPut(b, r->Location);
		HttpListenerPut(b, "\r\n");
	}

	if (r->Status == 405)
		HttpListenerPut(b, "Allow: GET, HEAD\r\n");

	if (r->Body != NULL)
		HttpListenerPut(b, "Content-Type: text/plain\r\n");

	Format(tmp, sizeof(tmp), "Content-Length: %u\r\nConnection: close\r\n\r\n", (r->Body != NULL ? r->Body->Size : 0));
	HttpListenerPut(b, tmp);

	if (r->Body != NULL && r->NoBody == false)
		WriteBuf(b, r->Body->Buf, r->Body->Size);

	return b;
}

void FreeHttpListenerResponse(HTTP_LISTENER_RESPONSE *r) {
	if (r == NULL)
		return;

	Free(r->Location);
	FreeBuf(r->Body);
	Free(r->Token);
	Free(r);
}

// The challenge lookup of the listener: the file of the token in the webroot, read on every request (nothing is cached),
// at most one byte over the size limit, which is enough to refuse a larger file
static BUF *HttpListenerReadChallenge(void *param, char *token) {
	char path[MAX_PATH];

	Format(path, sizeof(path), "%s/%s", HTTP_LISTENER_CHALLENGE_DIR, token);

	return ReadDumpWithMaxSize(path, HTTP_LISTENER_CHALLENGE_MAX_SIZE + 1);
}

// The enabled VPN listener ports of the server, which name the port of a redirect. The caller frees the array
static UINT *HttpListenerVpnPorts(SERVER *s, UINT *num) {
	UINT num_listeners = 0;
	SERVER_LISTENER_INFO *o = SiEnumListeners(s, &num_listeners);
	UINT *ports = ZeroMalloc(sizeof(UINT) * (num_listeners + 1));

	*num = 0;
	for (UINT i = 0; i < num_listeners; i++)
		if (o[i].Enabled)
			ports[(*num)++] = o[i].Port;

	Free(o);

	return ports;
}

// Answer a complete request, then log a request under the challenge prefix with the source address
static void HttpListenerAnswer(CEDAR *cedar, SOCK *s, UINT port, HTTP_HEADER *request) {
	char ip[MAX_SIZE];
	UINT num_ports = 0;
	UINT *ports = HttpListenerVpnPorts(cedar->Server, &num_ports);

	HTTP_LISTENER_RESPONSE *r = HttpListenerRespond(request, HttpListenerReadChallenge, NULL, ports, num_ports);
	BUF *b = HttpListenerResponseToBuf(r);

	SendAll(s, b->Buf, b->Size, false);

	if (r->Challenge) {
		IPToStr(ip, sizeof(ip), &s->RemoteIP);

		if (r->Status == 200)
			SLog(cedar, "LS_HTTP_ACME_SERVED", port, r->Token, ip);
		else
			SLog(cedar, "LS_HTTP_ACME_NOT_FOUND", port, ip);
	}

	FreeBuf(b);
	FreeHttpListenerResponse(r);
	Free(ports);
}

// The one request of a connection to the HTTP listener on port, read within HTTP_LISTENER_TIMEOUT of the accept and
// answered; then the caller closes the connection. Without a complete request in time, or over the limits of the reader,
// it closes without an answer
void HttpListenerServe(CEDAR *cedar, SOCK *s, UINT port) {
	UCHAR data[4096];
	HTTP_HEADER *request = NULL;
	UINT ret = HTTP_LISTENER_PARSE_MORE;
	if (cedar == NULL || s == NULL)
		return;

	UINT64 deadline = Tick64() + (UINT64)HTTP_LISTENER_TIMEOUT;
	BUF *b = NewBuf();

	while (ret == HTTP_LISTENER_PARSE_MORE) {
		UINT64 now = Tick64();
		if (now >= deadline)
			break;

		SetTimeout(s, (UINT)(deadline - now));

		UINT size = Recv(s, data, sizeof(data), false);
		if (size == 0 || size == SOCK_LATER)
			break;

		SeekBufToEnd(b);
		WriteBuf(b, data, size);

		ret = HttpListenerParse(b, &request);
	}

	if (ret == HTTP_LISTENER_PARSE_DONE)
		HttpListenerAnswer(cedar, s, port, request);

	FreeHttpHeader(request);
	FreeBuf(b);
}
