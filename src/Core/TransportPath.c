// TransportPath.c
// The outbound path of the new core's client transports (SDN-61, #254): the TCP connection of a TLS-443 dial to its
// server, through an outbound proxy where the configuration names one, and the underlay that it leaves through. A dial
// of TLS-443 goes:
// - direct;
// - through the system's proxy, which WinHTTP finds for the URL of the server, https and its host and port (ADR-0008:
//   WinHttpGetProxyForUrl plus a small CONNECT): the PAC script of the configuration, else the current user's settings
//   (auto-detect, WPAD by DHCP and DNS, and the PAC script they name; then their proxy and its bypass list), else the
//   WinHTTP default that netsh winhttp sets. The lookup runs on the Windows thread pool, so that a dial that is
//   cancelled, as the race of a fallback list cancels the attempts it does not need, returns at once;
// - through an HTTP proxy, which CONNECT opens to the server (RFC 9110 section 9.3.6), or a SOCKS5 proxy without
//   authentication (RFC 1928). Either resolves the server's name itself.
// QUIC goes direct: a proxy of TCP carries no UDP. The underlay binding names an interface, by its alias or its index,
// that the connection leaves through (IP_UNICAST_IF, IPV6_UNICAST_IF), a local address that it sends from (bind), or
// both.
//
// What a proxy answers, and the proxy list that a PAC script gives (WPAD brings the script from the network), are
// untrusted: TransportProxyParseHttp, TransportProxyParseSocks and TransportProxyParseList read them, and fuzz_transport
// drives each. The server speaks only after the client's ClientHello, so a proxy that sends more than its answer is
// refused, and the tunnel starts with the server's first byte.

#include "Core/TransportInternal.h"

#include <iphlpapi.h>
#include <winhttp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// How often a dial looks at its cancel while it waits (ms)
#define PATH_POLL 50
// A proxy answers within this time (ms)
#define PATH_ANSWER 10000
// WinHTTP finds the system's proxy within this time (ms); a lookup that takes longer leaves the dial direct
#define PATH_LOOKUP_TIME 30000
// A port with its NUL
#define PATH_PORT_SIZE 8
// The authority of a server, its host (an IPv6 address in brackets), a colon and its port, with its NUL
#define PATH_AUTHORITY_SIZE (TRANSPORT_ADDRESS_SIZE + PATH_PORT_SIZE + 3)
// A CONNECT request: the authority twice, and its fixed text
#define PATH_REQUEST_SIZE (2 * PATH_AUTHORITY_SIZE + 64)
// The URL of a server: https, its authority and a slash, with its NUL
#define PATH_URL_SIZE (PATH_AUTHORITY_SIZE + 16)

// SOCKS5 (RFC 1928): the version, the method without authentication, the command CONNECT, the types of an address, and
// the reply that the CONNECT succeeded
#define SOCKS_VERSION   0x05
#define SOCKS_NO_AUTH   0x00
#define SOCKS_CONNECT   0x01
#define SOCKS_IPV4      0x01
#define SOCKS_DOMAIN    0x03
#define SOCKS_IPV6      0x04
#define SOCKS_SUCCEEDED 0x00

// A request of SOCKS5 at most: the version, the command, a reserved byte, the type, the length of a name, the name and
// the port
#define SOCKS_REQUEST_SIZE (4 + 1 + 255 + 2)

// What reads an answer of a proxy: TransportProxyParseHttp, TransportProxyParseSocks or PathParseMethod
typedef UINT(PATH_PARSE_PROC)(const UCHAR *data, UINT size, UINT *used, UINT *code);

// A lookup of the system's proxy on the Windows thread pool, which a dial waits for while it looks at its cancel. The
// dial and the lookup each hold a reference; the one that lets go last frees it.
typedef struct PATH_LOOKUP {
	volatile LONG Refs;                     // The dial and the lookup
	HANDLE Done;                            // Set once the lookup ended
	char Pac[TRANSPORT_ADDRESS_SIZE];       // The URL of the path's PAC script, empty for the settings
	char Host[TRANSPORT_ADDRESS_SIZE];      // The server's host ...
	char Port[PATH_PORT_SIZE];              // ... and port
	char ProxyHost[TRANSPORT_ADDRESS_SIZE]; // The proxy that the lookup found, empty for none ...
	char ProxyPort[PATH_PORT_SIZE];         // ... and its port
} PATH_LOOKUP;

//
// Lists and names
//

// Whether c separates the entries of a list of WinHTTP: a semicolon or white space
static bool PathSeparator(char c) {
	return (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n');
}

// The lower case of an ASCII letter; any other character as it is
static char PathLower(char c) {
	return (c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c);
}

// Whether the len characters at s are text, case ignored
static bool PathIs(const char *s, UINT len, const char *text) {
	return (len == (UINT)strlen(text) && _strnicmp(s, text, len) == 0);
}

// A decimal number of 1 to 9 digits, above 0
static bool PathNumber(const char *s, ULONG *value) {
	ULONG v = 0;
	UINT n = 0;

	for (; s[n] != 0; n++) {
		if (s[n] < '0' || s[n] > '9' || n >= 9)
			return false;
		v = v * 10 + (ULONG)(s[n] - '0');
	}

	*value = v;
	return (n != 0 && v != 0);
}

// Split an entry of len characters, "host", "host:port", "[v6]" or "[v6]:port" (an IPv6 address without brackets has
// no port), into host (host_max bytes with its NUL, without the brackets) and port (port_max bytes): 1 to 5 digits, 1 to
// 65535; default_port where the entry has none, or false where default_port is NULL. False for an empty host and for a
// host or a port too long for its buffer.
static bool PathSplit(const char *s, UINT len, char *host, UINT host_max, char *port, UINT port_max, const char *default_port) {
	const char *h = s;
	const char *p = NULL;
	UINT host_len = len, port_len = 0;

	if (len != 0 && s[0] == '[') {
		const char *close = (const char *)memchr(s, ']', len);
		if (close == NULL)
			return false;

		UINT rest = len - (UINT)(close + 1 - s);
		if (rest != 0 && close[1] != ':')
			return false;
		h = s + 1;
		host_len = (UINT)(close - h);
		if (rest != 0) {
			p = close + 2;
			port_len = rest - 1;
		}
	} else {
		const char *colon = (const char *)memchr(s, ':', len);
		if (colon != NULL && memchr(colon + 1, ':', len - (UINT)(colon + 1 - s)) == NULL) {
			host_len = (UINT)(colon - s);
			p = colon + 1;
			port_len = len - host_len - 1;
		}
	}

	if (host_len == 0 || host_len >= host_max)
		return false;

	if (p == NULL) {
		if (default_port == NULL || (UINT)strlen(default_port) >= port_max)
			return false;
		strcpy_s(port, port_max, default_port);
	} else {
		UINT value = 0;

		if (port_len == 0 || port_len > 5 || port_len >= port_max)
			return false;
		for (UINT i = 0; i < port_len; i++) {
			if (p[i] < '0' || p[i] > '9')
				return false;
			value = value * 10 + (UINT)(p[i] - '0');
		}
		if (value == 0 || value > 65535)
			return false;

		CopyMemory(port, p, port_len);
		port[port_len] = 0;
	}

	CopyMemory(host, h, host_len);
	host[host_len] = 0;

	return true;
}

bool TransportProxyParseList(const char *list, char *host, UINT host_max, char *port, UINT port_max) {
	bool found = false, https = false;

	if (list == NULL || host == NULL || port == NULL || host_max == 0 || port_max == 0)
		return false;
	host[0] = 0;
	port[0] = 0;

	for (const char *p = list; *p != 0;) {
		if (PathSeparator(*p)) {
			p++;
			continue;
		}

		// One entry: its scheme and "=" where it has one, then the proxy, which may start with http:// and end with a
		// slash
		const char *e = p;
		while (*e != 0 && PathSeparator(*e) == false)
			e++;
		UINT len = (UINT)(e - p);
		const char *eq = (const char *)memchr(p, '=', len);
		const char *proxy = (eq != NULL ? eq + 1 : p);
		UINT proxy_len = len - (UINT)(proxy - p);
		bool for_https = (eq != NULL && PathIs(p, (UINT)(eq - p), "https"));

		if (proxy_len > 7 && _strnicmp(proxy, "http://", 7) == 0) {
			proxy += 7;
			proxy_len -= 7;
		}
		if (proxy_len != 0 && proxy[proxy_len - 1] == '/')
			proxy_len--;

		// The first entry for https, else the first one without a scheme
		bool wanted = (for_https ? https == false : (eq == NULL && found == false));
		if (wanted && PathSplit(proxy, proxy_len, host, host_max, port, port_max, "80")) {
			found = true;
			https = (https || for_https);
		}

		p = e;
	}

	return found;
}

// Whether the pattern of len characters, * standing for any characters, matches all of name, case ignored
static bool PathMatch(const char *pattern, UINT len, const char *name) {
	UINT name_len = (UINT)strlen(name);
	UINT p = 0, n = 0, star = 0, mark = 0;
	bool have_star = false;

	while (n < name_len) {
		if (p < len && pattern[p] == '*') {
			have_star = true;
			star = p;
			mark = n;
			p++;
		} else if (p < len && PathLower(pattern[p]) == PathLower(name[n])) {
			p++;
			n++;
		} else if (have_star) {
			mark++;
			p = star + 1;
			n = mark;
		} else {
			return false;
		}
	}

	while (p < len && pattern[p] == '*')
		p++;

	return (p == len);
}

// Whether host is a loopback host: localhost, an address of 127.0.0.0/8 or ::1
static bool PathLoopback(const char *host) {
	static const UCHAR loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	UCHAR address[16];

	ZeroMemory(address, sizeof(address));
	if (_stricmp(host, "localhost") == 0)
		return true;
	if (inet_pton(AF_INET, host, address) == 1)
		return (address[0] == 127);

	return (inet_pton(AF_INET6, host, address) == 1 && memcmp(address, loopback6, sizeof(loopback6)) == 0);
}

bool TransportProxyBypass(const char *bypass, const char *host) {
	bool loopback = true;

	if (host == NULL || host[0] == 0)
		return false;

	for (const char *p = (bypass != NULL ? bypass : ""); *p != 0;) {
		if (PathSeparator(*p)) {
			p++;
			continue;
		}

		const char *e = p;
		while (*e != 0 && PathSeparator(*e) == false)
			e++;
		UINT len = (UINT)(e - p);

		if (PathIs(p, len, "<-loopback>"))
			loopback = false;
		if (PathMatch(p, len, host) || (PathIs(p, len, "<local>") && strchr(host, '.') == NULL && strchr(host, ':') == NULL))
			return true;

		p = e;
	}

	return (loopback && PathLoopback(host));
}

//
// The answers of proxies
//

// The status line of an HTTP answer, len characters without its line end: "HTTP/1." and a digit, a space, the code in
// 3 digits, then a space and the reason, or nothing
static bool PathStatusLine(const UCHAR *p, UINT len, UINT *code) {
	UINT value = 0;

	if (len < 12 || memcmp(p, "HTTP/1.", 7) != 0 || p[7] < '0' || p[7] > '9' || p[8] != ' ' || (len > 12 && p[12] != ' '))
		return false;

	for (UINT i = 9; i < 12; i++) {
		if (p[i] < '0' || p[i] > '9')
			return false;
		value = value * 10 + (UINT)(p[i] - '0');
	}

	*code = value;
	return true;
}

UINT TransportProxyParseHttp(const UCHAR *data, UINT size, UINT *used, UINT *code) {
	UINT pos = 0;
	bool status = true;

	if (data == NULL || used == NULL || code == NULL)
		return TRANSPORT_PROXY_BAD;

	// Bytes that cannot start an answer fail at once, not at the end of a line that may never come
	if (memcmp(data, "HTTP/1.", size < 7 ? size : 7) != 0)
		return TRANSPORT_PROXY_BAD;

	// Line by line: a line ends at its LF, a CR before the LF is not part of it, and the empty line ends the answer
	while (true) {
		UINT start = pos;

		while (pos < size && pos < TRANSPORT_PROXY_ANSWER_MAX && data[pos] != '\n')
			pos++;
		if (pos >= TRANSPORT_PROXY_ANSWER_MAX)
			return TRANSPORT_PROXY_BAD;
		if (pos == size)
			return TRANSPORT_PROXY_MORE;

		UINT len = pos - start;
		if (len != 0 && data[pos - 1] == '\r')
			len--;
		pos++;

		if (status) {
			if (PathStatusLine(data + start, len, code) == false)
				return TRANSPORT_PROXY_BAD;
			status = false;
		} else if (len == 0) {
			*used = pos;
			return TRANSPORT_PROXY_DONE;
		}
	}
}

UINT TransportProxyParseSocks(const UCHAR *data, UINT size, UINT *used, UINT *code) {
	UINT address = 0;

	if (data == NULL || used == NULL || code == NULL)
		return TRANSPORT_PROXY_BAD;

	// The version, the reply code, a reserved byte and the type of the bound address
	if (size >= 1 && data[0] != SOCKS_VERSION)
		return TRANSPORT_PROXY_BAD;
	if (size < 4)
		return TRANSPORT_PROXY_MORE;

	// The bound address: 4 or 16 bytes, or a name and its length in the byte before it
	if (data[3] == SOCKS_IPV4) {
		address = 4;
	} else if (data[3] == SOCKS_IPV6) {
		address = 16;
	} else if (data[3] == SOCKS_DOMAIN) {
		if (size < 5)
			return TRANSPORT_PROXY_MORE;
		address = 1 + (UINT)data[4];
	} else {
		return TRANSPORT_PROXY_BAD;
	}

	// ... and its port
	if (size < 4 + address + 2)
		return TRANSPORT_PROXY_MORE;

	*used = 4 + address + 2;
	*code = data[1];
	return TRANSPORT_PROXY_DONE;
}

// The method that a SOCKS5 proxy chose (RFC 1928 section 3): the version and the method
static UINT PathParseMethod(const UCHAR *data, UINT size, UINT *used, UINT *code) {
	if (size >= 1 && data[0] != SOCKS_VERSION)
		return TRANSPORT_PROXY_BAD;
	if (size < 2)
		return TRANSPORT_PROXY_MORE;

	*used = 2;
	*code = data[1];
	return TRANSPORT_PROXY_DONE;
}

//
// The underlay
//

// A numeric local address ("192.0.2.10", "fe80::1%12") into local, its port 0
static bool PathLocal(const char *text, SOCKADDR_INET *local) {
	struct addrinfo hints, *res = NULL;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(text, NULL, &hints, &res) != 0 || res == NULL)
		return false;

	bool ok = ((res->ai_family == AF_INET || res->ai_family == AF_INET6) && res->ai_addrlen <= sizeof(SOCKADDR_INET));
	if (ok)
		CopyMemory(local, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	return ok;
}

bool TransportPathUnderlay(const TRANSPORT_PATH *path, ULONG *ifindex, SOCKADDR_INET *local) {
	char text[TRANSPORT_ADDRESS_SIZE];
	wchar_t alias[TRANSPORT_ADDRESS_SIZE];
	NET_LUID luid;

	if (ifindex == NULL || local == NULL)
		return false;
	*ifindex = 0;
	ZeroMemory(local, sizeof(SOCKADDR_INET));
	if (path == NULL)
		return true;

	// The interface: its alias, as Get-NetAdapter names it, else its index
	strncpy_s(text, sizeof(text), path->Interface, _TRUNCATE);
	if (text[0] != 0) {
		ZeroMemory(&luid, sizeof(luid));
		if (MultiByteToWideChar(CP_UTF8, 0, text, -1, alias, TRANSPORT_ADDRESS_SIZE) != 0 && ConvertInterfaceAliasToLuid(alias, &luid) == NO_ERROR) {
			if (ConvertInterfaceLuidToIndex(&luid, ifindex) != NO_ERROR)
				return false;
		} else if (PathNumber(text, ifindex) == false || ConvertInterfaceIndexToLuid(*ifindex, &luid) != NO_ERROR) {
			*ifindex = 0;
			return false;
		}
	}

	// The local address
	strncpy_s(text, sizeof(text), path->Local, _TRUNCATE);
	if (text[0] != 0 && PathLocal(text, local) == false)
		return false;

	return true;
}

// A socket for a connection to the address a, bound to the underlay: its interface (an index in network byte order for
// IPv4, in host byte order for IPv6) and its local address; INVALID_SOCKET when it cannot be bound
static SOCKET PathSocket(const struct addrinfo *a, ULONG ifindex, const SOCKADDR_INET *local) {
	DWORD v4 = htonl(ifindex), v6 = ifindex;
	int local_size = (local->si_family == AF_INET ? (int)sizeof(SOCKADDR_IN) : (int)sizeof(SOCKADDR_IN6));
	SOCKET s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	bool ok = (s != INVALID_SOCKET);

	if (ok && ifindex != 0 && a->ai_family == AF_INET)
		ok = (setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, (const char *)&v4, sizeof(v4)) == 0);
	if (ok && ifindex != 0 && a->ai_family == AF_INET6)
		ok = (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_IF, (const char *)&v6, sizeof(v6)) == 0);
	if (ok && local->si_family != AF_UNSPEC)
		ok = (bind(s, (const struct sockaddr *)local, local_size) == 0);

	if (ok == false && s != INVALID_SOCKET) {
		closesocket(s);
		s = INVALID_SOCKET;
	}

	return s;
}

// Wait until the connect of s completes: true when it did, false when it failed or cancel was set. A connect that
// failed shows in SO_ERROR, whether or not the wait reports it.
static bool PathConnectWait(SOCKET s, HANDLE cancel) {
	while (true) {
		WSAPOLLFD p;
		int error = 0, error_size = sizeof(error);

		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			return false;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLWRNORM;
		int r = WSAPoll(&p, 1, PATH_POLL);
		if (r < 0 || (r > 0 && (p.revents & (POLLERR | POLLHUP)) != 0))
			return false;
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) != 0 || error != 0)
			return false;
		if (r > 0)
			return true;
	}
}

// A TCP connection to one address through the underlay, connected without blocking so that cancel is seen; the socket
// blocks once it is connected
static SOCKET PathConnectOne(const struct addrinfo *a, ULONG ifindex, const SOCKADDR_INET *local, HANDLE cancel) {
	u_long nonblocking = 1, blocking = 0;
	SOCKET s = PathSocket(a, ifindex, local);

	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	bool ok = (ioctlsocket(s, FIONBIO, &nonblocking) == 0);
	if (ok && connect(s, a->ai_addr, (int)a->ai_addrlen) != 0)
		ok = (WSAGetLastError() == WSAEWOULDBLOCK && PathConnectWait(s, cancel));
	if (ok)
		ok = (ioctlsocket(s, FIONBIO, &blocking) == 0);

	if (ok == false) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// A TCP connection to host and port through the underlay: the addresses of the host in turn, those of the family of the
// local address where the underlay has one; INVALID_SOCKET when none answers or cancel was set
static SOCKET PathConnect(const char *host, const char *port, ULONG ifindex, const SOCKADDR_INET *local, HANDLE cancel) {
	struct addrinfo hints, *res = NULL;
	SOCKET s = INVALID_SOCKET;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = local->si_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return INVALID_SOCKET;

	for (const struct addrinfo *a = res; a != NULL && s == INVALID_SOCKET; a = a->ai_next)
		s = PathConnectOne(a, ifindex, local, cancel);
	freeaddrinfo(res);

	return s;
}

//
// The tunnel of a proxy
//

// Send size bytes to the proxy; false when the connection failed
static bool PathSend(SOCKET s, const void *buf, UINT size) {
	const char *p = (const char *)buf;

	while (size != 0) {
		int n = send(s, p, (int)size, 0);

		if (n <= 0)
			return false;
		p += n;
		size -= (UINT)n;
	}

	return true;
}

// Wait until s has bytes or its end: false once end passed, cancel was set or the wait failed
static bool PathReadable(SOCKET s, HANDLE cancel, UINT64 end) {
	while (true) {
		UINT64 now = GetTickCount64();
		WSAPOLLFD p;

		if (now >= end || (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0))
			return false;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLRDNORM;
		int r = WSAPoll(&p, 1, (INT)(end - now < PATH_POLL ? end - now : PATH_POLL));
		if (r != 0)
			return (r > 0);
	}
}

// Read the answer of the proxy with parse within PATH_ANSWER: its code into *code; false when the answer is bad or does
// not come in time, the connection ends or cancel was set. Nothing may follow the answer: the server speaks only after
// the client's ClientHello, so a byte after the answer would be the proxy's own.
static bool PathAnswer(SOCKET s, HANDLE cancel, PATH_PARSE_PROC *parse, UINT *code) {
	UCHAR buf[TRANSPORT_PROXY_ANSWER_MAX];
	UINT64 end = GetTickCount64() + PATH_ANSWER;
	UINT size = 0;

	ZeroMemory(buf, sizeof(buf));
	while (true) {
		UINT used = 0;
		UINT r = parse(buf, size, &used, code);

		if (r == TRANSPORT_PROXY_DONE)
			return (used == size);
		if (r != TRANSPORT_PROXY_MORE || size >= sizeof(buf) || PathReadable(s, cancel, end) == false)
			return false;

		int n = recv(s, (char *)buf + size, (int)(sizeof(buf) - size), 0);
		if (n <= 0)
			return false;
		size += (UINT)n;
	}
}

// The authority of a server, its host and port, into out (PATH_AUTHORITY_SIZE bytes): an IPv6 address in brackets
static bool PathAuthority(const char *host, const char *port, char *out) {
	int len;

	if (strchr(host, ':') != NULL)
		len = snprintf(out, PATH_AUTHORITY_SIZE, "[%s]:%s", host, port);
	else
		len = snprintf(out, PATH_AUTHORITY_SIZE, "%s:%s", host, port);

	return (len > 0 && len < PATH_AUTHORITY_SIZE);
}

// Open the tunnel of an HTTP proxy to the server: CONNECT to its authority, and an answer with a 2xx code
static bool PathHttpConnect(SOCKET s, const char *host, const char *port, HANDLE cancel) {
	char authority[PATH_AUTHORITY_SIZE];
	char request[PATH_REQUEST_SIZE];
	UINT code = 0;

	if (PathAuthority(host, port, authority) == false)
		return false;

	int len = snprintf(request, sizeof(request), "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority);
	if (len <= 0 || len >= (int)sizeof(request))
		return false;

	return (PathSend(s, request, (UINT)len) && PathAnswer(s, cancel, TransportProxyParseHttp, &code) && code >= 200 && code <= 299);
}

// Open the tunnel of a SOCKS5 proxy to the server (RFC 1928): the method without authentication, then CONNECT to its
// IPv4 or IPv6 address, or to its name, which the proxy resolves; the reply that it succeeded
static bool PathSocksConnect(SOCKET s, const char *host, const char *port, HANDLE cancel) {
	static const UCHAR hello[3] = {SOCKS_VERSION, 1, SOCKS_NO_AUTH};
	UCHAR request[SOCKS_REQUEST_SIZE];
	UCHAR address[16];
	UINT size = 4, code = 0;
	UINT name = (UINT)strnlen(host, 256);
	ULONG number = 0;

	ZeroMemory(request, sizeof(request));
	ZeroMemory(address, sizeof(address));
	if (PathNumber(port, &number) == false || number > 65535)
		return false;

	// The version, CONNECT and a reserved byte, then the address: 4 or 16 bytes, or the length of the name and the name
	request[0] = SOCKS_VERSION;
	request[1] = SOCKS_CONNECT;
	if (inet_pton(AF_INET, host, address) == 1) {
		request[3] = SOCKS_IPV4;
		CopyMemory(request + size, address, 4);
		size += 4;
	} else if (inet_pton(AF_INET6, host, address) == 1) {
		request[3] = SOCKS_IPV6;
		CopyMemory(request + size, address, 16);
		size += 16;
	} else {
		if (name == 0 || name > 255)
			return false;
		request[3] = SOCKS_DOMAIN;
		request[size] = (UCHAR)name;
		CopyMemory(request + size + 1, host, name);
		size += 1 + name;
	}

	// ... and the port
	if (size + 2 > sizeof(request))
		return false;
	request[size] = (UCHAR)(number >> 8);
	request[size + 1] = (UCHAR)(number & 0xFF);
	size += 2;

	if (PathSend(s, hello, sizeof(hello)) == false || PathAnswer(s, cancel, PathParseMethod, &code) == false || code != SOCKS_NO_AUTH)
		return false;

	return (PathSend(s, request, size) && PathAnswer(s, cancel, TransportProxyParseSocks, &code) && code == SOCKS_SUCCEEDED);
}

//
// The system's proxy
//

// Free a block of the heap, which may be NULL
static void PathFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

// A copy of a wide string in UTF-8 on the heap; NULL when it does not convert or there is no memory
static char *PathUtf8(const wchar_t *s) {
	int size = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);

	if (size <= 0)
		return NULL;

	char *out = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size);
	if (out != NULL && WideCharToMultiByte(CP_UTF8, 0, s, -1, out, size, NULL, NULL) != size) {
		PathFree(out);
		return NULL;
	}

	return out;
}

// Free the strings of a WINHTTP_PROXY_INFO
static void PathFreeInfo(WINHTTP_PROXY_INFO *info) {
	if (info->lpszProxy != NULL)
		GlobalFree(info->lpszProxy);
	if (info->lpszProxyBypass != NULL)
		GlobalFree(info->lpszProxyBypass);
}

// The proxy of a proxy list of WinHTTP for the lookup's server, unless the bypass list, which may be NULL, sends the
// server direct
static void PathListProxy(PATH_LOOKUP *l, const wchar_t *list, const wchar_t *bypass) {
	char *text = PathUtf8(list);
	char *skip = (bypass != NULL ? PathUtf8(bypass) : NULL);

	if (text != NULL && TransportProxyBypass(skip, l->Host) == false)
		(void)TransportProxyParseList(text, l->ProxyHost, sizeof(l->ProxyHost), l->ProxyPort, sizeof(l->ProxyPort));

	PathFree(text);
	PathFree(skip);
}

// The URL of the server, https and its authority, into url (PATH_URL_SIZE characters)
static bool PathUrl(const char *host, const char *port, wchar_t *url) {
	char authority[PATH_AUTHORITY_SIZE];
	char text[PATH_URL_SIZE];

	if (PathAuthority(host, port, authority) == false)
		return false;

	int len = snprintf(text, sizeof(text), "https://%s/", authority);
	return (len > 0 && len < (int)sizeof(text) && MultiByteToWideChar(CP_UTF8, 0, text, -1, url, PATH_URL_SIZE) != 0);
}

// What the auto-proxy of WinHTTP finds for url: auto-detect (WPAD, by DHCP and DNS), the PAC script at script, or both,
// in the WinHTTP auto-proxy service. True when it decided, for a proxy or for direct; false when it found no script or
// the script failed.
static bool PathAutoProxy(PATH_LOOKUP *l, const wchar_t *url, bool detect, const wchar_t *script) {
	WINHTTP_AUTOPROXY_OPTIONS opt;
	WINHTTP_PROXY_INFO info;

	HINTERNET session = WinHttpOpen(L"Ranz", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (session == NULL)
		return false;

	ZeroMemory(&opt, sizeof(opt));
	ZeroMemory(&info, sizeof(info));
	opt.dwFlags = (detect ? WINHTTP_AUTOPROXY_AUTO_DETECT : 0) | (script != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : 0);
	opt.dwAutoDetectFlags = (detect ? WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A : 0);
	opt.lpszAutoConfigUrl = script;

	// The credentials of the user for a script that asks for them, as the documentation of WinHttpGetProxyForUrl advises;
	// then the script in the process, where the auto-proxy service fails
	BOOL ok = WinHttpGetProxyForUrl(session, url, &opt, &info);
	if (ok == FALSE && GetLastError() == ERROR_WINHTTP_LOGIN_FAILURE) {
		opt.fAutoLogonIfChallenged = TRUE;
		ok = WinHttpGetProxyForUrl(session, url, &opt, &info);
	}
	if (ok == FALSE && GetLastError() == ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR) {
		opt.dwFlags |= WINHTTP_AUTOPROXY_RUN_INPROCESS;
		ok = WinHttpGetProxyForUrl(session, url, &opt, &info);
	}

	if (ok && info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && info.lpszProxy != NULL)
		PathListProxy(l, info.lpszProxy, info.lpszProxyBypass);
	if (ok)
		PathFreeInfo(&info);

	WinHttpCloseHandle(session);
	return (ok != FALSE);
}

// The lookup: the PAC script of the path decides alone, and the dial goes direct where it cannot be had. Else the
// current user's settings decide: their auto-detect and their PAC script first, then their proxy and its bypass list;
// without settings (a service account may have none) auto-detect does; where none of them names a proxy, the WinHTTP
// default does.
static void PathLookupRun(PATH_LOOKUP *l) {
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie;
	WINHTTP_PROXY_INFO def;
	wchar_t url[PATH_URL_SIZE];
	wchar_t pac[TRANSPORT_ADDRESS_SIZE];

	if (PathUrl(l->Host, l->Port, url) == false)
		return;

	if (l->Pac[0] != 0) {
		if (MultiByteToWideChar(CP_UTF8, 0, l->Pac, -1, pac, TRANSPORT_ADDRESS_SIZE) != 0)
			(void)PathAutoProxy(l, url, false, pac);
		return;
	}

	ZeroMemory(&ie, sizeof(ie));
	bool settings = (WinHttpGetIEProxyConfigForCurrentUser(&ie) != FALSE);
	bool detect = (settings == false || ie.fAutoDetect != FALSE);
	bool decided = false;
	if (detect || ie.lpszAutoConfigUrl != NULL)
		decided = PathAutoProxy(l, url, detect, ie.lpszAutoConfigUrl);

	if (decided == false && ie.lpszProxy != NULL) {
		PathListProxy(l, ie.lpszProxy, ie.lpszProxyBypass);
	} else if (decided == false) {
		ZeroMemory(&def, sizeof(def));
		if (WinHttpGetDefaultProxyConfiguration(&def)) {
			if (def.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && def.lpszProxy != NULL)
				PathListProxy(l, def.lpszProxy, def.lpszProxyBypass);
			PathFreeInfo(&def);
		}
	}

	if (ie.lpszAutoConfigUrl != NULL)
		GlobalFree(ie.lpszAutoConfigUrl);
	if (ie.lpszProxy != NULL)
		GlobalFree(ie.lpszProxy);
	if (ie.lpszProxyBypass != NULL)
		GlobalFree(ie.lpszProxyBypass);
}

// Let go of a reference to a lookup: the last one frees it
static void PathLookupRelease(PATH_LOOKUP *l) {
	if (InterlockedDecrement(&l->Refs) != 0)
		return;

	if (l->Done != NULL)
		CloseHandle(l->Done);
	HeapFree(GetProcessHeap(), 0, l);
}

// The lookup, on a callback of the pool
static void CALLBACK PathLookupCallback(PTP_CALLBACK_INSTANCE instance, void *param) {
	PATH_LOOKUP *l = (PATH_LOOKUP *)param;

	// WinHTTP may wait for the network: the pool starts another thread for the next callback
	(void)CallbackMayRunLong(instance);
	PathLookupRun(l);
	SetEvent(l->Done);
	PathLookupRelease(l);
}

// The system's proxy for the server, from a lookup on the thread pool: its host and port into proxy_host and proxy_port
// (TRANSPORT_ADDRESS_SIZE and PATH_PORT_SIZE bytes), empty for direct. False when cancel was set or the lookup could not
// start; a lookup that does not end within PATH_LOOKUP_TIME leaves the dial direct.
static bool PathSystem(const char *pac, const char *host, const char *port, HANDLE cancel, char *proxy_host, char *proxy_port) {
	PATH_LOOKUP *l = (PATH_LOOKUP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PATH_LOOKUP));
	bool cancelled = false;

	proxy_host[0] = 0;
	proxy_port[0] = 0;
	if (l == NULL)
		return false;

	l->Refs = 2;
	l->Done = CreateEventW(NULL, TRUE, FALSE, NULL);
	strncpy_s(l->Pac, sizeof(l->Pac), pac, _TRUNCATE);
	strncpy_s(l->Host, sizeof(l->Host), host, _TRUNCATE);
	strncpy_s(l->Port, sizeof(l->Port), port, _TRUNCATE);
	if (l->Done == NULL || TrySubmitThreadpoolCallback(PathLookupCallback, l, NULL) == FALSE) {
		l->Refs = 1;
		PathLookupRelease(l);
		return false;
	}

	// Until the lookup ends, the dial is cancelled or the lookup runs out of its time
	UINT64 end = GetTickCount64() + PATH_LOOKUP_TIME;
	while (WaitForSingleObject(l->Done, PATH_POLL) == WAIT_TIMEOUT) {
		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) {
			cancelled = true;
			break;
		}
		if (GetTickCount64() >= end)
			break;
	}

	// The proxy is read only once the lookup set Done after it wrote it
	if (cancelled == false && WaitForSingleObject(l->Done, 0) == WAIT_OBJECT_0) {
		strcpy_s(proxy_host, TRANSPORT_ADDRESS_SIZE, l->ProxyHost);
		strcpy_s(proxy_port, PATH_PORT_SIZE, l->ProxyPort);
	}
	PathLookupRelease(l);

	return (cancelled == false);
}

//
// The path
//

SOCKET TransportPathConnect(const TRANSPORT_PATH *path, const char *host, const char *port, HANDLE cancel) {
	char proxy[TRANSPORT_ADDRESS_SIZE];
	char proxy_host[TRANSPORT_ADDRESS_SIZE];
	char proxy_port[PATH_PORT_SIZE];
	SOCKADDR_INET local;
	ULONG ifindex = 0;
	UINT mode = (path != NULL ? path->Proxy : TRANSPORT_PROXY_NONE);

	if (host == NULL || port == NULL || TransportPathUnderlay(path, &ifindex, &local) == false)
		return INVALID_SOCKET;

	// The proxy: the one the system names, which may be none, or the one of the path
	proxy[0] = 0;
	proxy_host[0] = 0;
	proxy_port[0] = 0;
	if (path != NULL)
		strncpy_s(proxy, sizeof(proxy), path->ProxyAddress, _TRUNCATE);
	if (mode == TRANSPORT_PROXY_SYSTEM) {
		if (PathSystem(proxy, host, port, cancel, proxy_host, proxy_port) == false)
			return INVALID_SOCKET;
		mode = (proxy_host[0] != 0 ? TRANSPORT_PROXY_HTTP : TRANSPORT_PROXY_NONE);
	} else if (mode == TRANSPORT_PROXY_HTTP || mode == TRANSPORT_PROXY_SOCKS5) {
		if (PathSplit(proxy, (UINT)strlen(proxy), proxy_host, sizeof(proxy_host), proxy_port, sizeof(proxy_port), NULL) == false)
			return INVALID_SOCKET;
	} else if (mode != TRANSPORT_PROXY_NONE) {
		return INVALID_SOCKET;
	}

	if (mode == TRANSPORT_PROXY_NONE)
		return PathConnect(host, port, ifindex, &local, cancel);

	// The underlay reaches the proxy, and the proxy the server
	SOCKET s = PathConnect(proxy_host, proxy_port, ifindex, &local, cancel);
	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	bool ok = (mode == TRANSPORT_PROXY_HTTP ? PathHttpConnect(s, host, port, cancel) : PathSocksConnect(s, host, port, cancel));
	if (ok == false) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}
