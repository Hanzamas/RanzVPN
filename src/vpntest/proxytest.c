// proxytest.c
// Named outbound path test of vpntest ("proxy" command, SDN-61 #254)
//
// The outbound path of the new core's client transports (src/Core/TransportPath.c): a client of the TLS transport
// (TLS-443) dials its server on a test port, never 443, through a test proxy that this file runs on another test port,
// and the Noise session comes up over the tunnel and carries records both ways. The server's name, PROXYTEST_NAME,
// resolves nowhere but in the test proxies (to 127.0.0.1), so a session to that name shows that the client left the
// name to the proxy. The checks:
// - what a proxy answers (TransportProxyParseHttp, TransportProxyParseSocks), the proxy lists of WinHTTP
//   (TransportProxyParseList) and its bypass lists (TransportProxyBypass), on answers and lists made here;
// - an HTTP proxy: the client sends CONNECT with the server's name and port, and the 200 opens the tunnel; a 403 and an
//   answer that is no HTTP fail the dial;
// - a SOCKS5 proxy: the client asks for no authentication and CONNECT with the server's name, its IPv4 address or its
//   IPv6 address; a refusal (reply 5) and a proxy that wants a method the client did not offer fail the dial;
// - the system's proxy through WinHTTP: a PAC script that this file serves over HTTP sends the server's name through the
//   HTTP proxy and its address direct; a dial whose PAC script never comes returns at once when it is cancelled, as the
//   race of a fallback list cancels the attempts it does not need; without a PAC script, the system's settings send a
//   loopback server direct;
// - the underlay: a client bound to the local address 127.0.0.2 reaches a relay of this file, and a proxy, from that
//   address; one bound to the loopback interface, by its alias and by its index, from an address of that interface; one
//   bound to a non-loopback interface of the machine, where it has one with an IPv4 address, from that address; a local
//   address and an interface that the machine does not have fail the dial.
// One runner has no two networks: two KM-TEST adapters on separate subnets, a proxy that only one of them reaches, and
// the packets of the underlay counted on the bound adapter are for the VM job of the multi-node seam (CORE-S3-2, #72),
// which does not exist yet.
// Print "PROXY TEST OK" only when every check passes.

#include "testlist.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <WS2tcpip.h>
#include <iphlpapi.h>

#include <stdio.h>

#define	PROXYTEST_WATCHDOG	240000				// The test process is aborted after this (ms)
#define	PROXYTEST_TIMEOUT	15000				// A handshake, an accept or a record within this time (ms)
#define	PROXYTEST_POLL		100					// The threads of the test look at their stop this often (ms)
#define	PROXYTEST_CANCEL	300					// The cancelled dial is cancelled after this (ms) ...
#define	PROXYTEST_CANCELLED	5000				// ... and returns within this (ms)
#define	PROXYTEST_BUF		16384				// Bytes of a read of a relay
#define	PROXYTEST_NAME		"ranz-proxytest.invalid"	// The server's name, which only the test proxies resolve
#define	PROXYTEST_CN		L"CN=localhost"		// The subject of the server certificate
#define	PROXYTEST_SAN		L"localhost"		// Its subject alternative name
#define	PROXYTEST_LOCAL		"127.0.0.2"			// A local address of the loopback interface besides 127.0.0.1
#define	PROXYTEST_NO_ADDRESS	"192.0.2.1"		// A local address that no machine has (TEST-NET-1, RFC 5737)
#define	PROXYTEST_NO_ALIAS	"Ranz No Such Interface"	// An interface alias that no machine has
#define	PROXYTEST_NO_INDEX	"999999999"			// An interface index that no machine has

// How a test proxy takes a connection
#define	PROXYTEST_HTTP		0					// An HTTP proxy: CONNECT
#define	PROXYTEST_SOCKS		1					// A SOCKS5 proxy without authentication
#define	PROXYTEST_RELAY		2					// A relay to the server, which speaks no proxy protocol

// What a test proxy answers
#define	PROXYTEST_OPEN		0					// It opens the tunnel
#define	PROXYTEST_REFUSE	1					// HTTP: 403; SOCKS5: the reply 5, connection refused
#define	PROXYTEST_GARBAGE	2					// HTTP: an answer that is no HTTP; SOCKS5: the method "username and password"

// The state of the test
typedef struct PROXYTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} PROXYTEST_CTX;

// A test proxy: a thread that takes one connection at a time on its listening socket of the loopback interface (or of
// every address), answers it as Mode and Answer say, and relays the tunnel until either end closes
typedef struct PROXYTEST_PROXY
{
	UINT Mode;							// PROXYTEST_HTTP, PROXYTEST_SOCKS or PROXYTEST_RELAY
	volatile LONG Answer;				// PROXYTEST_OPEN, PROXYTEST_REFUSE or PROXYTEST_GARBAGE
	USHORT TargetPort;					// The relay: the server's port on 127.0.0.1
	SOCKET Listener;					// The listening socket ...
	USHORT Port;						// ... and its port
	HANDLE Stop;						// Set when the thread is to end
	THREAD *Thread;						// The thread
	SRWLOCK Lock;						// The fields below
	char Peer[64];						// The address that the last connection came from
	char Target[MAX_SIZE];				// What its request named: "name host:port", "ipv4 ..." or "ipv6 ..." for SOCKS5
	UINT NumConnections;				// The connections it took
} PROXYTEST_PROXY;

// The server: a thread that accepts the streams of the TLS listener one at a time, runs the responder of the Noise
// session on each and echoes its records until the client closes
typedef struct PROXYTEST_SERVER
{
	TRANSPORT *Transport;				// The server transport
	TRANSPORT_LISTENER *Listener;		// Its listener on every address
	USHORT Port;						// ... and its port
	UCHAR Key[NOISE_KEY_SIZE];			// The responder's static key
	UCHAR Pub[NOISE_KEY_SIZE];			// ... and its public half, which the clients know
	HANDLE Stop;						// Set when the thread is to end
	THREAD *Thread;						// The thread
	volatile LONG NumSessions;			// The Noise sessions that came up
} PROXYTEST_SERVER;

// A PAC server: a thread that answers every request on its listening socket with the PAC script
typedef struct PROXYTEST_PAC
{
	SOCKET Listener;					// The listening socket ...
	USHORT Port;						// ... and its port
	char Script[MAX_SIZE];				// The PAC script
	HANDLE Stop;						// Set when the thread is to end
	THREAD *Thread;						// The thread
	volatile LONG NumRequests;			// The requests it answered
} PROXYTEST_PAC;

// An interface of the machine
typedef struct PROXYTEST_INTERFACE
{
	char Alias[MAX_SIZE];				// Its alias, as Get-NetAdapter names it
	UINT Index;							// Its index
	char Address[64];					// An IPv4 address of it
} PROXYTEST_INTERFACE;

// The test
typedef struct PROXYTEST
{
	PROXYTEST_CTX Ctx;
	char Thumbprint[MAX_SIZE];			// The server certificate, which the clients pin
	PROXYTEST_SERVER Server;
	PROXYTEST_PROXY Http;				// The HTTP proxy
	PROXYTEST_PROXY Socks;				// The SOCKS5 proxy
	PROXYTEST_PROXY Relay;				// The relay on 127.0.0.1
} PROXYTEST;

static bool ProxyTestCheck(PROXYTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ProxyTestCheck(PROXYTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test instead of a hung CI step
static DWORD WINAPI ProxyTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, PROXYTEST_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "PROXY TEST FAILED (did not finish within %u ms)\n", PROXYTEST_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// Sockets
//

// A listening socket on address (an IPv4 address, "0.0.0.0" for every one), port 0, and the port it bound
static SOCKET ProxyTestListen(char *address, USHORT *port)
{
	struct sockaddr_in sa;
	int size = sizeof(sa);
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	*port = 0;
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	if (inet_pton(AF_INET, address, &sa.sin_addr) != 1 || bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(s, SOMAXCONN) != 0 ||
		getsockname(s, (struct sockaddr *)&sa, &size) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	*port = ntohs(sa.sin_port);
	return s;
}

// Wait until s has bytes or its end within timeout, or stop is set: true when it has
static bool ProxyTestReadable(SOCKET s, UINT timeout, HANDLE stop)
{
	UINT64 end = Tick64() + timeout;

	while (Tick64() < end)
	{
		WSAPOLLFD p;

		if (stop != NULL && WaitForSingleObject(stop, 0) == WAIT_OBJECT_0)
		{
			return false;
		}

		Zero(&p, sizeof(p));
		p.fd = s;
		p.events = POLLRDNORM;
		int r = WSAPoll(&p, 1, PROXYTEST_POLL);
		if (r != 0)
		{
			return (r > 0);
		}
	}

	return false;
}

// Read exactly size bytes within PROXYTEST_TIMEOUT
static bool ProxyTestRecvAll(SOCKET s, void *buf, UINT size, HANDLE stop)
{
	UINT got = 0;

	while (got < size)
	{
		if (ProxyTestReadable(s, PROXYTEST_TIMEOUT, stop) == false)
		{
			return false;
		}

		int n = recv(s, (char *)buf + got, (int)(size - got), 0);
		if (n <= 0)
		{
			return false;
		}
		got += (UINT)n;
	}

	return true;
}

// Send all size bytes
static bool ProxyTestSendAll(SOCKET s, void *buf, UINT size)
{
	UINT sent = 0;

	while (sent < size)
	{
		int n = send(s, (char *)buf + sent, (int)(size - sent), 0);
		if (n <= 0)
		{
			return false;
		}
		sent += (UINT)n;
	}

	return true;
}

// A TCP connection to host and port: the server's name of the test is 127.0.0.1
static SOCKET ProxyTestConnect(char *host, UINT port)
{
	struct addrinfo hints, *res = NULL;
	char port_str[16];
	SOCKET s = INVALID_SOCKET;

	Zero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	Format(port_str, sizeof(port_str), "%u", port);
	if (getaddrinfo(StrCmpi(host, PROXYTEST_NAME) == 0 ? "127.0.0.1" : host, port_str, &hints, &res) != 0)
	{
		return INVALID_SOCKET;
	}

	for (struct addrinfo *a = res; a != NULL && s == INVALID_SOCKET; a = a->ai_next)
	{
		s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (s != INVALID_SOCKET && connect(s, a->ai_addr, (int)a->ai_addrlen) != 0)
		{
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}
	freeaddrinfo(res);

	return s;
}

// The text of a socket address
static void ProxyTestAddress(SOCKADDR_STORAGE *sa, char *str, UINT size)
{
	StrCpy(str, size, "");
	if (sa->ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, str, size);
	}
	else if (sa->ss_family == AF_INET6)
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, str, size);
	}
}

//
// The test proxies
//

// Relay the bytes of a and b both ways until either ends or stop is set
static void ProxyTestRelayBytes(SOCKET a, SOCKET b, HANDLE stop)
{
	char *buf = Malloc(PROXYTEST_BUF);
	bool open = true;

	while (open && WaitForSingleObject(stop, 0) != WAIT_OBJECT_0)
	{
		WSAPOLLFD p[2];

		Zero(p, sizeof(p));
		p[0].fd = a;
		p[0].events = POLLRDNORM;
		p[1].fd = b;
		p[1].events = POLLRDNORM;
		int r = WSAPoll(p, 2, PROXYTEST_POLL);
		if (r < 0)
		{
			break;
		}

		for (UINT i = 0;i < 2 && open;i++)
		{
			if (p[i].revents == 0)
			{
				continue;
			}

			int n = recv(p[i].fd, buf, PROXYTEST_BUF, 0);
			open = (n > 0 && ProxyTestSendAll(p[1 - i].fd, buf, (UINT)n));
		}
	}

	Free(buf);
}

// The request of an HTTP client: CONNECT and its target, which the proxy keeps, then the answer that the proxy is to
// give; the connection to the target, or INVALID_SOCKET
static SOCKET ProxyTestHttp(PROXYTEST_PROXY *p, SOCKET c)
{
	char request[MAX_SIZE * 4];
	char target[MAX_SIZE];
	char host[MAX_SIZE];
	UINT size = 0;
	SOCKET t = INVALID_SOCKET;

	// The request, up to its empty line
	Zero(request, sizeof(request));
	while (size < sizeof(request) - 1 && strstr(request, "\r\n\r\n") == NULL)
	{
		if (ProxyTestReadable(c, PROXYTEST_TIMEOUT, p->Stop) == false)
		{
			return INVALID_SOCKET;
		}
		int n = recv(c, request + size, (int)(sizeof(request) - 1 - size), 0);
		if (n <= 0)
		{
			return INVALID_SOCKET;
		}
		size += (UINT)n;
	}

	// "CONNECT <target> HTTP/1.1"
	StrCpy(target, sizeof(target), "");
	if (StartWith(request, "CONNECT "))
	{
		char *end = strchr(request + 8, ' ');
		if (end != NULL && (UINT)(end - (request + 8)) < sizeof(target))
		{
			Copy(target, request + 8, (UINT)(end - (request + 8)));
			target[end - (request + 8)] = 0;
		}
	}
	AcquireSRWLockExclusive(&p->Lock);
	StrCpy(p->Target, sizeof(p->Target), target);
	ReleaseSRWLockExclusive(&p->Lock);

	if (p->Answer == PROXYTEST_REFUSE)
	{
		char *answer = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
		ProxyTestSendAll(c, answer, StrLen(answer));
		return INVALID_SOCKET;
	}
	if (p->Answer == PROXYTEST_GARBAGE)
	{
		char *answer = "SSH-2.0-OpenSSH_9.6\r\n";
		ProxyTestSendAll(c, answer, StrLen(answer));
		return INVALID_SOCKET;
	}

	// The target: "host:port" or "[v6]:port"
	char *colon = strrchr(target, ':');
	if (colon != NULL)
	{
		StrCpy(host, sizeof(host), target[0] == '[' ? target + 1 : target);
		host[(colon - target) - (target[0] == '[' ? 2 : 0)] = 0;
		t = ProxyTestConnect(host, ToInt(colon + 1));
	}
	if (t == INVALID_SOCKET)
	{
		char *answer = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
		ProxyTestSendAll(c, answer, StrLen(answer));
		return INVALID_SOCKET;
	}

	char *answer = "HTTP/1.1 200 Connection established\r\nProxy-Agent: vpntest\r\n\r\n";
	if (ProxyTestSendAll(c, answer, StrLen(answer)) == false)
	{
		closesocket(t);
		return INVALID_SOCKET;
	}

	return t;
}

// The requests of a SOCKS5 client: its methods, then CONNECT and its target, which the proxy keeps, and the replies that
// the proxy is to give; the connection to the target, or INVALID_SOCKET
static SOCKET ProxyTestSocks(PROXYTEST_PROXY *p, SOCKET c)
{
	UCHAR buf[300];
	UCHAR reply[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
	char host[MAX_SIZE];
	char target[MAX_SIZE];
	UINT port = 0;
	UCHAR type = 0;
	SOCKET t = INVALID_SOCKET;

	// The version and the methods: no authentication, which the proxy takes, or the method that the client did not offer
	if (ProxyTestRecvAll(c, buf, 2, p->Stop) == false || buf[0] != 5 || buf[1] == 0 || ProxyTestRecvAll(c, buf + 2, buf[1], p->Stop) == false)
	{
		return INVALID_SOCKET;
	}
	UCHAR method[2] = {5, (UCHAR)(p->Answer == PROXYTEST_GARBAGE ? 0x02 : 0x00)};
	if (ProxyTestSendAll(c, method, sizeof(method)) == false || p->Answer == PROXYTEST_GARBAGE)
	{
		return INVALID_SOCKET;
	}

	// CONNECT: the version, the command, a reserved byte and the type, then the address and the port
	if (ProxyTestRecvAll(c, buf, 4, p->Stop) == false || buf[0] != 5 || buf[1] != 1)
	{
		return INVALID_SOCKET;
	}
	type = buf[3];
	if (type == 1 && ProxyTestRecvAll(c, buf, 4 + 2, p->Stop))
	{
		inet_ntop(AF_INET, buf, host, sizeof(host));
		port = ((UINT)buf[4] << 8) | buf[5];
		Format(target, sizeof(target), "ipv4 %s:%u", host, port);
	}
	else if (type == 4 && ProxyTestRecvAll(c, buf, 16 + 2, p->Stop))
	{
		inet_ntop(AF_INET6, buf, host, sizeof(host));
		port = ((UINT)buf[16] << 8) | buf[17];
		Format(target, sizeof(target), "ipv6 [%s]:%u", host, port);
	}
	else if (type == 3 && ProxyTestRecvAll(c, buf, 1, p->Stop) && ProxyTestRecvAll(c, buf + 1, buf[0] + 2, p->Stop))
	{
		Copy(host, buf + 1, buf[0]);
		host[buf[0]] = 0;
		port = ((UINT)buf[1 + buf[0]] << 8) | buf[2 + buf[0]];
		Format(target, sizeof(target), "name %s:%u", host, port);
	}
	else
	{
		return INVALID_SOCKET;
	}
	AcquireSRWLockExclusive(&p->Lock);
	StrCpy(p->Target, sizeof(p->Target), target);
	ReleaseSRWLockExclusive(&p->Lock);

	if (p->Answer != PROXYTEST_REFUSE)
	{
		t = ProxyTestConnect(host, port);
	}
	reply[1] = (t != INVALID_SOCKET ? 0 : (p->Answer == PROXYTEST_REFUSE ? 5 : 1));
	if (ProxyTestSendAll(c, reply, sizeof(reply)) == false && t != INVALID_SOCKET)
	{
		closesocket(t);
		t = INVALID_SOCKET;
	}

	return t;
}

// The thread of a test proxy
static void ProxyTestProxyThread(THREAD *thread, void *param)
{
	PROXYTEST_PROXY *p = (PROXYTEST_PROXY *)param;

	while (WaitForSingleObject(p->Stop, 0) != WAIT_OBJECT_0)
	{
		SOCKADDR_STORAGE from;
		int from_size = sizeof(from);
		char peer[64];
		SOCKET t = INVALID_SOCKET;

		if (ProxyTestReadable(p->Listener, PROXYTEST_POLL, p->Stop) == false)
		{
			continue;
		}

		Zero(&from, sizeof(from));
		SOCKET c = accept(p->Listener, (struct sockaddr *)&from, &from_size);
		if (c == INVALID_SOCKET)
		{
			continue;
		}

		ProxyTestAddress(&from, peer, sizeof(peer));
		AcquireSRWLockExclusive(&p->Lock);
		StrCpy(p->Peer, sizeof(p->Peer), peer);
		StrCpy(p->Target, sizeof(p->Target), "");
		p->NumConnections++;
		ReleaseSRWLockExclusive(&p->Lock);

		if (p->Mode == PROXYTEST_HTTP)
		{
			t = ProxyTestHttp(p, c);
		}
		else if (p->Mode == PROXYTEST_SOCKS)
		{
			t = ProxyTestSocks(p, c);
		}
		else
		{
			t = ProxyTestConnect("127.0.0.1", p->TargetPort);
		}

		if (t != INVALID_SOCKET)
		{
			ProxyTestRelayBytes(c, t, p->Stop);
			closesocket(t);
		}
		closesocket(c);
	}
}

// Start a test proxy of a mode on address, port 0; false when it cannot listen
static bool ProxyTestProxyStart(PROXYTEST_PROXY *p, UINT mode, char *address, USHORT target_port)
{
	Zero(p, sizeof(PROXYTEST_PROXY));
	InitializeSRWLock(&p->Lock);
	p->Mode = mode;
	p->TargetPort = target_port;
	p->Listener = ProxyTestListen(address, &p->Port);
	p->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (p->Listener == INVALID_SOCKET || p->Stop == NULL)
	{
		return false;
	}

	p->Thread = NewThread(ProxyTestProxyThread, p);
	return true;
}

// Stop a test proxy
static void ProxyTestProxyStop(PROXYTEST_PROXY *p)
{
	if (p->Stop != NULL)
	{
		SetEvent(p->Stop);
	}
	if (p->Thread != NULL)
	{
		WaitThread(p->Thread, INFINITE);
		ReleaseThread(p->Thread);
	}
	if (p->Listener != INVALID_SOCKET && p->Listener != 0)
	{
		closesocket(p->Listener);
	}
	if (p->Stop != NULL)
	{
		CloseHandle(p->Stop);
	}
	Zero(p, sizeof(PROXYTEST_PROXY));
}

// What a test proxy saw of its last connection, and how many it took
static UINT ProxyTestSeen(PROXYTEST_PROXY *p, char *peer, UINT peer_size, char *target, UINT target_size)
{
	AcquireSRWLockShared(&p->Lock);
	UINT num = p->NumConnections;
	if (peer != NULL)
	{
		StrCpy(peer, peer_size, p->Peer);
	}
	if (target != NULL)
	{
		StrCpy(target, target_size, p->Target);
	}
	ReleaseSRWLockShared(&p->Lock);

	return num;
}

//
// The PAC server
//

// The thread of the PAC server: every request gets the script, then the connection closes
static void ProxyTestPacThread(THREAD *thread, void *param)
{
	PROXYTEST_PAC *pac = (PROXYTEST_PAC *)param;
	char head[MAX_SIZE];
	char request[MAX_SIZE * 4];

	while (WaitForSingleObject(pac->Stop, 0) != WAIT_OBJECT_0)
	{
		UINT size = 0;

		if (ProxyTestReadable(pac->Listener, PROXYTEST_POLL, pac->Stop) == false)
		{
			continue;
		}

		SOCKET c = accept(pac->Listener, NULL, NULL);
		if (c == INVALID_SOCKET)
		{
			continue;
		}

		// The request up to its empty line, then the script
		Zero(request, sizeof(request));
		while (size < sizeof(request) - 1 && strstr(request, "\r\n\r\n") == NULL && ProxyTestReadable(c, PROXYTEST_TIMEOUT, pac->Stop))
		{
			int n = recv(c, request + size, (int)(sizeof(request) - 1 - size), 0);
			if (n <= 0)
			{
				break;
			}
			size += (UINT)n;
		}

		if (strstr(request, "\r\n\r\n") != NULL)
		{
			Format(head, sizeof(head), "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
				StrLen(pac->Script));
			if (ProxyTestSendAll(c, head, StrLen(head)) && ProxyTestSendAll(c, pac->Script, StrLen(pac->Script)))
			{
				InterlockedIncrement(&pac->NumRequests);
			}
		}

		shutdown(c, SD_SEND);
		closesocket(c);
	}
}

//
// The server and the clients
//

// The configuration of an end of a test session
static void ProxyTestConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 1000;
	c->DeadTimeout = PROXYTEST_TIMEOUT;
}

// The server thread: each stream gets the responder of a Noise session, which echoes every control and data record
// until the client closes
static void ProxyTestServerThread(THREAD *thread, void *param)
{
	PROXYTEST_SERVER *srv = (PROXYTEST_SERVER *)param;
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);

	while (WaitForSingleObject(srv->Stop, 0) != WAIT_OBJECT_0)
	{
		NOISE_SESSION_CONFIG c;
		TRANSPORT_STREAM *s = TransportAccept(srv->Listener, PROXYTEST_POLL);

		if (s == NULL)
		{
			continue;
		}

		TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
		ProxyTestConfig(&c, srv->Key, NULL);
		if (TransportNoiseAccept(n, s, &c, PROXYTEST_TIMEOUT))
		{
			InterlockedIncrement(&srv->NumSessions);
			TransportNoiseAcceptLogin(n);

			while (true)
			{
				UINT size = 0;
				UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, PROXYTEST_TIMEOUT);

				if (ret != NOISE_RECEIVE_DATA && ret != NOISE_RECEIVE_CONTROL)
				{
					break;
				}
				TransportNoiseSend(n, (ret == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
			}
		}

		TransportNoiseClose(n);
		Free(n);
	}

	Free(buf);
}

// The client's end of a session over stream s: the Noise session comes up, and a control and a data record go to the
// server and come back. The session takes s.
static bool ProxyTestSession(TRANSPORT_STREAM *s, UCHAR *server_pub)
{
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	NOISE_SESSION_CONFIG c;
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;
	bool ok = false;

	CryptoX25519GenerateKey(key, pub);
	ProxyTestConfig(&c, key, server_pub);

	if (s != NULL && TransportNoiseConnect(n, s, &c, PROXYTEST_TIMEOUT))
	{
		bool control = TransportNoiseSend(n, NOISE_RECORD_CONTROL, "hello", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, PROXYTEST_TIMEOUT) == NOISE_RECEIVE_CONTROL && size == 5 && Cmp(buf, "hello", 5) == 0;
		bool data = TransportNoiseSend(n, NOISE_RECORD_DATA, "frame", 5) &&
			TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, PROXYTEST_TIMEOUT) == NOISE_RECEIVE_DATA && size == 5 && Cmp(buf, "frame", 5) == 0;
		ok = (control && data);
	}

	TransportNoiseClose(n);
	Zero(key, sizeof(key));
	Free(buf);
	Free(n);

	return ok;
}

// A path of a proxy mode and address, and of an underlay
static void ProxyTestPath(TRANSPORT_PATH *path, UINT proxy, char *proxy_address, char *interface_name, char *local)
{
	Zero(path, sizeof(TRANSPORT_PATH));
	path->Proxy = proxy;
	StrCpy(path->ProxyAddress, sizeof(path->ProxyAddress), proxy_address != NULL ? proxy_address : "");
	StrCpy(path->Interface, sizeof(path->Interface), interface_name != NULL ? interface_name : "");
	StrCpy(path->Local, sizeof(path->Local), local != NULL ? local : "");
}

// A client of the TLS transport along path dials address, cancelled at cancel (which may be NULL), and the Noise session
// runs over the stream: true when the session came up and echoed. *dialled tells whether the dial gave a stream, after
// its TLS handshake; *elapsed, which may be NULL, how long the dial took (ms).
static bool ProxyTestDial(PROXYTEST *t, TRANSPORT_PATH *path, char *address, HANDLE cancel, bool *dialled, UINT64 *elapsed)
{
	TRANSPORT_TLS_CONFIG cfg;
	TRANSPORT_TLS_INFO info;
	bool ok = false;

	*dialled = false;
	TransportTlsDefaultConfig(&cfg, t->Thumbprint, false);
	cfg.SetGroups = false;
	Copy(&cfg.Path, path, sizeof(TRANSPORT_PATH));

	TRANSPORT *client = TransportTlsClientNew(&cfg);
	if (client != NULL)
	{
		UINT64 start = Tick64();
		TRANSPORT_STREAM *s = TransportDial(client, address, cancel);

		if (elapsed != NULL)
		{
			*elapsed = Tick64() - start;
		}
		*dialled = (s != NULL && TransportTlsLastHandshake(client, &info) && (info.Version == TRANSPORT_TLS_13 || info.Version == TRANSPORT_TLS_12));
		ok = ProxyTestSession(s, t->Server.Pub);
		TransportTlsFree(client);
	}

	return ok;
}

// A dial that is to give no stream: true when it gave none
static bool ProxyTestNoDial(PROXYTEST *t, TRANSPORT_PATH *path, char *address)
{
	bool dialled = false;

	ProxyTestDial(t, path, address, NULL, &dialled, NULL);

	return (dialled == false);
}

//
// The checks
//

// What proxies answer, and the lists of WinHTTP, on answers and lists made here
static void ProxyTestParsers(PROXYTEST_CTX *ctx)
{
	static char *lists[][3] =
	{
		{"proxy.example:8080", "proxy.example", "8080"},
		{"proxy.example", "proxy.example", "80"},
		{"http=a.example:80;https=b.example:3128", "b.example", "3128"},
		{"  ;a.example:1 b.example:2", "a.example", "1"},
		{"[2001:db8::1]:3128", "2001:db8::1", "3128"},
		{"http://proxy.example:8080/", "proxy.example", "8080"},
		{"d.example:8080;https=c.example:443", "c.example", "443"},
		{"a.example:0;b.example:99999;c.example:8080", "c.example", "8080"},
		{"http=a.example:80", NULL, NULL},
		{"socks=s.example:1080", NULL, NULL},
		{"", NULL, NULL},
	};
	static char *bypass[][3] =
	{
		{"<local>", "vpn", "1"},
		{"<local>", "vpn.example", "0"},
		{"*.example.com", "a.EXAMPLE.com", "1"},
		{"*.example.com", "example.com", "0"},
		{"10.*", "10.1.2.3", "1"},
		{"10.*", "110.1.2.3", "0"},
		{"", "127.0.0.1", "1"},
		{"", "localhost", "1"},
		{"", "::1", "1"},
		{"<-loopback>", "127.0.0.1", "0"},
		{"<-loopback>;127.*", "127.0.0.1", "1"},
		{"", "vpn.example", "0"},
	};
	static UCHAR socks_v4[] = {5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38};
	static UCHAR socks_refused[] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
	static UCHAR socks_name[] = {5, 0, 0, 3, 3, 'a', '.', 'b', 0, 80};
	static UCHAR socks_v6[22] = {5, 0, 0, 4};
	static UCHAR socks_bad_version[] = {4, 0, 0, 1, 127, 0, 0, 1, 0, 80};
	static UCHAR socks_bad_type[] = {5, 0, 0, 2, 127, 0, 0, 1, 0, 80};
	char host[MAX_SIZE], port[MAX_SIZE];
	UINT used = 0, code = 0;
	bool ok = true;
	char *a;

	Print("[what proxies answer, and the proxy and bypass lists of WinHTTP]\n");

	a = "HTTP/1.1 200 Connection established\r\n\r\n";
	ok = (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_DONE && used == StrLen(a) && code == 200);
	a = "HTTP/1.0 200 OK\nProxy-Agent: vpntest\n\n";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_DONE && used == StrLen(a) && code == 200);
	a = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_DONE && used == StrLen(a) && code == 407);
	a = "HTTP/1.1 200 OK\r\n\r\nX";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_DONE && used == StrLen(a) - 1);
	ProxyTestCheck(ctx, ok, "an HTTP proxy's answer: a 200 and a 407, with CRLF or LF line ends, ends at its empty line", "the parse disagrees");

	a = "HTTP/1.1 200 Connection est";
	ok = (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_MORE);
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,3, &used, &code) == TRANSPORT_PROXY_MORE);
	a = "SSH-2.0-OpenSSH_9.6\r\n";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_BAD);
	a = "HTTP/1.1 2000 OK\r\n\r\n";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_BAD);
	a = "HTTP/2 200\r\n\r\n";
	ok = ok && (TransportProxyParseHttp((UCHAR *)a,StrLen(a), &used, &code) == TRANSPORT_PROXY_BAD);
	UCHAR *big = ZeroMalloc(TRANSPORT_PROXY_ANSWER_MAX + 64);
	StrCpy((char *)big, TRANSPORT_PROXY_ANSWER_MAX + 64, "HTTP/1.1 200 OK\r\nX-Pad: ");
	for (UINT i = StrLen((char *)big);i < TRANSPORT_PROXY_ANSWER_MAX + 32;i++)
	{
		big[i] = 'a';
	}
	ok = ok && (TransportProxyParseHttp(big, TRANSPORT_PROXY_ANSWER_MAX + 32, &used, &code) == TRANSPORT_PROXY_BAD);
	Free(big);
	ProxyTestCheck(ctx, ok, "an HTTP answer cut short waits for more; one that is no HTTP/1.x status line, or longer than the limit, is refused", "the parse disagrees");

	ok = (TransportProxyParseSocks(socks_v4, sizeof(socks_v4), &used, &code) == TRANSPORT_PROXY_DONE && used == 10 && code == 0);
	ok = ok && (TransportProxyParseSocks(socks_refused, sizeof(socks_refused), &used, &code) == TRANSPORT_PROXY_DONE && used == 10 && code == 5);
	ok = ok && (TransportProxyParseSocks(socks_name, sizeof(socks_name), &used, &code) == TRANSPORT_PROXY_DONE && used == 10 && code == 0);
	ok = ok && (TransportProxyParseSocks(socks_v6, sizeof(socks_v6), &used, &code) == TRANSPORT_PROXY_DONE && used == 22);
	ok = ok && (TransportProxyParseSocks(socks_v4, 5, &used, &code) == TRANSPORT_PROXY_MORE && TransportProxyParseSocks(socks_name, 4, &used, &code) == TRANSPORT_PROXY_MORE);
	ok = ok && (TransportProxyParseSocks(socks_bad_version, sizeof(socks_bad_version), &used, &code) == TRANSPORT_PROXY_BAD);
	ok = ok && (TransportProxyParseSocks(socks_bad_type, sizeof(socks_bad_type), &used, &code) == TRANSPORT_PROXY_BAD);
	ProxyTestCheck(ctx, ok, "a SOCKS5 reply with an IPv4 address, a name or an IPv6 address ends at its port; another version or address type is refused",
		"the parse disagrees");

	ok = true;
	for (UINT i = 0;i < sizeof(lists) / sizeof(lists[0]);i++)
	{
		bool found = TransportProxyParseList(lists[i][0], host, sizeof(host), port, sizeof(port));
		bool right = (lists[i][1] == NULL ? found == false : (found && StrCmp(host, lists[i][1]) == 0 && StrCmp(port, lists[i][2]) == 0));
		if (right == false)
		{
			Print("  the list \"%s\" gave %s:%s (found %u)\n", lists[i][0], host, port, (UINT)found);
			ok = false;
		}
	}
	ProxyTestCheck(ctx, ok, "a proxy list of WinHTTP: the entry for https first, then one without a scheme; ports, brackets and http:// as WinHTTP writes them",
		"an entry was taken wrong");

	ok = true;
	for (UINT i = 0;i < sizeof(bypass) / sizeof(bypass[0]);i++)
	{
		bool direct = TransportProxyBypass(bypass[i][0], bypass[i][1]);
		if (direct != (bypass[i][2][0] == '1'))
		{
			Print("  the bypass list \"%s\" sends %s %s\n", bypass[i][0], bypass[i][1], direct ? "direct" : "through the proxy");
			ok = false;
		}
	}
	ok = ok && TransportProxyBypass(NULL, "vpn.example") == false && TransportProxyBypass(NULL, "127.0.0.1");
	ProxyTestCheck(ctx, ok, "a bypass list of WinHTTP: <local>, wildcards and case; a loopback server goes direct unless <-loopback>", "a host was sent wrong");
}

// An HTTP proxy
static void ProxyTestHttpProxy(PROXYTEST *t)
{
	PROXYTEST_CTX *ctx = &t->Ctx;
	TRANSPORT_PATH path;
	char proxy[MAX_SIZE], address[MAX_SIZE], target[MAX_SIZE], expect[MAX_SIZE];
	bool dialled = false;

	Print("[an HTTP proxy: CONNECT]\n");
	Format(proxy, sizeof(proxy), "127.0.0.1:%u", (UINT)t->Http.Port);
	Format(address, sizeof(address), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);
	ProxyTestPath(&path, TRANSPORT_PROXY_HTTP, proxy, NULL, NULL);

	InterlockedExchange(&t->Http.Answer, PROXYTEST_OPEN);
	UINT before = ProxyTestSeen(&t->Http, NULL, 0, NULL, 0);
	bool ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
	UINT after = ProxyTestSeen(&t->Http, NULL, 0, target, sizeof(target));
	Format(expect, sizeof(expect), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);
	ProxyTestCheck(ctx, dialled && ok && after == before + 1, "behind the HTTP proxy, the client completes the TLS handshake and the Noise session comes up over the tunnel",
		"dialled %u, session %u, connections to the proxy %u", (UINT)dialled, (UINT)ok, after - before);
	ProxyTestCheck(ctx, StrCmp(target, expect) == 0, "the CONNECT names the server's name and port, which only the proxy resolves", "it named \"%s\"", target);

	InterlockedExchange(&t->Http.Answer, PROXYTEST_REFUSE);
	ok = ProxyTestNoDial(t, &path, address);
	InterlockedExchange(&t->Http.Answer, PROXYTEST_GARBAGE);
	ok = ProxyTestNoDial(t, &path, address) && ok;
	InterlockedExchange(&t->Http.Answer, PROXYTEST_OPEN);
	ProxyTestCheck(ctx, ok, "a 403 of the proxy, and an answer that is no HTTP, fail the dial", "a dial got a stream");

	ProxyTestPath(&path, TRANSPORT_PROXY_HTTP, "127.0.0.1", NULL, NULL);
	ProxyTestCheck(ctx, ProxyTestNoDial(t, &path, address), "a proxy address without a port fails the dial", "the dial got a stream");
}

// A SOCKS5 proxy
static void ProxyTestSocksProxy(PROXYTEST *t)
{
	PROXYTEST_CTX *ctx = &t->Ctx;
	TRANSPORT_PATH path;
	char proxy[MAX_SIZE], address[MAX_SIZE], target[MAX_SIZE], expect[MAX_SIZE];
	char *hosts[3] = {PROXYTEST_NAME, "127.0.0.1", "[::1]"};
	char *types[3] = {"name " PROXYTEST_NAME, "ipv4 127.0.0.1", "ipv6 [::1]"};
	char *what[3] =
	{
		"behind the SOCKS5 proxy, a session to the server's name, which the proxy resolves (CONNECT of a name)",
		"behind the SOCKS5 proxy, a session to an IPv4 address (CONNECT of an IPv4 address)",
		"behind the SOCKS5 proxy, a session to an IPv6 address (CONNECT of an IPv6 address)",
	};
	bool dialled = false;

	Print("[a SOCKS5 proxy]\n");
	Format(proxy, sizeof(proxy), "127.0.0.1:%u", (UINT)t->Socks.Port);
	ProxyTestPath(&path, TRANSPORT_PROXY_SOCKS5, proxy, NULL, NULL);

	for (UINT i = 0;i < 3;i++)
	{
		Format(address, sizeof(address), "%s:%u", hosts[i], (UINT)t->Server.Port);
		Format(expect, sizeof(expect), "%s:%u", types[i], (UINT)t->Server.Port);
		bool ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
		ProxyTestSeen(&t->Socks, NULL, 0, target, sizeof(target));
		ProxyTestCheck(ctx, dialled && ok && StrCmp(target, expect) == 0, what[i], "dialled %u, session %u, the request named \"%s\"", (UINT)dialled, (UINT)ok, target);
	}

	Format(address, sizeof(address), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);
	InterlockedExchange(&t->Socks.Answer, PROXYTEST_REFUSE);
	bool ok = ProxyTestNoDial(t, &path, address);
	InterlockedExchange(&t->Socks.Answer, PROXYTEST_GARBAGE);
	ok = ProxyTestNoDial(t, &path, address) && ok;
	InterlockedExchange(&t->Socks.Answer, PROXYTEST_OPEN);
	ProxyTestCheck(ctx, ok, "a refusal of the proxy (reply 5), and a method that the client did not offer, fail the dial", "a dial got a stream");
}

// The cancel of a dial: set after PROXYTEST_CANCEL ms
static void ProxyTestCancelThread(THREAD *thread, void *param)
{
	SleepThread(PROXYTEST_CANCEL);
	SetEvent((HANDLE)param);
}

// The system's proxy through WinHTTP: a PAC script of the path, one that never comes, and the system's settings
static void ProxyTestSystem(PROXYTEST *t)
{
	PROXYTEST_CTX *ctx = &t->Ctx;
	PROXYTEST_PAC *pac = ZeroMalloc(sizeof(PROXYTEST_PAC));
	TRANSPORT_PATH path;
	char url[MAX_SIZE], address[MAX_SIZE], target[MAX_SIZE];
	USHORT hold_port = 0;
	bool dialled = false;
	UINT64 elapsed = 0;

	Print("[the system's proxy, through WinHTTP]\n");

	// The script: the server's name through the HTTP proxy, everything else direct
	Format(pac->Script, sizeof(pac->Script),
		"function FindProxyForURL(url, host) { if (host == \"%s\") return \"PROXY 127.0.0.1:%u\"; return \"DIRECT\"; }\n", PROXYTEST_NAME, (UINT)t->Http.Port);
	pac->Listener = ProxyTestListen("127.0.0.1", &pac->Port);
	pac->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (ProxyTestCheck(ctx, pac->Listener != INVALID_SOCKET && pac->Stop != NULL, "a PAC script is served over HTTP on a test port", "it cannot listen"))
	{
		pac->Thread = NewThread(ProxyTestPacThread, pac);
		Format(url, sizeof(url), "http://127.0.0.1:%u/proxy.pac", (UINT)pac->Port);
		ProxyTestPath(&path, TRANSPORT_PROXY_SYSTEM, url, NULL, NULL);

		Format(address, sizeof(address), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);
		UINT before = ProxyTestSeen(&t->Http, NULL, 0, NULL, 0);
		bool ok = ProxyTestDial(t, &path, address, NULL, &dialled, &elapsed);
		UINT after = ProxyTestSeen(&t->Http, NULL, 0, target, sizeof(target));
		Print("  the dial took %u ms; the PAC server answered %u requests\n", (UINT)elapsed, (UINT)pac->NumRequests);
		ProxyTestCheck(ctx, dialled && ok && after == before + 1 && pac->NumRequests != 0,
			"the PAC script sends the server's name through the HTTP proxy, and the session comes up over the tunnel",
			"dialled %u, session %u, connections to the proxy %u, PAC requests %u", (UINT)dialled, (UINT)ok, after - before, (UINT)pac->NumRequests);

		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)t->Server.Port);
		before = ProxyTestSeen(&t->Http, NULL, 0, NULL, 0);
		ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
		after = ProxyTestSeen(&t->Http, NULL, 0, NULL, 0);
		ProxyTestCheck(ctx, dialled && ok && after == before, "the PAC script sends the server's address direct", "dialled %u, session %u, connections to the proxy %u",
			(UINT)dialled, (UINT)ok, after - before);

		SetEvent(pac->Stop);
		WaitThread(pac->Thread, INFINITE);
		ReleaseThread(pac->Thread);
	}

	// A PAC script that never comes: a listener that takes connections and never answers. The dial returns at once when
	// it is cancelled; the lookup ends on its own once the listener closes.
	SOCKET hold = ProxyTestListen("127.0.0.1", &hold_port);
	HANDLE cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (ProxyTestCheck(ctx, hold != INVALID_SOCKET && cancel != NULL, "a PAC server that never answers listens on a test port", "it cannot listen"))
	{
		Format(url, sizeof(url), "http://127.0.0.1:%u/never.pac", (UINT)hold_port);
		ProxyTestPath(&path, TRANSPORT_PROXY_SYSTEM, url, NULL, NULL);
		Format(address, sizeof(address), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);

		THREAD *canceller = NewThread(ProxyTestCancelThread, cancel);
		bool ok = ProxyTestDial(t, &path, address, cancel, &dialled, &elapsed);
		WaitThread(canceller, INFINITE);
		ReleaseThread(canceller);
		Print("  the cancelled dial returned after %u ms\n", (UINT)elapsed);
		ProxyTestCheck(ctx, dialled == false && ok == false && elapsed < PROXYTEST_CANCELLED,
			"a dial whose PAC script does not come returns at once when it is cancelled", "dialled %u, after %u ms", (UINT)dialled, (UINT)elapsed);
	}
	if (hold != INVALID_SOCKET)
	{
		closesocket(hold);
	}
	if (cancel != NULL)
	{
		CloseHandle(cancel);
	}

	// The system's settings: a loopback server goes direct, as in WinINet, whatever proxy they name
	ProxyTestPath(&path, TRANSPORT_PROXY_SYSTEM, NULL, NULL, NULL);
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)t->Server.Port);
	bool ok = ProxyTestDial(t, &path, address, NULL, &dialled, &elapsed);
	Print("  the dial along the system's settings took %u ms\n", (UINT)elapsed);
	ProxyTestCheck(ctx, dialled && ok, "along the system's settings, a loopback server is dialled direct and the session comes up", "dialled %u, session %u",
		(UINT)dialled, (UINT)ok);

	if (pac->Listener != INVALID_SOCKET && pac->Listener != 0)
	{
		closesocket(pac->Listener);
	}
	if (pac->Stop != NULL)
	{
		CloseHandle(pac->Stop);
	}
	Free(pac);
}

// The interfaces of the machine: the loopback interface, and the first other one that is up with an IPv4 address that
// is not a link-local one; false when it has no loopback interface
static bool ProxyTestInterfaces(PROXYTEST_INTERFACE *loopback, PROXYTEST_INTERFACE *other)
{
	ULONG size = 65536;
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	IP_ADAPTER_ADDRESSES *list = Malloc(size);
	bool found = false;

	Zero(loopback, sizeof(PROXYTEST_INTERFACE));
	Zero(other, sizeof(PROXYTEST_INTERFACE));

	if (GetAdaptersAddresses(AF_INET, flags, NULL, list, &size) == NO_ERROR)
	{
		for (IP_ADAPTER_ADDRESSES *a = list;a != NULL;a = a->Next)
		{
			PROXYTEST_INTERFACE *i = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK ? loopback : other);

			if (a->OperStatus != IfOperStatusUp || i->Index != 0)
			{
				continue;
			}

			for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress;u != NULL;u = u->Next)
			{
				struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
				char str[64];

				if (sa->sin_family != AF_INET || (ntohl(sa->sin_addr.s_addr) >> 16) == 0xA9FE)
				{
					continue;
				}

				inet_ntop(AF_INET, &sa->sin_addr, str, sizeof(str));
				if (WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, i->Alias, sizeof(i->Alias), NULL, NULL) == 0)
				{
					continue;
				}
				StrCpy(i->Address, sizeof(i->Address), str);
				i->Index = a->IfIndex;
				found = found || (i == loopback);
				break;
			}
		}
	}

	Free(list);
	return found;
}

// The underlay: a local address and an interface, through the relay and the HTTP proxy
static void ProxyTestUnderlay(PROXYTEST *t)
{
	PROXYTEST_CTX *ctx = &t->Ctx;
	PROXYTEST_INTERFACE loopback, other;
	TRANSPORT_PATH path;
	char address[MAX_SIZE], proxy[MAX_SIZE], peer[64], index[16];
	bool dialled = false;

	Print("[the underlay: a local address and an interface]\n");
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)t->Relay.Port);

	ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, NULL, PROXYTEST_LOCAL);
	bool ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
	ProxyTestSeen(&t->Relay, peer, sizeof(peer), NULL, 0);
	ProxyTestCheck(ctx, dialled && ok && StrCmp(peer, PROXYTEST_LOCAL) == 0, "bound to the local address " PROXYTEST_LOCAL ", the client reaches the server from it",
		"dialled %u, session %u, the relay saw %s", (UINT)dialled, (UINT)ok, peer);

	Format(proxy, sizeof(proxy), "127.0.0.1:%u", (UINT)t->Http.Port);
	ProxyTestPath(&path, TRANSPORT_PROXY_HTTP, proxy, NULL, PROXYTEST_LOCAL);
	Format(address, sizeof(address), "%s:%u", PROXYTEST_NAME, (UINT)t->Server.Port);
	ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
	ProxyTestSeen(&t->Http, peer, sizeof(peer), NULL, 0);
	ProxyTestCheck(ctx, dialled && ok && StrCmp(peer, PROXYTEST_LOCAL) == 0, "bound to " PROXYTEST_LOCAL ", the client reaches the HTTP proxy from it",
		"dialled %u, session %u, the proxy saw %s", (UINT)dialled, (UINT)ok, peer);

	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)t->Relay.Port);
	ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, NULL, PROXYTEST_NO_ADDRESS);
	ProxyTestCheck(ctx, ProxyTestNoDial(t, &path, address), "a local address that the machine does not have fails the dial", "the dial got a stream");
	ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, NULL, "not-an-address");
	ProxyTestCheck(ctx, ProxyTestNoDial(t, &path, address), "a local address that is not a numeric one fails the dial", "the dial got a stream");

	if (ProxyTestCheck(ctx, ProxyTestInterfaces(&loopback, &other), "the machine has a loopback interface", "GetAdaptersAddresses lists none"))
	{
		Print("  the loopback interface: \"%s\", index %u, %s\n", loopback.Alias, loopback.Index, loopback.Address);
		Format(index, sizeof(index), "%u", loopback.Index);

		ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, loopback.Alias, NULL);
		ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
		ProxyTestSeen(&t->Relay, peer, sizeof(peer), NULL, 0);
		ProxyTestCheck(ctx, dialled && ok && StrCmp(peer, loopback.Address) == 0, "bound to the loopback interface by its alias, the client reaches the server from its address",
			"dialled %u, session %u, the relay saw %s", (UINT)dialled, (UINT)ok, peer);

		ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, index, PROXYTEST_LOCAL);
		ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
		ProxyTestSeen(&t->Relay, peer, sizeof(peer), NULL, 0);
		ProxyTestCheck(ctx, dialled && ok && StrCmp(peer, PROXYTEST_LOCAL) == 0,
			"bound to the loopback interface by its index and to " PROXYTEST_LOCAL ", the client reaches the server from that address", "dialled %u, session %u, the relay saw %s",
			(UINT)dialled, (UINT)ok, peer);
	}

	ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, PROXYTEST_NO_ALIAS, NULL);
	ok = ProxyTestNoDial(t, &path, address);
	ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, PROXYTEST_NO_INDEX, NULL);
	ok = ProxyTestNoDial(t, &path, address) && ok;
	ProxyTestCheck(ctx, ok, "an interface alias or an index that the machine does not have fails the dial", "a dial got a stream");

	// A non-loopback interface: a relay on every address, dialled at the interface's address through the interface
	if (other.Index == 0)
	{
		Print("  the machine has no other interface with an IPv4 address that is up: the check of a non-loopback interface is skipped\n");
		return;
	}

	PROXYTEST_PROXY *relay = ZeroMalloc(sizeof(PROXYTEST_PROXY));
	Print("  a non-loopback interface: \"%s\", index %u, %s\n", other.Alias, other.Index, other.Address);
	if (ProxyTestCheck(ctx, ProxyTestProxyStart(relay, PROXYTEST_RELAY, "0.0.0.0", t->Server.Port), "a relay listens on every address", "it cannot listen"))
	{
		Format(address, sizeof(address), "%s:%u", other.Address, (UINT)relay->Port);
		ProxyTestPath(&path, TRANSPORT_PROXY_NONE, NULL, other.Alias, NULL);
		ok = ProxyTestDial(t, &path, address, NULL, &dialled, NULL);
		ProxyTestSeen(relay, peer, sizeof(peer), NULL, 0);
		ProxyTestCheck(ctx, dialled && ok && StrCmp(peer, other.Address) == 0, "bound to a non-loopback interface by its alias, the client reaches the server from its address",
			"dialled %u, session %u, the relay saw %s", (UINT)dialled, (UINT)ok, peer);
	}
	ProxyTestProxyStop(relay);
	Free(relay);
}

RANZ_TEST_TAGS("proxy", proxy_test, "core", "The outbound path of the TLS-443 client: an HTTP CONNECT proxy, a SOCKS5 proxy and the system's proxy through WinHTTP (a PAC script) on test ports, and the underlay bound to a local address and an interface.");
void proxy_test(UINT num, char **arg)
{
	PROXYTEST *t = ZeroMalloc(sizeof(PROXYTEST));
	PROXYTEST_CTX *ctx = &t->Ctx;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ProxyTestWatchdog, done, 0, NULL) : NULL);
	UINT scope = 0;

	Print("Proxy test: the outbound path of the TLS-443 client: an HTTP proxy, a SOCKS5 proxy, the system's proxy through WinHTTP, and the underlay\n");

	ProxyTestParsers(ctx);

	if (ProxyTestCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed"))
	{
		// The server certificate: a self-signed one in the current user's My store, its key in the KSP, which the server
		// loads and the clients pin
		PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(PROXYTEST_CN, PROXYTEST_SAN, NULL, 30, scope);
		bool have = (cert != NULL && CryptoCertThumbprintStr(cert, t->Thumbprint, sizeof(t->Thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
		TRANSPORT_TLS_CONFIG cfg;

		TransportTlsDefaultConfig(&cfg, t->Thumbprint, false);
		cfg.SetGroups = false;
		t->Server.Transport = (have ? TransportTlsServerNew(&cfg) : NULL);
		t->Server.Listener = (t->Server.Transport != NULL ? TransportListen(t->Server.Transport, ":0") : NULL);
		t->Server.Port = (t->Server.Listener != NULL ? TransportTlsBoundPort(t->Server.Transport) : 0);
		t->Server.Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
		CryptoX25519GenerateKey(t->Server.Key, t->Server.Pub);

		if (ProxyTestCheck(ctx, t->Server.Listener != NULL && t->Server.Stop != NULL, "the TLS-443 server listens on a test port of every address",
			"the certificate, the transport or the listener failed"))
		{
			t->Server.Thread = NewThread(ProxyTestServerThread, &t->Server);

			bool proxies = ProxyTestProxyStart(&t->Http, PROXYTEST_HTTP, "127.0.0.1", 0) && ProxyTestProxyStart(&t->Socks, PROXYTEST_SOCKS, "127.0.0.1", 0) &&
				ProxyTestProxyStart(&t->Relay, PROXYTEST_RELAY, "127.0.0.1", t->Server.Port);
			if (ProxyTestCheck(ctx, proxies, "the test proxies and the relay listen on test ports of the loopback interface", "one cannot listen"))
			{
				ProxyTestHttpProxy(t);
				ProxyTestSocksProxy(t);
				ProxyTestSystem(t);
				ProxyTestUnderlay(t);
			}

			ProxyTestProxyStop(&t->Relay);
			ProxyTestProxyStop(&t->Socks);
			ProxyTestProxyStop(&t->Http);

			SetEvent(t->Server.Stop);
			WaitThread(t->Server.Thread, INFINITE);
			ReleaseThread(t->Server.Thread);
			Print("  the server had %u Noise sessions\n", (UINT)t->Server.NumSessions);
		}

		TransportCloseListener(t->Server.Listener);
		TransportTlsFree(t->Server.Transport);
		if (t->Server.Stop != NULL)
		{
			CloseHandle(t->Server.Stop);
		}
		Zero(t->Server.Key, sizeof(t->Server.Key));

		if (cert != NULL)
		{
			CryptoCertRemoveFromStore(t->Thumbprint, NULL, scope);
			CryptoCertDeleteKey(cert);
			CryptoCertFree(cert);
		}
	}

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx->NumFailed == 0)
	{
		Print("PROXY TEST OK\n");
	}
	else
	{
		Print("PROXY TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(t);
}
