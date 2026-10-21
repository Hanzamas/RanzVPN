// NetworkSocket.c
// Sockets: socket events and cancel objects, select, UDP, TCP connect and bind, listen, send and receive buffering, timeouts, socket information and buffer sizes

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

static void Win32Cancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

static void Win32CleanupCancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		CloseHandle(c->hEvent);
	}

	Free(c);
}

static CANCEL *Win32NewCancel()
{
	CANCEL *c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

static bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	if (event == NULL || timeout == 0)
	{
		return false;
	}

	if (WaitForSingleObject((HANDLE)event->hEvent, timeout) == WAIT_OBJECT_0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

static void Win32CleanupSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

static void Win32SetSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

static SOCK_EVENT *Win32NewSockEvent()
{
	SOCK_EVENT *e = ZeroMalloc(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

static void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	HANDLE hEvent = event->hEvent;

	WSAEventSelect(sock->socket, hEvent, FD_READ | FD_WRITE | FD_CLOSE);

	AddRef(event->ref);
	sock->SockEvent = event;
}

static void Win32InitAsyncSocket(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	sock->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	WSAEventSelect(sock->socket, sock->hEvent, FD_READ | FD_WRITE | FD_CLOSE);
}

static void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	SOCK *s;
	Zero(array, sizeof(array));
	UINT n = 0;

	if (set != NULL)
	{
		for (UINT i = 0; i < set->NumSocket; i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				Win32InitAsyncSocket(s);
				if (s->hEvent != NULL)
				{
					array[n++] = (HANDLE)s->hEvent;
				}
			}
		}
	}
	if (c1 != NULL && c1->hEvent != NULL)
	{
		array[n++] = c1->hEvent;
	}
	if (c2 != NULL && c2->hEvent != NULL)
	{
		array[n++] = c2->hEvent;
	}

	if (timeout == 0)
	{
		return;
	}

	if (n == 0)
	{
		SleepThread(timeout);
	}
	else
	{
		if (n == 1)
		{
			WaitForSingleObject(array[0], timeout);
		}
		else
		{
			WaitForMultipleObjects(n, array, false, timeout);
		}
	}
}

SOCK_EVENT *NewSockEvent()
{
	return Win32NewSockEvent();
}

void SetSockEvent(SOCK_EVENT *event)
{
	Win32SetSockEvent(event);
}

bool WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	bool ret = false;
	ret = Win32WaitSockEvent(event, timeout);
	return ret;
}

void ReleaseSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	if (Release(event->ref) == 0)
	{
		Win32CleanupSockEvent(event);
	}
}

void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	if (sock == NULL || event == NULL)
	{
		return;
	}

	Win32JoinSockToSockEvent(sock, event);
}

CANCEL *NewCancelSpecial(void *hEvent)
{
	if (hEvent == NULL)
	{
		return NULL;
	}

	CANCEL *c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = true;

	c->hEvent = (HANDLE)hEvent;

	return c;
}

CANCEL *NewCancel()
{
	CANCEL *c = NULL;
	c = Win32NewCancel();
	return c;
}

void ReleaseCancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		Win32CleanupCancel(c);
	}
}

void Cancel(CANCEL *c)
{
	Win32Cancel(c);
}

// Fill a sockaddr for a UDP socket of the given family and return its length, 0 if the IP is not of that
// family. A NULL or zero IP gives the any-address, which is what bind wants.
static int UdpSockAddr(struct sockaddr_storage *sa, bool ipv6, const IP *ip, UINT port)
{
	Zero(sa, sizeof(*sa));

	if (ipv6)
	{
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;

		if (ip != NULL && IsIP6(ip) == false)
		{
			return 0;
		}

		a6->sin6_family = AF_INET6;
		a6->sin6_port = htons((USHORT)port);

		if (ip != NULL && IsZeroIP(ip) == false)
		{
			IPToInAddr6(&a6->sin6_addr, ip);
			a6->sin6_scope_id = ip->ipv6_scope_id;
		}

		return sizeof(*a6);
	}
	else
	{
		struct sockaddr_in *a4 = (struct sockaddr_in *)sa;

		if (ip != NULL && IsIP4(ip) == false)
		{
			return 0;
		}

		a4->sin_family = AF_INET;
		a4->sin_port = htons((USHORT)port);

		if (ip != NULL && IsZeroIP(ip) == false)
		{
			IPToInAddr(&a4->sin_addr, ip);
		}

		return sizeof(*a4);
	}
}

// Read the source IP and port from the sockaddr that recvfrom filled in
static void UdpSockAddrToIP(IP *ip, UINT *port, struct sockaddr_storage *sa, bool ipv6)
{
	if (ipv6)
	{
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;

		InAddrToIP6(ip, &a6->sin6_addr);
		ip->ipv6_scope_id = a6->sin6_scope_id;
		*port = (UINT)ntohs(a6->sin6_port);
	}
	else
	{
		struct sockaddr_in *a4 = (struct sockaddr_in *)sa;

		InAddrToIP(ip, &a4->sin_addr);
		*port = (UINT)ntohs(a4->sin_port);
	}
}

// Whether a datagram to this address needs SO_BROADCAST: the IPv4 limited broadcast, or a multicast address
static bool UdpNeedsBroadcast(bool ipv6, const IP *ip)
{
	if (ipv6)
	{
		return (GetIPAddrType6(ip) & IPV6_ADDR_MULTICAST) != 0;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	return (ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
		(ipv4[0] >= 224 && ipv4[0] <= 239);
}

// The result of a failed recvfrom (send == false) or sendto (send == true): SOCK_LATER when the call would
// block, else 0. An error that only means "the datagram was lost" sets the Ignore flag of that direction.
static UINT UdpIoFailed(SOCK *sock, bool send)
{
	UINT e = (UINT)WSAGetLastError();

	if (e == WSAECONNRESET || e == WSAENETRESET || e == WSAEMSGSIZE || e == WSAENETUNREACH ||
	        e == WSAENOBUFS || e == WSAEHOSTUNREACH || e == WSAEUSERS || e == WSAEADDRNOTAVAIL ||
	        (send && e == WSAEINVAL))
	{
		if (send)
		{
			sock->IgnoreSendErr = true;
		}
		else
		{
			sock->IgnoreRecvErr = true;
		}
	}
	else if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS)
	{
		return SOCK_LATER;
	}
	else if (send == false)
	{
		Debug("RecvFrom(): recvfrom() failed with error: %u\n", e);
	}

	return 0;
}

UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_storage addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock == NULL)
	{
		return 0;
	}

	sock->IgnoreRecvErr = false;

	if (src_addr == NULL || src_port == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}

	ret = recvfrom(sock->socket, data, size, 0, (struct sockaddr *)&addr, &socklen);
	if (ret > 0)
	{
		UdpSockAddrToIP(src_addr, src_port, &addr, sock->IPv6);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}

	return UdpIoFailed(sock, false);
}

UINT SendTo(SOCK *sock, const IP *dest_addr, UINT dest_port, const void *data, UINT size)
{
	struct sockaddr_storage addr;

	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || dest_port == 0 || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	int addrlen = UdpSockAddr(&addr, sock->IPv6, dest_addr, dest_port);
	if (addrlen == 0)
	{
		return 0;
	}

	if (sock->UdpBroadcast == false && UdpNeedsBroadcast(sock->IPv6, dest_addr))
	{
		UINT yes = 1;

		sock->UdpBroadcast = true;

		(void)setsockopt(sock->socket, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
	}

	int ret = sendto(sock->socket, data, size, 0, (struct sockaddr *)&addr, addrlen);
	if (ret != (int)size)
	{
		return UdpIoFailed(sock, true);
	}

	return ret;
}

// Winsock reports an ICMP port or network unreachable, caused by an earlier datagram of a UDP socket, as
// WSAECONNRESET or WSAENETRESET on the next recvfrom() or sendto() of the socket. The error says nothing about
// the datagram at hand and every caller only skips it, so both reports are switched off.
static void DisableUdpReset(SOCKET s)
{
	BOOL off = FALSE;
	DWORD ret_size = 0;

	if (WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &ret_size, NULL, NULL) != 0)
	{
		Debug("DisableUdpReset(): SIO_UDP_CONNRESET failed with error: %u\n", WSAGetLastError());
	}

	if (WSAIoctl(s, SIO_UDP_NETRESET, &off, sizeof(off), NULL, 0, &ret_size, NULL, NULL) != 0)
	{
		Debug("DisableUdpReset(): SIO_UDP_NETRESET failed with error: %u\n", WSAGetLastError());
	}
}

SOCK *NewUDP(UINT port)
{
	return NewUDPEx2(port, false, NULL);
}
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip)
{
	struct sockaddr_storage addr;
	UINT true_flag = 1;

	int addrlen = UdpSockAddr(&addr, ipv6, ip, port);
	if (addrlen == 0)
	{
		return NULL;
	}

	SOCKET s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
	{
		if (port != 0)
		{
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
			{
				UINT false_flag = 0;
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
				if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
				{
					closesocket(s);
					return NULL;
				}
			}
		}
		else
		{
			closesocket(s);
			return NULL;
		}
	}

	SOCK *sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	sock->IPv6 = ipv6;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	DisableUdpReset(s);

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDPEx3(UINT port, IP *ip)
{
	return NewUDPEx2(port, ip != NULL && IsIP4(ip) == false, ip);
}

void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	Win32Select(set, timeout, c1, c2);
}

void AddSockSet(SOCKSET *set, SOCK *sock)
{
	if (set == NULL || sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_TCP && sock->Connected == false)
	{
		return;
	}

	if (set->NumSocket >= MAX_SOCKSET_NUM)
	{
		return;
	}
	set->Sock[set->NumSocket++] = sock;
}

void InitSockSet(SOCKSET *set)
{
	if (set == NULL)
	{
		return;
	}

	Zero(set, sizeof(SOCKSET));
}

bool RecvAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UINT sz, ret;
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}
	if (sock->AsyncMode)
	{
		return false;
	}

	UINT recv_size = 0;

	while (true)
	{
		sz = size - recv_size;
		ret = Recv(sock, (UCHAR *)data + recv_size, sz, secure);
		if (ret == 0)
		{
			return false;
		}
		if (ret == SOCK_LATER)
		{
			// Safe: RecvAll() runs only when AsyncMode is true, and Recv() returns
			// SOCK_LATER only when AsyncMode is false.
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

bool SendNow(SOCK *sock, int secure)
{
	if (sock == NULL || sock->AsyncMode != false)
	{
		return false;
	}
	if (sock->SendBuf->Size == 0)
	{
		return true;
	}

	bool ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
	ClearBuf(sock->SendBuf);

	return ret;
}

void SendAdd(SOCK *sock, void *data, UINT size)
{
	if (sock == NULL || data == NULL || size == 0 || sock->AsyncMode != false)
	{
		return;
	}

	WriteBuf(sock->SendBuf, data, size);
}

bool SendAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UINT ret;
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (sock->AsyncMode)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	UCHAR *buf = (UCHAR *)data;
	UINT sent_size = 0;

	while (true)
	{
		ret = Send(sock, buf, size - sent_size, secure);
		if (ret == 0)
		{
			return false;
		}
		sent_size += ret;
		buf += ret;
		if (sent_size >= size)
		{
			return true;
		}
	}
}

UINT GetTimeout(SOCK *sock)
{
	if (sock == NULL)
	{
		return INFINITE;
	}
	if (sock->Type != SOCK_TCP)
	{
		return INFINITE;
	}

	return sock->TimeOut;
}

void SetTimeout(SOCK *sock, UINT timeout)
{
	if (sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_UDP)
	{
		return;
	}

	if (timeout == INFINITE)
	{
		timeout = TIMEOUT_INFINITE;
	}

	// Same value again, or "no limit" on a socket whose timeouts were never set (the OS default): nothing to change
	if (timeout == sock->TimeOut || (timeout == TIMEOUT_INFINITE && sock->TimeOut == 0))
	{
		sock->TimeOut = timeout;
		return;
	}

	sock->TimeOut = timeout;

	setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));
}

void AcceptInit(SOCK *s)
{
	AcceptInitEx(s, false);
}

// True when a failed accept() of a listening socket may succeed on the next call: the peer reset or aborted the
// connection before it was accepted, or the process ran short of buffers or descriptors. Any other error, and a
// canceled accept (err 0), means that the listening socket must be rebuilt.
bool IsTransientAcceptError(UINT err)
{
	switch (err)
	{
	case WSAECONNRESET:
	case WSAECONNABORTED:
	case WSAENOBUFS:
	case WSAEMFILE:
		return true;

	default:
		return false;
	}
}

// A TCP socket bound to addr. An AF_INET6 socket gets IPV6_V6ONLY from v6only: false makes it dual-stack.
// bind_failed (may be NULL) tells a failed bind(), a port held or reserved, from a family the stack does not support.
static SOCKET ListenBind(struct sockaddr *addr, int addr_size, bool v6only, bool *bind_failed)
{
	SOCKET s = socket(addr->sa_family, SOCK_STREAM, 0);

	if (bind_failed != NULL)
	{
		*bind_failed = false;
	}

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (addr->sa_family == AF_INET6)
	{
		DWORD flag = (v6only ? 1 : 0);

		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flag, sizeof(flag)) != 0)
		{
			closesocket(s);
			return INVALID_SOCKET;
		}
	}

	if (bind(s, addr, addr_size) != 0)
	{
		if (bind_failed != NULL)
		{
			*bind_failed = true;
		}

		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// One TCP listen socket per port. Without a ListenIP it is a dual-stack AF_INET6 socket on [::]:port, so IPv4 peers
// arrive as ::ffff:a.b.c.d. AF_INET is used for an IPv4 ListenIP (127.0.0.1 for a local-only socket), ipv4_only or
// an unsupported IPv6.
SOCK *Listen(UINT port, IP *listen_ip, bool ipv4_only)
{
	SOCKET s = INVALID_SOCKET;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	bool is_ipv6 = false;
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	Zero(&addr4, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons((UINT)port);
	Zero(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons((UINT)port);

	if (listen_ip == NULL || IsZeroIP(listen_ip))
	{
		bool held = false;

		if (ipv4_only == false)
		{
			s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), false, &held);
			is_ipv6 = true;
		}

		// IPv6 is off or unsupported: IPv4 listens. A port another process holds or Windows reserves stays a failed
		// bind, so the listener reports it and retries instead of listening on one family only.
		if (s == INVALID_SOCKET && held == false)
		{
			s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false, NULL);
			is_ipv6 = false;
		}
	}
	else if (IsIP4(listen_ip))
	{
		IPToInAddr(&addr4.sin_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false, NULL);
	}
	else if (ipv4_only == false)
	{
		IPToInAddr6(&addr6.sin6_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), true, NULL);
		is_ipv6 = true;
	}

	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	if (listen(s, SOMAXCONN))
	{
		closesocket(s);
		return NULL;
	}

	SOCK *sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = is_ipv6;

	return sock;
}

static char *PrintError(int ErrorCode)
{
	char *Message;
	switch (ErrorCode) {
	case WSAEFAULT:
		Message = "Bad address.";
		break;

	case WSAEWOULDBLOCK:
		Message = "Resource temporarily unavailable.";
		break;

	case WSAEINPROGRESS:
		Message = "Operation now in progress.";
		break;

	case WSAEALREADY:
		Message = "Operation already in progress.";
		break;

	case WSAEAFNOSUPPORT:
		Message = "Address family not supported by protocol family.";
		break;

	case WSAEADDRINUSE:
		Message = "Address already in use.";
		break;

	case WSAEADDRNOTAVAIL:
		Message = "Cannot assign requested address.";
		break;

	case WSAEISCONN:
		Message = "Socket is already connected.";
		break;

	case WSAEINVAL:
		Message = "Invalid argument.";
		break;

	default:
		Message = "";
		break;
	}
	return Message;
}

static int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	bool ok = false;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	WSAEVENT hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// WSAEventSelect puts the socket in non-blocking mode; connect() is issued once and
	// its result arrives as FD_CONNECT, polled in 25 ms slices so the cancel flag is honoured
	WSAEventSelect(s, hEvent, FD_CONNECT);

	UINT64 end_time = Tick64() + (UINT64)timeout;

	if (connect(s, addr, size) == 0)
	{
		ok = true;
	}
	else if (WSAGetLastError() == WSAEWOULDBLOCK)
	{
		while (*cancel_flag == false && Tick64() < end_time)
		{
			WSANETWORKEVENTS events;

			if (WaitForSingleObject(hEvent, 25) != WAIT_OBJECT_0)
			{
				continue;
			}

			if (WSAEnumNetworkEvents(s, hEvent, &events) != 0)
			{
				break;
			}

			if (events.lNetworkEvents & FD_CONNECT)
			{
				ok = (events.iErrorCode[FD_CONNECT_BIT] == 0);
				break;
			}
		}
	}

	WSAEventSelect(s, hEvent, 0);

	WSAIoctl(s, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);

	CloseHandle(hEvent);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static int bind_sock(SOCKET sock, IP *ip, UINT port)
{

	if (IsIP4(ip))
	{
		struct sockaddr_in sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		sockaddr_in.sin_family = AF_INET;
		IPToInAddr(&sockaddr_in.sin_addr, ip);
		sockaddr_in.sin_port = htons((USHORT)port);

		UINT true_flag = 1;
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&true_flag, sizeof(true_flag));

		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	}
	else
	{
		struct sockaddr_in6 sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		sockaddr_in.sin6_family = AF_INET6;
		IPToInAddr6(&sockaddr_in.sin6_addr, ip);
		sockaddr_in.sin6_scope_id = ip->ipv6_scope_id;
		sockaddr_in.sin6_port = htons((USHORT)port);

		UINT true_flag = 1;
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&true_flag, sizeof(true_flag));

		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	}
}

static SOCKET BindConnectTimeout(bool ipv6, IP *localIP, UINT localport, IP *ip, UINT port, UINT timeout, bool *cancel_flag)
{
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;
	struct sockaddr *addr;
	int addr_size;
	IP tmpIP;
	IP *bind_ip = localIP;

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&sockaddr6, sizeof(sockaddr6));

	if (ipv6)
	{
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_port = htons((USHORT)port);
		sockaddr6.sin6_scope_id = ip->ipv6_scope_id;
		IPToInAddr6(&sockaddr6.sin6_addr, ip);
		addr = (struct sockaddr *)&sockaddr6;
		addr_size = sizeof(sockaddr6);
	}
	else
	{
		sockaddr4.sin_family = AF_INET;
		sockaddr4.sin_port = htons((USHORT)port);
		IPToInAddr(&sockaddr4.sin_addr, ip);
		addr = (struct sockaddr *)&sockaddr4;
		addr_size = sizeof(sockaddr4);
	}

	SOCKET s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (bind_ip == BIND_LOCALIP_NULL)
	{
		// A NULL local address is the unspecified address of the target family
		StrToIP(&tmpIP, ipv6 ? "0::0" : "0.0.0.0");
		bind_ip = &tmpIP;
	}

	if ((IsZeroIP(bind_ip) == false) || (localport != 0))
	{
		if (bind_sock(s, bind_ip, localport) != 0)
		{
			int ier = WSAGetLastError();
			Debug("IPv%d bind() failed with error: %d %s\n", ipv6 ? 6 : 4, ier, PrintError(ier));
			closesocket(s);
			return INVALID_SOCKET;
		}
	}

	if (connect_timeout(s, addr, addr_size, timeout, cancel_flag) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

static void BindConnectThread(THREAD *thread, void *param)
{
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	for (UINT i = 0; i < LIST_NUM(p->IpList); ++i)
	{
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIP(ip))
		{
			continue;
		}

		if (i > 0 && p->RetryDelay >= 1)
		{
			WaitEx(NULL, p->RetryDelay, p->CancelFlag);
		}

		if (*p->CancelFlag)
		{
			break;
		}

		SOCKET s = BindConnectTimeout(p->IPv6, p->LocalIP, p->LocalPort, ip, p->Port, p->Timeout, p->CancelFlag);

		if (s != INVALID_SOCKET)
		{
			Copy(p->Ret_Ip, ip, sizeof(IP));

			p->Sock = CreateTCPSock(s, p->IPv6, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->Finished = true;

	Set(p->FinishEvent);
}

SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, char *hostname_original)
{
	UINT true_flag = 1;

	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	SOCK *sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	StrCpy(sock->UnderlayProtocol, sizeof(sock->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);
	AddProtocolDetailsStr(sock->ProtocolDetails, sizeof(sock->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	sock->RemoteHostname = CopyStr(hostname_original);

	(void)setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(sock, TIMEOUT_INFINITE);

	QuerySocketInformation(sock);

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

SOCK *Connect(char *hostname, UINT port)
{
	return ConnectEx4(hostname, port, 0, NULL, NULL);
}
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, IP *ret_ip)
{
	return BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, ret_ip);
}

SOCK *BindConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, IP *ret_ip)
{
	bool dummy = false;
	IP dummy_ret_ip;
	LIST *iplists[2] = {NULL, NULL};	// [0] IPv6, [1] IPv4
	CONNECT_SERIAL_PARAM params[2];
	THREAD *threads[2] = {NULL, NULL};
	IP ret_ips[2];
	bool cancel_flag2 = false;
	bool no_delay_flag = false;
	SOCK *ret = NULL;
	if (hostname == NULL || port == 0 || port >= 65536 || IsEmptyStr(hostname))
	{
		return NULL;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}
	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy;
	}

	Zero(&dummy_ret_ip, sizeof(IP));
	if (ret_ip == NULL)
	{
		ret_ip = &dummy_ret_ip;
	}

	if (IsZeroIP(ret_ip) == false)
	{
		LIST **target = IsIP6(ret_ip) ? &iplists[0] : &iplists[1];

		*target = NewListFast(NULL);
		AddHostIPAddressToList(*target, ret_ip);
	}
	else
	{
		if (DnsResolveEx(&iplists[0], &iplists[1], hostname, 0, cancel_flag) == false)
		{
			return NULL;
		}
	}

	EVENT *finish_event = NewEvent();

	Zero(params, sizeof(params));
	Zero(ret_ips, sizeof(ret_ips));

	for (UINT i = 0; i < 2; ++i)
	{
		CONNECT_SERIAL_PARAM *p = &params[i];

		if (LIST_NUM(iplists[i]) == 0)
		{
			continue;
		}

		p->IpList = iplists[i];
		p->IPv6 = (i == 0);

		if (localIP == BIND_LOCALIP_NULL)
		{
			p->LocalIP = BIND_LOCALIP_NULL;
		}
		else
		{
			CopyIP(&p->LocalIP_Cache, localIP);
			p->LocalIP = &p->LocalIP_Cache;
		}
		p->LocalPort = localport;

		p->Port = port;
		p->Timeout = timeout;
		StrCpy(p->Hostname, sizeof(p->Hostname), hostname);
		p->CancelFlag = &cancel_flag2;
		p->NoDelayFlag = &no_delay_flag;
		p->FinishEvent = finish_event;
		p->Ret_Ip = &ret_ips[i];
		p->RetryDelay = 250;
		p->Delay = (p->IPv6 ? 0 : 250);		// Delay IPv4 by 250ms to prioritize IPv6 (RFC 6555 recommends 150-250ms, Chrome uses 300ms)
		threads[i] = NewThread(BindConnectThread, p);
	}

	if (threads[0] == NULL || threads[1] == NULL)
	{
		no_delay_flag = true;
	}

	while (true)
	{
		if (*cancel_flag)
		{
			break;
		}

		if ((threads[0] == NULL || params[0].Finished) && (threads[1] == NULL || params[1].Finished))
		{
			break;
		}

		if ((params[0].Finished && params[0].Ok) || (params[1].Finished && params[1].Ok))
		{
			break;
		}

		// This check must be placed last to avoid race condition with cancel flag
		if (no_delay_flag == false && (params[0].Finished || params[1].Finished))
		{
			no_delay_flag = true;
		}

		Wait(finish_event, 25);
	}

	cancel_flag2 = true;
	no_delay_flag = true;

	for (UINT i = 0; i < 2; ++i)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	ReleaseEvent(finish_event);
	FreeHostIPAddressList(iplists[0]);
	FreeHostIPAddressList(iplists[1]);

	// IPv6 wins over IPv4 when both connected; the losing socket (or both, on cancel) is closed
	for (UINT i = 0; i < 2; ++i)
	{
		if (*cancel_flag == false && ret == NULL && params[i].Ok)
		{
			ret = params[i].Sock;
			Copy(ret_ip, &ret_ips[i], sizeof(IP));
		}
		else
		{
			Disconnect(params[i].Sock);
			ReleaseSock(params[i].Sock);
		}
	}

	return ret;
}

void AddProtocolDetailsStr(char *dst, UINT dst_size, char *str)
{
	if (dst == NULL || str == NULL)
	{
		return;
	}

	TOKEN_LIST *t1 = ParseTokenWithoutNullStr(dst, " ");
	TOKEN_LIST *t2 = ParseTokenWithoutNullStr(str, " ");

	for (UINT i = 0; i < t2->NumTokens; i++)
	{
		bool exists = false;
		for (UINT j = 0; j < t1->NumTokens; j++)
		{
			if (StrCmpi(t1->Token[j], t2->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			StrCat(dst, dst_size, t2->Token[i]);
			StrCat(dst, dst_size, " ");
		}
	}

	FreeToken(t1);
	FreeToken(t2);
}

static void AddProtocolDetailsKeyValueStr(char *dst, UINT dst_size, char *key, char *value)
{
	char tmp[128];
	StrCpy(tmp, sizeof(tmp), key);
	StrCat(tmp, sizeof(tmp), "=");
	StrCat(tmp, sizeof(tmp), value);
	AddProtocolDetailsStr(dst, dst_size, tmp);
}

void AddProtocolDetailsKeyValueInt(char *dst, UINT dst_size, char *key, UINT value)
{
	char tmp[128];
	ToStr(tmp, value);
	AddProtocolDetailsKeyValueStr(dst, dst_size, key, tmp);
}

static bool SetSocketBufferSize(SOCKET s, bool send, UINT size)
{
	int value = (int)size;
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	if (setsockopt(s, SOL_SOCKET, (send ? SO_SNDBUF : SO_RCVBUF), (char *)&value, sizeof(int)) != 0)
	{
		return false;
	}

	return true;
}
static UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size)
{
	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	while (true)
	{
		if (SetSocketBufferSize(s, send, size))
		{
			return size;
		}

		size = (UINT)((double)size / 1.5);

		if (size <= 32767)
		{
			return 0;
		}
	}
}

void InitUdpSocketBufferSize(SOCKET s)
{
	SetSocketBufferSizeWithBestEffort(s, true, UDP_MAX_BUFFER_SIZE);
	SetSocketBufferSizeWithBestEffort(s, false, UDP_MAX_BUFFER_SIZE);
}

// Decode a socket address by its family. An IPv4-mapped IPv6 address (an IPv4 peer of a dual-stack socket)
// becomes an IPv4 IP.
static void DecodeSockAddr(struct sockaddr_storage *addr, IP *ip, UINT *port)
{
	if (addr->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		*port = (UINT)ntohs(addr6->sin6_port);
		InAddrToIP6(ip, &addr6->sin6_addr);
		ip->ipv6_scope_id = addr6->sin6_scope_id;
	}
	else if (addr->ss_family == AF_INET)
	{
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

		*port = (UINT)ntohs(addr4->sin_port);
		InAddrToIP(ip, &addr4->sin_addr);
	}
}

void QuerySocketInformation(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_storage sockaddr;
		int size;

		if (sock->Type == SOCK_TCP)
		{
			size = sizeof(sockaddr);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr, &size) == 0)
			{
				DecodeSockAddr(&sockaddr, &sock->RemoteIP, &sock->RemotePort);
			}
		}

		size = sizeof(sockaddr);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr, &size) == 0)
		{
			DecodeSockAddr(&sockaddr, &sock->LocalIP, &sock->LocalPort);
		}

	}
	Unlock(sock->lock);
}

void ReleaseSock(SOCK *s)
{
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSock(s);
	}
}
