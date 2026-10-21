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
	HANDLE hEvent;
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	hEvent = event->hEvent;

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
	UINT n, i;
	SOCK *s;
	Zero(array, sizeof(array));
	n = 0;

	if (set != NULL)
	{
		for (i = 0; i < set->NumSocket; i++)
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
	CANCEL *c;
	if (hEvent == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CANCEL));
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
	const BYTE *ipv4;

	if (ipv6)
	{
		return (GetIPAddrType6(ip) & IPV6_ADDR_MULTICAST) != 0;
	}

	ipv4 = IPV4(ip->address);

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
	int addrlen;
	int ret;

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

	addrlen = UdpSockAddr(&addr, sock->IPv6, dest_addr, dest_port);
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

	ret = sendto(sock->socket, data, size, 0, (struct sockaddr *)&addr, addrlen);
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
	SOCK *sock;
	SOCKET s;
	struct sockaddr_storage addr;
	int addrlen;
	UINT true_flag = 1;

	addrlen = UdpSockAddr(&addr, ipv6, ip, port);
	if (addrlen == 0)
	{
		return NULL;
	}

	s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

	sock = NewSock();

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
	UINT recv_size, sz, ret;
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

	recv_size = 0;

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
	bool ret;
	if (sock == NULL || sock->AsyncMode != false)
	{
		return false;
	}
	if (sock->SendBuf->Size == 0)
	{
		return true;
	}

	ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
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
	UCHAR *buf;
	UINT sent_size;
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

	buf = (UCHAR *)data;
	sent_size = 0;

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
