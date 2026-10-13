// NetworkSocket.c
// Sockets: TCP connect, bind, listen and accept, send and receive, UDP, socket events and cancel objects, socket information, lifetime and timeouts

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "HTTP.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Pack.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <IcmpAPI.h>
#include "NetworkInternal.h"

typedef struct WIN32_ACCEPT_CHECK_DATA
{
	bool IsIPv6;
	bool Rejected;
} WIN32_ACCEPT_CHECK_DATA;

int CALLBACK Win32AcceptCheckCallback(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
                                      LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
                                      GROUP FAR *g, DWORD_PTR dwCallbackData)
{
	return CF_ACCEPT;
}

SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6)
{
	SOCKET ret;
	WIN32_ACCEPT_CHECK_DATA d;
	UINT err;
	int initial_addrlen = *addrlen;
	UINT num_error = 0;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	if (sock == NULL || s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (sock->hAcceptEvent == NULL)
	{
		sock->hAcceptEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

		WSAEventSelect(s, sock->hAcceptEvent, FD_ACCEPT | FD_CLOSE);
	}

L_LOOP:

	if (sock->CancelAccept)
	{
		return INVALID_SOCKET;
	}

	Zero(&d, sizeof(d));

	d.IsIPv6 = ipv6;

	*addrlen = initial_addrlen;
	Zero(addr, initial_addrlen);
	ret = WSAAccept(s, addr, addrlen, Win32AcceptCheckCallback, (DWORD_PTR)&d);

	if (ret == INVALID_SOCKET)
	{
		err = WSAGetLastError();

		if (err == WSAEWOULDBLOCK)
		{
			UINT wait_ret = WaitForSingleObject(sock->hAcceptEvent, 1234);

			if (wait_ret == WAIT_OBJECT_0 || wait_ret == WAIT_TIMEOUT)
			{
				goto L_LOOP;
			}

			Debug("!!! WaitForSingleObject Error. ret=%u GetLastError=%u\n", wait_ret, GetLastError());
		}

		num_error++;

		Debug("!!! WSAAccept Error: %u  rej=%u  num=%u  tick=%I64u\n", err, d.Rejected, num_error, Tick64());

		if (d.Rejected && err == WSAECONNREFUSED)
		{
			goto L_LOOP;
		}

		if (err == WSAETIMEDOUT)
		{
			goto L_LOOP;
		}
	}
	else
	{
		WSAEventSelect(ret, sock->hAcceptEvent, 0);

		WSAIoctl(ret, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);
	}

	return ret;
}

void Win32InitSocketLibrary()
{
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);
}

void Win32Cancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

void Win32CleanupCancel(CANCEL *c)
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

CANCEL *Win32NewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout)
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

void Win32CleanupSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

void Win32SetSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

SOCK_EVENT *Win32NewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
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

void Win32InitAsyncSocket(SOCK *sock)
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

void Win32FreeAsyncSocket(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	if (sock->hEvent != NULL)
	{
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	if (sock->SockEvent != NULL)
	{
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}

void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
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

UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_in addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock != NULL)
	{
		if (sock->IPv6)
		{
			return RecvFrom6(sock, src_addr, src_port, data, size);
		}

		sock->IgnoreRecvErr = false;
	}
	else
	{
		return 0;
	}

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
		InAddrToIP(src_addr, &addr.sin_addr);
		*src_port = (UINT)ntohs(addr.sin_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}
	else
	{
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
		return 0;
	}
}

UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_in6 addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock != NULL)
	{
		sock->IgnoreRecvErr = false;
	}
	else
	{
		return 0;
	}

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
		InAddrToIP6(src_addr, &addr.sin6_addr);
		src_addr->ipv6_scope_id = addr.sin6_scope_id;
		*src_port = (UINT)ntohs(addr.sin6_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}
	else
	{
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
		return 0;
	}
}

UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	return SendToEx(sock, dest_addr, dest_port, data, size, false);
}

UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in addr;
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
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

	if (sock->IPv6)
	{
		return SendTo6Ex(sock, dest_addr, dest_port, data, size, broadcast);
	}

	if (IsIP4(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	if (sock->IsRawSocket == false)
	{
		addr.sin_port = htons((USHORT)dest_port);
	}
	IPToInAddr(&addr.sin_addr, dest_addr);

	const BYTE *ipv4 = IPV4(dest_addr->address);
	if ((ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
		(ipv4[0] >= 224 && ipv4[0] <= 239) ||
		broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
		}
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in6 addr;
	UINT type;
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
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

	if (IsIP6(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (sock->IsRawSocket == false)
	{
		addr.sin6_port = htons((USHORT)dest_port);
	}
	IPToInAddr6(&addr.sin6_addr, dest_addr);
	addr.sin6_scope_id = dest_addr->ipv6_scope_id;

	type = GetIPAddrType6(dest_addr);

	if ((type & IPV6_ADDR_MULTICAST) || broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

SOCK *NewUDP(UINT port)
{
	return NewUDPEx2(port, false, NULL);
}

SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip)
{
	if (ipv6 == false)
	{
		return NewUDP4(port, ip);
	}
	else
	{
		return NewUDP6(port, ip);
	}
}

SOCK *NewUDPEx3(UINT port, IP *ip)
{
	if (ip == NULL)
	{
		return NewUDPEx2(port, false, NULL);
	}

	if (IsIP4(ip))
	{
		return NewUDPEx2(port, false, ip);
	}
	else
	{
		return NewUDPEx2(port, true, ip);
	}
}

SOCK *NewUDP4(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in addr;
	if (ip != NULL && IsIP4(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;

	if (ip == NULL || IsZeroIP(ip))
	{
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		IPToInAddr(&addr.sin_addr, ip);
	}

	if (port == 0 || IS_SPECIAL_PORT(port))
	{
		addr.sin_port = 0;
	}
	else
	{
		addr.sin_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		if (port != 0)
		{
			UINT true_flag = 1;
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				UINT false_flag = 0;
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef	SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
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
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize((int)s);

	if (IS_SPECIAL_PORT(port))
	{
		UINT no = 0;
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}

SOCK *NewUDP6(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in6 addr;
	if (ip != NULL && IsIP6(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET6, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (port == 0)
	{
		addr.sin6_port = 0;
	}
	else
	{
		addr.sin6_port = htons((USHORT)port);
	}

	if (ip != NULL && IsZeroIP(ip) == false)
	{
		IPToInAddr6(&addr.sin6_addr, ip);
		addr.sin6_scope_id = ip->ipv6_scope_id;
	}

	UINT true_flag = 1;
	UINT false_flag = 0;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		if (port != 0)
		{
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef	SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
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
	sock->IPv6 = true;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	if (IS_SPECIAL_PORT(port))
	{
		UINT no = 0;
#ifdef	IPV6_HDRINCL
		(void)setsockopt(sock->socket, IPPROTO_IP, IPV6_HDRINCL, (char *)&no, sizeof(no));
#endif
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
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

UINT Peek(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret;

	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (sock->AsyncMode)
	{
		return 0;
	}

	s = sock->socket;

	ret = recv(s, data, size, MSG_PEEK);


	if (ret > 0)
	{
		return ret;
	}

	return 0;
}

UINT Recv(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;

	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureRecv(sock, data, size);
	}

	s = sock->socket;

	ret = recv(s, data, size, 0);

	if (ret > 0)
	{
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

	if (sock->AsyncMode)
	{
		if (ret == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				return SOCK_LATER;
			}
			else
			{
			}
		}
	}

	Disconnect(sock);
	return 0;
}

UINT Send(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureSend(sock, data, size);
	}

	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0)
	{
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

	if (sock->AsyncMode)
	{
		if (ret == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				return SOCK_LATER;
			}
			else
			{
			}
		}
	}

	Disconnect(sock);
	return 0;
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

	sock->TimeOut = timeout;


	setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));

}

void AcceptInit(SOCK *s)
{
	AcceptInitEx(s, false);
}

SOCK *Accept(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in addr;
	UINT true_flag = 1;
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6)
	{
		return Accept6(sock);
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

	if (sock->EnableConditionalAccept)
	{
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr,(int *)&size, false);
	}
	else
	{
		new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
	}

	if (new_socket == INVALID_SOCKET)
	{
		if (sock->CancelAccept)
		{
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept)
	{
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(ret, TIMEOUT_INFINITE);

	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, false) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, false);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V4);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), "IPv4");

	return ret;
}

SOCK *Accept6(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in6 addr;
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6 == false)
	{
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

	if (sock->EnableConditionalAccept)
	{
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr,(int *)&size, true);
	}
	else
	{
		new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
	}

	if (new_socket == INVALID_SOCKET)
	{
		if (sock->CancelAccept)
		{
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept)
	{
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	UINT true_flag = 1;
	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(ret, TIMEOUT_INFINITE);

	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}
	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, true) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, true);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V6);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), "IPv6");

	return ret;
}

SOCK *ListenEx6(UINT port, bool local_only)
{
	return ListenEx63(port, local_only, false, NULL);
}

SOCK *ListenEx63(UINT port, bool local_only, bool enable_ca, IP *listen_ip)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in6 addr;
	struct in6_addr in;
	IP localhost;
	UINT backlog = SOMAXCONN;
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	GetLocalHostIP6(&localhost);

	addr.sin6_port = htons((UINT)port);
	if (listen_ip == NULL || IsZeroIP(listen_ip))
	{
		addr.sin6_addr = in6addr_any;
	}
	else if (IsIP6(listen_ip))
	{
		IPToInAddr6(&addr.sin6_addr, listen_ip);
	}
	else
	{
		return NULL;
	}
	addr.sin6_family = AF_INET6;

	if (local_only)
	{
		IPToInAddr6(&addr.sin6_addr, &localhost);

		enable_ca = false;
	}

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	UINT true_flag = 1;

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) != 0)
	{
		closesocket(s);
		return NULL;
	}

	if (enable_ca)
	{
		backlog = 1;
	}

	if (listen(s, backlog))
	{
		closesocket(s);
		return NULL;
	}

	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = true;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

SOCK *Listen(UINT port)
{
	return ListenEx(port, false);
}

SOCK *ListenEx(UINT port, bool local_only)
{
	return ListenEx2(port, local_only, false, NULL);
}

SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca, IP *listen_ip)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in addr;
	struct in_addr in;
	IP localhost;
	UINT backlog = SOMAXCONN;
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	SetIP(&localhost, 127, 0, 0, 1);

	addr.sin_port = htons((UINT)port);
	if (listen_ip == NULL || IsZeroIP(listen_ip))
	{
		*((UINT *)&addr.sin_addr) = htonl(INADDR_ANY);
	}
	else if (IsIP4(listen_ip))
	{
		IPToInAddr(&addr.sin_addr, listen_ip);
	}
	else
	{
		return NULL;
	}
	addr.sin_family = AF_INET;

	if (local_only)
	{
		IPToInAddr(&addr.sin_addr, &localhost);

		enable_ca = false;
	}

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	UINT true_flag = 1;

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0)
	{
		closesocket(s);
		return NULL;
	}

	if (enable_ca)
	{
		setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&true_flag, sizeof(true_flag));
		backlog = 1;
	}

	if (listen(s, backlog))
	{
		closesocket(s);
		return NULL;
	}

	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout)
{
	SOCK *s;
	if (hostname == NULL || port == 0 || port >= 65536)
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	s = ConnectEx4(hostname, port, timeout, NULL, true, NULL);
	if (s == NULL)
	{
		return false;
	}
	else
	{
		Disconnect(s);
		ReleaseSock(s);
		return true;
	}
}

char *PrintError(int ErrorCode)
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

int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	UINT64 start_time;
	bool ok = false;
	bool timeouted = false;
	WSAEVENT hEvent;
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

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	WSAEventSelect(s, hEvent, FD_CONNECT);

	start_time = Tick64();

	while (true)
	{
		int ret;

		ret = connect(s, addr, size);

		if (ret == 0)
		{
			ok = true;
			break;
		}
		else
		{
			int err = WSAGetLastError();
			if (timeouted && err == WSAEALREADY)
			{
				ok = false;
				break;
			}
			if (*cancel_flag)
			{
				ok = false;
				break;
			}
			if (err == WSAEISCONN || err == WSAEINVAL)
			{
				ok = true;
				break;
			}
			if (((start_time + (UINT64)timeout) <= Tick64()) || (err != WSAEWOULDBLOCK && err != WSAEALREADY))
			{
				break;
			}
			else
			{
				SleepThread(10);
				if (WaitForSingleObject(hEvent, 100) == WAIT_OBJECT_0)
				{
					timeouted = true;
				}
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

void SetSockTos(SOCK *s, int tos)
{
	if (s == NULL)
	{
		return;
	}

	if (s->CurrentTos == tos)
	{
		return;
	}

#ifdef	IP_TOS
	(void)setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int));
#endif

	s->CurrentTos = tos;
}

void SetSockHighPriority(SOCK *s, bool flag)
{
	if (s == NULL)
	{
		return;
	}

	SetSockTos(s, (flag ? 16 : 0));
}

int bind_sock(SOCKET sock, IP *ip, UINT port)
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

SOCKET BindConnectTimeoutIPv4(IP* localIP, UINT localport, IP* ip, UINT port, UINT timeout, bool* cancel_flag)
{
	SOCKET s;
	struct sockaddr_in sockaddr4;
	struct in_addr addr4;

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&addr4, sizeof(addr4));

	IPToInAddr(&addr4, ip);
	sockaddr4.sin_port = htons((USHORT)port);
	sockaddr4.sin_family = AF_INET;
	sockaddr4.sin_addr.s_addr = addr4.s_addr;

	s = socket(AF_INET, SOCK_STREAM, 0);

	if (s != INVALID_SOCKET) {
		int ier;
		IP tmpIP;
		IP *tmpIP2;

		if (localIP == BIND_LOCALIP_NULL) {
			StrToIP(&tmpIP, "0.0.0.0");	// A NULL address for the argument "localIP" is treated as if "0.0.0.0" in IPV4 was specified.
			tmpIP2 = &tmpIP;
		}
		else {
			tmpIP2 = localIP;
		}

		if ((IsZeroIP(tmpIP2) == false) || (localport != 0)) {

			if (bind_sock(s, tmpIP2, localport) != 0) {
				ier = WSAGetLastError();
				Debug("IPv4 bind() failed with error: %d %s\n", ier, PrintError(ier));
				closesocket(s);
				s = INVALID_SOCKET;
			}
		}
	}

	if (s != INVALID_SOCKET)
	{
		if (connect_timeout(s, (struct sockaddr *)&sockaddr4, sizeof(struct sockaddr_in), timeout, cancel_flag) != 0)
		{
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}

	return s;
}

void BindConnectThreadForIPv4(THREAD *thread, void *param)
{
	SOCKET s = INVALID_SOCKET;
	IP current_ip;
	UINT i;
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	Zero(&current_ip, sizeof(current_ip));

	for (i = 0; i < LIST_NUM(p->IpList); ++i)
	{
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIp(ip))
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

		s = BindConnectTimeoutIPv4(p->LocalIP, p->LocalPort, ip, p->Port, p->Timeout, p->CancelFlag);

		if (s != INVALID_SOCKET)
		{
			Copy(&current_ip, ip, sizeof(IP));

			Copy(p->Ret_Ip, ip, sizeof(IP));
		}

		if (s != INVALID_SOCKET)
		{
			p->Sock = CreateTCPSock(s, false, &current_ip, p->No_Get_Hostname, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

void BindConnectThreadForIPv6(THREAD* thread, void* param)
{
	SOCKET s = INVALID_SOCKET;
	IP current_ip;
	UINT i;
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	Zero(&current_ip, sizeof(current_ip));

	for (i = 0; i < LIST_NUM(p->IpList); ++i)
	{
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIp(ip))
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

		struct sockaddr_in6 sockaddr6;
		struct in6_addr addr6;

		Zero(&sockaddr6, sizeof(sockaddr6));
		Zero(&addr6, sizeof(addr6));

		IPToInAddr6(&addr6, ip);
		sockaddr6.sin6_port = htons((USHORT)p->Port);
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_scope_id = ip->ipv6_scope_id;
		Copy(&sockaddr6.sin6_addr, &addr6, sizeof(addr6));

		s = socket(AF_INET6, SOCK_STREAM, 0);

		if (s != INVALID_SOCKET){
			int ier;
			IP tmpIP;
			IP *tmpIP2;

			if (p->LocalIP == BIND_LOCALIP_NULL) {
				StrToIP(&tmpIP, "0::0");	// A NULL address for the argument "p->LocalIP" is treated as if "0::0" in IPV6 was specified.
				tmpIP2 = &tmpIP;
			}
			else {
				tmpIP2 = p->LocalIP;
			}

			if ((IsZeroIP(tmpIP2) == false) || (p->LocalPort != 0)){

				if (bind_sock(s, tmpIP2, p->LocalPort) != 0) {
					ier = WSAGetLastError();
					Debug("IPv6 bind() failed with error: %d %s\n", ier, PrintError(ier));
					closesocket(s);
					s = INVALID_SOCKET;
				}
			}
		}

		if (s != INVALID_SOCKET)
		{
			if (connect_timeout(s, (struct sockaddr *)&sockaddr6, sizeof(struct sockaddr_in6), p->Timeout, p->CancelFlag) != 0)
			{
				closesocket(s);
				s = INVALID_SOCKET;
			}
			else
			{
				Copy(&current_ip, ip, sizeof(IP));

				Copy(p->Ret_Ip, ip, sizeof(IP));
			}
		}

		if (s != INVALID_SOCKET)
		{
			p->Sock = CreateTCPSock(s, true, &current_ip, p->No_Get_Hostname, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, IP *current_ip, bool no_get_hostname, char *hostname_original)
{
	struct linger ling;
	char tmp[MAX_SIZE];
	SOCK *sock;

	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	StrCpy(sock->UnderlayProtocol, sizeof(sock->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);
	AddProtocolDetailsStr(sock->ProtocolDetails, sizeof(sock->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	if (no_get_hostname || (GetHostName(tmp, sizeof(tmp), current_ip) == false))
	{
		StrCpy(tmp, sizeof(tmp), hostname_original);
	}


	sock->RemoteHostname = CopyStr(tmp);


	Zero(&ling, sizeof(ling));

	UINT true_flag = 1;
#ifdef	SO_DONTLINGER
	(void)setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(true_flag));
#else
	UINT false_flag = 0;
	(void)setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(false_flag));
#endif

	(void)setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(sock, TIMEOUT_INFINITE);

	QuerySocketInformation(sock);

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, is_ipv6) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, is_ipv6);
		}
	}

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

SOCK *Connect(char *hostname, UINT port)
{
	return ConnectEx4(hostname, port, 0, NULL, true, NULL);
}

SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip)
{
	return BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, no_get_hostname, ret_ip);
}

SOCK *BindConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, bool no_get_hostname, IP *ret_ip)
{
	bool dummy = false;
	IP dummy_ret_ip;
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

	LIST *iplist_v6 = NULL;
	LIST *iplist_v4 = NULL;

	if (IsZeroIp(ret_ip) == false)
	{
		if (IsIP6(ret_ip))
		{
			iplist_v6 = NewListFast(NULL);
			AddHostIPAddressToList(iplist_v6, ret_ip);
		}
		else
		{
			iplist_v4 = NewListFast(NULL);
			AddHostIPAddressToList(iplist_v4, ret_ip);
		}

	}
	else
	{
		if (DnsResolveEx(&iplist_v6, &iplist_v4, hostname, 0, cancel_flag) == false)
		{
			return NULL;
		}
	}

	CONNECT_SERIAL_PARAM p4, p6;
	EVENT *finish_event;
	THREAD *t4 = NULL;
	THREAD *t6 = NULL;
	bool cancel_flag2 = false;
	bool no_delay_flag = false;
	IP ret_ip4, ret_ip6;

	finish_event = NewEvent();

	Zero(&p4, sizeof(p4));
	Zero(&p6, sizeof(p6));

	if (LIST_NUM(iplist_v6) > 0)
	{
		p6.IpList = iplist_v6;

		if (localIP == BIND_LOCALIP_NULL) {
			p6.LocalIP = BIND_LOCALIP_NULL;
		}
		else {
			CopyIP(&p6.LocalIP_Cache, localIP);
			p6.LocalIP = &p6.LocalIP_Cache;
		}
		p6.LocalPort = localport;

		p6.Port = port;
		p6.Timeout = timeout;
		StrCpy(p6.Hostname, sizeof(p6.Hostname), hostname);
		p6.No_Get_Hostname = no_get_hostname;
		p6.CancelFlag = &cancel_flag2;
		p6.NoDelayFlag = &no_delay_flag;
		p6.FinishEvent = finish_event;
		p6.Ret_Ip = &ret_ip6;
		p6.RetryDelay = 250;
		p6.Delay = 0;
		t6 = NewThread(BindConnectThreadForIPv6, &p6);
	}

	if (LIST_NUM(iplist_v4) > 0)
	{
		p4.IpList = iplist_v4;

		if (localIP == BIND_LOCALIP_NULL) {
			p4.LocalIP = BIND_LOCALIP_NULL;
		}
		else {
			CopyIP(&p4.LocalIP_Cache, localIP);
			p4.LocalIP = &p4.LocalIP_Cache;
		}
		p4.LocalPort = localport;

		p4.Port = port;
		p4.Timeout = timeout;
		StrCpy(p4.Hostname, sizeof(p4.Hostname), hostname);
		p4.No_Get_Hostname = no_get_hostname;
		p4.CancelFlag = &cancel_flag2;
		p4.NoDelayFlag = &no_delay_flag;
		p4.FinishEvent = finish_event;
		p4.Ret_Ip = &ret_ip4;
		p4.RetryDelay = 250;
		p4.Delay = 250;		// Delay by 250ms to prioritize IPv6 (RFC 6555 recommends 150-250ms, Chrome uses 300ms)
		t4 = NewThread(BindConnectThreadForIPv4, &p4);
	}

	if (t6 == NULL || t4 == NULL)
	{
		no_delay_flag = true;
	}

	while (true)
	{
		if (*cancel_flag)
		{
			break;
		}

		if ((t6 == NULL || p6.Finished) && (t4 == NULL || p4.Finished))
		{
			break;
		}

		if ((p6.Finished && p6.Ok) || (p4.Finished && p4.Ok))
		{
			break;
		}

		// This check must be placed last to avoid race condition with cancel flag
		if (no_delay_flag == false && (p6.Finished || p4.Finished))
		{
			no_delay_flag = true;
		}

		Wait(finish_event, 25);
	}

	cancel_flag2 = true;
	no_delay_flag = true;

	WaitThread(t6, INFINITE);
	WaitThread(t4, INFINITE);
	ReleaseThread(t6);
	ReleaseThread(t4);
	ReleaseEvent(finish_event);
	FreeHostIPAddressList(iplist_v6);
	FreeHostIPAddressList(iplist_v4);

	if (*cancel_flag)
	{
		Disconnect(p6.Sock);
		ReleaseSock(p6.Sock);
		Disconnect(p4.Sock);
		ReleaseSock(p4.Sock);

		return NULL;
	}

	if (p6.Ok)
	{
		Disconnect(p4.Sock);
		ReleaseSock(p4.Sock);
		Copy(ret_ip, &ret_ip6, sizeof(IP));
		return p6.Sock;
	}

	if (p4.Ok)
	{
		Disconnect(p6.Sock);
		ReleaseSock(p6.Sock);
		Copy(ret_ip, &ret_ip4, sizeof(IP));
		return p4.Sock;
	}

	return NULL;
}

void AddProtocolDetailsStr(char *dst, UINT dst_size, char *str)
{
	TOKEN_LIST *t1, *t2;
	UINT i, j;
	if (dst == NULL || str == NULL)
	{
		return;
	}

	t1 = ParseTokenWithoutNullStr(dst, " ");
	t2 = ParseTokenWithoutNullStr(str, " ");

	for (i = 0; i < t2->NumTokens; i++)
	{
		bool exists = false;
		for (j = 0; j < t1->NumTokens; j++)
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

void AddProtocolDetailsKeyValueStr(char *dst, UINT dst_size, char *key, char *value)
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

bool SetSocketBufferSize(SOCKET s, bool send, UINT size)
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

UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size)
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

void QuerySocketInformation(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_in6 sockaddr6;
		struct in6_addr *addr6;
		int size;
		UINT dw;
		UINT opt_value = 0;

		if (sock->Type == SOCK_TCP)
		{
			size = sizeof(sockaddr6);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
			{
				if (size >= sizeof(struct sockaddr_in6))
				{
					sock->RemotePort = (UINT)ntohs(sockaddr6.sin6_port);
					addr6 = &sockaddr6.sin6_addr;
					InAddrToIP6(&sock->RemoteIP, addr6);
					sock->RemoteIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
				}
				else
				{
					struct sockaddr_in *sockaddr;
					struct in_addr *addr;

					sockaddr = (struct sockaddr_in *)&sockaddr6;
					sock->RemotePort = (UINT)ntohs(sockaddr->sin_port);
					addr = &sockaddr->sin_addr;
					InAddrToIP(&sock->RemoteIP, addr);
				}
			}
		}

		size = sizeof(sockaddr6);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
		{
			if (size >= sizeof(struct sockaddr_in6))
			{
				sock->LocalPort = (UINT)ntohs(sockaddr6.sin6_port);
				addr6 = &sockaddr6.sin6_addr;
				InAddrToIP6(&sock->LocalIP, addr6);
				sock->LocalIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
			}
			else
			{
				struct sockaddr_in *sockaddr;
				struct in_addr *addr;

				sockaddr = (struct sockaddr_in *)&sockaddr6;
				sock->LocalPort = (UINT)ntohs(sockaddr->sin_port);
				addr = &sockaddr->sin_addr;
				InAddrToIP(&sock->LocalIP, addr);
			}
		}

		if (sock->IsRawSocket)
		{
			sock->LocalPort = sock->RemotePort = MAKE_SPECIAL_PORT(sock->RawSocketIPProtocol);
		}

		if (sock->Type == SOCK_UDP)
		{
			sock->UdpMaxMsgSize = UDP_MAX_MSG_SIZE_DEFAULT;

			if (true)
			{
				UINT max_value = 0;
				int len = sizeof(UINT);

				if (getsockopt(sock->socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&max_value, &len) == 0)
				{
					sock->UdpMaxMsgSize = max_value;
				}
			}
		}

		if (sock->IPv6)
		{
#ifdef	IPV6_UNICAST_HOPS
			opt_value = IPV6_UNICAST_HOPS;
#endif
		}
		else
		{
#ifdef	IP_TTL
			opt_value = IP_TTL;
#endif
		}

		size = sizeof(UINT);
		if (opt_value == 0 ||
		        getsockopt(sock->socket, (sock->IPv6 ? IPPROTO_IPV6 : IPPROTO_IP), opt_value, (char *)&dw, &size) != 0)
		{
			sock->IsTtlSupported = false;
		}
		else
		{
			sock->IsTtlSupported = true;
			sock->CurrentTtl = dw;
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
		if (s->ListenMode == false && s->ServerMode)
		{
			Print("");
		}
		CleanupSock(s);
	}
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
