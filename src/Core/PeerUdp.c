// PeerUdp.c
// A UDP socket of the peer layer on Winsock: dual-stack, on the wildcard address, with one receive thread that
// drains the socket into PeerInput and runs PeerTick. It stands in for the QUIC datagrams of CORE-S1-1 (#67),
// which the relay will take on the QUIC listener on UDP 443 (ADR-0035).

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "Core/PeerInternal.h"

#include <stdio.h>
#include <string.h>

#define PEER_UDP_TICK 1000 // ms between two PeerTick calls of the receive thread

struct PEER_UDP {
	SOCKET Socket;     // The socket
	USHORT Port;       // Its port
	WSAEVENT Event;    // Signalled while it holds datagrams (WSAEventSelect, FD_READ)
	HANDLE StopEvent;  // Ends the receive thread
	HANDLE Thread;     // The receive thread, NULL before PeerUdpStart
	PEER_AGENT *Agent; // The peer layer that the datagrams go to
	bool WsaStarted;   // WSAStartup succeeded
};

// The PEER_ADDR of a socket address; false for a family other than IPv4 and IPv6
static bool PeerUdpFromSockaddr(PEER_ADDR *a, const SOCKADDR_STORAGE *sa) {
	ZeroMemory(a, sizeof(PEER_ADDR));

	if (sa->ss_family == AF_INET6) {
		const SOCKADDR_IN6 *in6 = (const SOCKADDR_IN6 *)sa;

		CopyMemory(a->Ip, &in6->sin6_addr, sizeof(a->Ip));
		a->Port = ntohs(in6->sin6_port);
		return true;
	}

	if (sa->ss_family == AF_INET) {
		const SOCKADDR_IN *in = (const SOCKADDR_IN *)sa;
		const UCHAR *b = (const UCHAR *)&in->sin_addr;

		PeerAddrSetV4(a, b[0], b[1], b[2], b[3], ntohs(in->sin_port));
		return true;
	}

	return false;
}

// The IPv6 socket address of a PEER_ADDR; an IPv4 address stays IPv4-mapped, which the dual-stack socket sends
// over IPv4
static void PeerUdpToSockaddr(SOCKADDR_IN6 *sa, const PEER_ADDR *a) {
	ZeroMemory(sa, sizeof(SOCKADDR_IN6));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(a->Port);
	CopyMemory(&sa->sin6_addr, a->Ip, sizeof(a->Ip));
}

// Open a UDP socket on port of the wildcard address, IPv4 and IPv6 (0 for a port that the system picks). NULL when
// the socket cannot be opened or bound.
PEER_UDP *PeerUdpNew(USHORT port) {
	WSADATA wsa;
	SOCKADDR_IN6 sa;
	int sa_len = sizeof(sa);
	DWORD off = 0;
	BOOL no_reset = FALSE;
	DWORD ret = 0;

	PEER_UDP *u = (PEER_UDP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEER_UDP));
	if (u == NULL)
		return NULL;

	u->Socket = INVALID_SOCKET;
	u->WsaStarted = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	if (u->WsaStarted)
		u->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (u->Socket == INVALID_SOCKET) {
		PeerUdpFree(u);
		return NULL;
	}

	// Dual-stack; and an ICMP port unreachable after a send must not fail the next receive (SIO_UDP_CONNRESET)
	setsockopt(u->Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof(off));
	WSAIoctl(u->Socket, SIO_UDP_CONNRESET, &no_reset, sizeof(no_reset), NULL, 0, &ret, NULL, NULL);

	// The zero address is the wildcard ::
	ZeroMemory(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(port);

	if (bind(u->Socket, (const SOCKADDR *)&sa, sizeof(sa)) != 0 || getsockname(u->Socket, (SOCKADDR *)&sa, &sa_len) != 0) {
		PeerUdpFree(u);
		return NULL;
	}
	u->Port = ntohs(sa.sin6_port);

	// WSAEventSelect makes the socket non-blocking: the receive thread drains it until WSAEWOULDBLOCK
	u->Event = WSACreateEvent();
	u->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (u->Event == WSA_INVALID_EVENT || u->StopEvent == NULL || WSAEventSelect(u->Socket, u->Event, FD_READ) != 0) {
		PeerUdpFree(u);
		return NULL;
	}

	return u;
}

// The port of the socket
USHORT PeerUdpPort(PEER_UDP *u) {
	return (u != NULL ? u->Port : 0);
}

// The PEER_SEND_PROC of a socket: param is the PEER_UDP
bool PeerUdpSend(void *param, const PEER_ADDR *dst, const void *data, UINT size) {
	PEER_UDP *u = (PEER_UDP *)param;
	SOCKADDR_IN6 sa;

	if (u == NULL || dst == NULL || data == NULL || size == 0 || size > PEER_MAX_DATAGRAM)
		return false;

	PeerUdpToSockaddr(&sa, dst);

	return sendto(u->Socket, (const char *)data, (int)size, 0, (const SOCKADDR *)&sa, sizeof(sa)) == (int)size;
}

// Hand every datagram that the socket holds to the peer layer
static void PeerUdpDrain(PEER_UDP *u) {
	UCHAR buf[PEER_MAX_DATAGRAM];
	SOCKADDR_STORAGE from;
	PEER_ADDR a;

	while (true) {
		int from_len = sizeof(from);
		int n = recvfrom(u->Socket, (char *)buf, (int)sizeof(buf), 0, (SOCKADDR *)&from, &from_len);

		if (n == SOCKET_ERROR) {
			// A datagram larger than the buffer is dropped; anything else, WSAEWOULDBLOCK first, ends the drain
			if (WSAGetLastError() == WSAEMSGSIZE)
				continue;
			break;
		}

		if (n > 0 && PeerUdpFromSockaddr(&a, &from))
			PeerInput(u->Agent, &a, buf, (UINT)n);
	}
}

// The receive thread: it waits for datagrams or the stop event, and calls PeerTick every PEER_UDP_TICK
static DWORD WINAPI PeerUdpThread(void *param) {
	PEER_UDP *u = (PEER_UDP *)param;
	WSANETWORKEVENTS ne;
	HANDLE events[2];
	ULONGLONG next_tick = GetTickCount64() + PEER_UDP_TICK;

	// The stop event first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = u->StopEvent;
	events[1] = u->Event;

	while (true) {
		ULONGLONG now = GetTickCount64();
		DWORD wait = (now >= next_tick ? 0 : (DWORD)(next_tick - now));
		DWORD ret = WaitForMultipleObjects(2, events, FALSE, wait);

		if (ret == WAIT_OBJECT_0)
			break;

		if (ret == WAIT_OBJECT_0 + 1) {
			// Resets the event; recvfrom enables FD_READ again
			WSAEnumNetworkEvents(u->Socket, u->Event, &ne);
			PeerUdpDrain(u);
		}

		if (GetTickCount64() >= next_tick) {
			PeerTick(u->Agent);
			next_tick = GetTickCount64() + PEER_UDP_TICK;
		}
	}

	return 0;
}

// Start the receive thread, which hands the datagrams of the socket to the peer layer a. The layer sends through
// PeerUdpSend with u as its parameter, so it must be created on u before.
bool PeerUdpStart(PEER_UDP *u, PEER_AGENT *a) {
	if (u == NULL || a == NULL || u->Thread != NULL)
		return false;

	u->Agent = a;
	u->Thread = CreateThread(NULL, 0, PeerUdpThread, u, 0, NULL);

	return (u->Thread != NULL);
}

// Stop and join the receive thread, then close the socket. The peer layer that sends on it must not send any more;
// free it after this.
void PeerUdpFree(PEER_UDP *u) {
	if (u == NULL)
		return;

	if (u->Thread != NULL) {
		SetEvent(u->StopEvent);
		WaitForSingleObject(u->Thread, INFINITE);
		CloseHandle(u->Thread);
	}

	if (u->Socket != INVALID_SOCKET)
		closesocket(u->Socket);
	if (u->Event != NULL && u->Event != WSA_INVALID_EVENT)
		WSACloseEvent(u->Event);
	if (u->StopEvent != NULL)
		CloseHandle(u->StopEvent);
	if (u->WsaStarted)
		WSACleanup();

	HeapFree(GetProcessHeap(), 0, u);
}

// The text of an address: a.b.c.d:port for an IPv4-mapped address, [address]:port for IPv6
void PeerAddrToStr(char *str, UINT size, const PEER_ADDR *a) {
	static const UCHAR mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
	char ip[INET6_ADDRSTRLEN];

	if (str == NULL || size == 0)
		return;

	str[0] = 0;
	if (a == NULL)
		return;

	if (memcmp(a->Ip, mapped, sizeof(mapped)) == 0) {
		snprintf(str, size, "%u.%u.%u.%u:%u", a->Ip[12], a->Ip[13], a->Ip[14], a->Ip[15], a->Port);
		return;
	}

	if (inet_ntop(AF_INET6, a->Ip, ip, sizeof(ip)) == NULL)
		ip[0] = 0;

	snprintf(str, size, "[%s]:%u", ip, a->Port);
}
