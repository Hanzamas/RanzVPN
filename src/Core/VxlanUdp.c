// VxlanUdp.c
// The UDP socket of the VXLAN module on Winsock: dual-stack, on the wildcard address and the VXLAN port (or one that
// the system picks), held exclusively, with one receive thread that drains the socket into VxlanInput. A VTEP does not
// fragment a VXLAN datagram (RFC 7348 section 4.3): the socket sends with the don't-fragment bit, so a datagram above
// the path MTU fails instead, and the module counts the failed send.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "Core/Vxlan.h"

struct VXLAN_UDP {
	SOCKET Socket;    // The socket
	USHORT Port;      // Its port
	WSAEVENT Event;   // Signalled while it holds datagrams (WSAEventSelect, FD_READ)
	HANDLE StopEvent; // Ends the receive thread
	HANDLE Thread;    // The receive thread, NULL before VxlanUdpStart
	VXLAN *Vxlan;     // The module that the datagrams go to
	bool WsaStarted;  // WSAStartup succeeded
};

// The VXLAN_ADDR of a socket address; false for a family other than IPv4 and IPv6
static bool VxlanUdpFromSockaddr(VXLAN_ADDR *a, const SOCKADDR_STORAGE *sa) {
	ZeroMemory(a, sizeof(VXLAN_ADDR));

	if (sa->ss_family == AF_INET6) {
		const SOCKADDR_IN6 *in6 = (const SOCKADDR_IN6 *)sa;

		CopyMemory(a->Ip, &in6->sin6_addr, sizeof(a->Ip));
		a->Port = ntohs(in6->sin6_port);
		return true;
	}

	if (sa->ss_family == AF_INET) {
		const SOCKADDR_IN *in = (const SOCKADDR_IN *)sa;
		const UCHAR *b = (const UCHAR *)&in->sin_addr;

		VxlanAddrSetV4(a, b[0], b[1], b[2], b[3], ntohs(in->sin_port));
		return true;
	}

	return false;
}

// The IPv6 socket address of a VXLAN_ADDR; an IPv4 address stays IPv4-mapped, which the dual-stack socket sends over
// IPv4
static void VxlanUdpToSockaddr(SOCKADDR_IN6 *sa, const VXLAN_ADDR *a) {
	ZeroMemory(sa, sizeof(SOCKADDR_IN6));
	sa->sin6_family = AF_INET6;
	sa->sin6_port = htons(a->Port);
	CopyMemory(&sa->sin6_addr, a->Ip, sizeof(a->Ip));
}

// Open a UDP socket on port of the wildcard address, IPv4 and IPv6: VXLAN_PORT for the VTEP of a node, 0 for one that
// the system picks. NULL when the socket cannot be opened or bound, as when another socket holds the port.
VXLAN_UDP *VxlanUdpNew(USHORT port) {
	WSADATA wsa;
	SOCKADDR_IN6 sa;
	int sa_len = sizeof(sa);
	DWORD off = 0;
	DWORD on = 1;
	BOOL exclusive = TRUE;
	BOOL no_reset = FALSE;
	DWORD ret = 0;

	VXLAN_UDP *u = (VXLAN_UDP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VXLAN_UDP));
	if (u == NULL)
		return NULL;

	u->Socket = INVALID_SOCKET;
	u->WsaStarted = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	if (u->WsaStarted)
		u->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	if (u->Socket == INVALID_SOCKET) {
		VxlanUdpFree(u);
		return NULL;
	}

	// Dual-stack, and no other socket on the port (SO_EXCLUSIVEADDRUSE, before the bind); no datagram fragmented, over
	// IPv4 or IPv6; and an ICMP port unreachable after a send must not fail the next receive (SIO_UDP_CONNRESET)
	setsockopt(u->Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof(off));
	setsockopt(u->Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive));
	setsockopt(u->Socket, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&on, sizeof(on));
	setsockopt(u->Socket, IPPROTO_IPV6, IPV6_DONTFRAG, (const char *)&on, sizeof(on));
	WSAIoctl(u->Socket, SIO_UDP_CONNRESET, &no_reset, sizeof(no_reset), NULL, 0, &ret, NULL, NULL);

	// The zero address is the wildcard ::
	ZeroMemory(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(port);

	if (bind(u->Socket, (const SOCKADDR *)&sa, sizeof(sa)) != 0 || getsockname(u->Socket, (SOCKADDR *)&sa, &sa_len) != 0) {
		VxlanUdpFree(u);
		return NULL;
	}
	u->Port = ntohs(sa.sin6_port);

	// WSAEventSelect makes the socket non-blocking: the receive thread drains it until WSAEWOULDBLOCK
	u->Event = WSACreateEvent();
	u->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (u->Event == WSA_INVALID_EVENT || u->StopEvent == NULL || WSAEventSelect(u->Socket, u->Event, FD_READ) != 0) {
		VxlanUdpFree(u);
		return NULL;
	}

	return u;
}

// The port of the socket
USHORT VxlanUdpPort(VXLAN_UDP *u) {
	return (u != NULL ? u->Port : 0);
}

// The VXLAN_SEND_PROC of a socket: param is the VXLAN_UDP
bool VxlanUdpSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size) {
	VXLAN_UDP *u = (VXLAN_UDP *)param;
	SOCKADDR_IN6 sa;

	if (u == NULL || dst == NULL || data == NULL || size == 0 || size > VXLAN_MAX_DATAGRAM)
		return false;

	VxlanUdpToSockaddr(&sa, dst);

	return sendto(u->Socket, (const char *)data, (int)size, 0, (const SOCKADDR *)&sa, sizeof(sa)) == (int)size;
}

// Hand every datagram that the socket holds to the module
static void VxlanUdpDrain(VXLAN_UDP *u) {
	UCHAR buf[VXLAN_MAX_DATAGRAM];
	SOCKADDR_STORAGE from;
	VXLAN_ADDR a;

	while (true) {
		int from_len = sizeof(from);
		int n = recvfrom(u->Socket, (char *)buf, (int)sizeof(buf), 0, (SOCKADDR *)&from, &from_len);

		if (n == SOCKET_ERROR) {
			// A datagram larger than the buffer is dropped; anything else, WSAEWOULDBLOCK first, ends the drain
			if (WSAGetLastError() == WSAEMSGSIZE)
				continue;
			break;
		}

		if (n > 0 && VxlanUdpFromSockaddr(&a, &from))
			VxlanInput(u->Vxlan, &a, buf, (UINT)n);
	}
}

// The receive thread: it waits for datagrams or the stop event
static DWORD WINAPI VxlanUdpThread(void *param) {
	VXLAN_UDP *u = (VXLAN_UDP *)param;
	WSANETWORKEVENTS ne;
	HANDLE events[2];

	// The stop event first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = u->StopEvent;
	events[1] = u->Event;

	while (WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
		// Resets the event; recvfrom enables FD_READ again
		WSAEnumNetworkEvents(u->Socket, u->Event, &ne);
		VxlanUdpDrain(u);
	}

	return 0;
}

// Start the receive thread, which hands the datagrams of the socket to the module v. The module sends through
// VxlanUdpSend with u as its parameter, so it must be created on u before.
bool VxlanUdpStart(VXLAN_UDP *u, VXLAN *v) {
	if (u == NULL || v == NULL || u->Thread != NULL)
		return false;

	u->Vxlan = v;
	u->Thread = CreateThread(NULL, 0, VxlanUdpThread, u, 0, NULL);

	return (u->Thread != NULL);
}

// Stop and join the receive thread, then close the socket. The module that sends on it must not send any more; free
// it after this.
void VxlanUdpFree(VXLAN_UDP *u) {
	if (u == NULL)
		return;

	if (u->Thread != NULL) {
		SetEvent(u->StopEvent);
		WaitForSingleObject(u->Thread, INFINITE);
		CloseHandle(u->Thread);
	}

	if (u->Socket != INVALID_SOCKET)
		closesocket(u->Socket);
	if (u->Event != WSA_INVALID_EVENT)
		WSACloseEvent(u->Event);
	if (u->StopEvent != NULL)
		CloseHandle(u->StopEvent);
	if (u->WsaStarted)
		WSACleanup();

	HeapFree(GetProcessHeap(), 0, u);
}
