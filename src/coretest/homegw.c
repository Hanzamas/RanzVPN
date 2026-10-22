// homegw.c
// The simulated home gateway of the ICE tests (ice.c; CORE-S5-3, #79): a UPnP Internet Gateway Device (UPnP Device
// Architecture 1.0, WANIPConnection:1) that libplum finds with SSDP and asks for a port mapping, and the port
// forwarding of the mapping it grants. Its WAN side is the IPv4 loopback, 127.0.0.1, and its home network the IPv6
// loopback, ::1, where the ICE socket of the node behind it is. A socket on the IPv4 loopback cannot send to the IPv6
// loopback, so a peer on the WAN side reaches that node only at the public port of the gateway.
//
// The gateway answers M-SEARCH on 239.255.255.250:1900, joined on every IPv4 interface since multicast loops back
// to the host on the interface it leaves by; it serves its description and its control URL over HTTP on 127.0.0.1;
// and it takes GetExternalIPAddress, AddPortMapping and DeletePortMapping. The mapping forwards what comes to its
// public port from an address of the WAN side to the internal port on ::1, from a port of its own for each such
// address (a flow), and sends what the node sends back to that port to the address of the flow, from the public
// port. With its link down (HomeGwSetLink) it forwards nothing, as a gateway whose WAN link failed.
//
// One thread serves everything: the SSDP socket, the HTTP listener, the public port and the flows.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>

#include "coretest.h"

#include <stdlib.h>
#include <string.h>

#define HOMEGW_SSDP_PORT 1900
#define HOMEGW_MAX_FLOWS 8    // WAN addresses that the mapping forwards for
#define HOMEGW_BUFFER    4096 // The largest datagram it forwards, and the largest HTTP request

// One address of the WAN side that the mapping forwards for, and the gateway's port for it on the home network
typedef struct HOMEGW_FLOW {
	SOCKADDR_IN Remote; // The address on the WAN side
	SOCKET Inside;      // The gateway's socket on ::1 for it
} HOMEGW_FLOW;

struct HOMEGW {
	bool WsaStarted;                     // WSAStartup succeeded
	SOCKET Ssdp;                         // UDP 1900, in the SSDP multicast group
	SOCKET Http;                         // The HTTP listener on 127.0.0.1
	USHORT HttpPort;                     // ... its port
	CRITICAL_SECTION Lock;               // The mapping, for HomeGwMapped
	SOCKET Wan;                          // The public port of the mapping on 127.0.0.1, INVALID_SOCKET for none
	USHORT External;                     // ... its number
	USHORT Internal;                     // The internal port on ::1 that it forwards to
	UINT NumFlows;                       // The flows of the mapping
	HOMEGW_FLOW Flows[HOMEGW_MAX_FLOWS]; // ... in the order they came
	volatile LONG Link;                  // 1 while the WAN link is up
	volatile LONG Searches;              // M-SEARCH requests answered
	volatile LONG Forwarded;             // Datagrams forwarded either way
	volatile LONG Stop;                  // Ends the thread
	HANDLE Thread;                       // The thread
};

// A non-blocking UDP socket on the loopback address of family at port, where an ICMP port unreachable does not fail
// the next receive; INVALID_SOCKET when it cannot be bound
static SOCKET HomeGwUdp(int family, USHORT port) {
	SOCKADDR_STORAGE sa;
	BOOL no_reset = FALSE;
	DWORD ret = 0;
	u_long nonblocking = 1;
	int len;

	SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	WSAIoctl(s, SIO_UDP_CONNRESET, &no_reset, sizeof(no_reset), NULL, 0, &ret, NULL, NULL);
	ioctlsocket(s, FIONBIO, &nonblocking);

	ZeroMemory(&sa, sizeof(sa));
	if (family == AF_INET) {
		SOCKADDR_IN *in = (SOCKADDR_IN *)&sa;

		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		len = sizeof(SOCKADDR_IN);
	} else {
		SOCKADDR_IN6 *in6 = (SOCKADDR_IN6 *)&sa;

		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		in6->sin6_addr.s6_addr[15] = 1;
		len = sizeof(SOCKADDR_IN6);
	}

	if (bind(s, (const SOCKADDR *)&sa, len) != 0) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Join the SSDP group on the interface of the IPv4 address ifaddr; a second join of one interface fails, which
// does no harm
static void HomeGwJoin(SOCKET s, IN_ADDR ifaddr) {
	IP_MREQ m;

	ZeroMemory(&m, sizeof(m));
	inet_pton(AF_INET, "239.255.255.250", &m.imr_multiaddr);
	m.imr_interface = ifaddr;
	setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&m, sizeof(m));
}

// Join the SSDP group on the default interface and on every IPv4 address of an interface that is up
static void HomeGwJoinAll(SOCKET s) {
	IN_ADDR any;
	ULONG size = 16384;
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

	any.s_addr = htonl(INADDR_ANY);
	HomeGwJoin(s, any);

	IP_ADAPTER_ADDRESSES *list = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, size);
	ULONG ret = (list != NULL ? GetAdaptersAddresses(AF_INET, flags, NULL, list, &size) : ERROR_NOT_ENOUGH_MEMORY);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		HeapFree(GetProcessHeap(), 0, list);
		list = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, size);
		ret = (list != NULL ? GetAdaptersAddresses(AF_INET, flags, NULL, list, &size) : ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ret == NO_ERROR) {
		for (IP_ADAPTER_ADDRESSES *ad = list; ad != NULL; ad = ad->Next) {
			if (ad->OperStatus != IfOperStatusUp)
				continue;
			for (IP_ADAPTER_UNICAST_ADDRESS *u = ad->FirstUnicastAddress; u != NULL; u = u->Next)
				if (u->Address.lpSockaddr->sa_family == AF_INET)
					HomeGwJoin(s, ((SOCKADDR_IN *)u->Address.lpSockaddr)->sin_addr);
		}
	}

	if (list != NULL)
		HeapFree(GetProcessHeap(), 0, list);
}

// Answer every M-SEARCH for an Internet Gateway Device with the location of the description
static void HomeGwSsdp(HOMEGW *g) {
	char buf[HOMEGW_BUFFER];
	char reply[512];
	SOCKADDR_STORAGE from;

	while (true) {
		int from_len = sizeof(from);
		int n = recvfrom(g->Ssdp, buf, sizeof(buf) - 1, 0, (SOCKADDR *)&from, &from_len);

		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEMSGSIZE)
				continue;
			break;
		}

		buf[n] = 0;
		if (strncmp(buf, "M-SEARCH", 8) != 0 || strstr(buf, "InternetGatewayDevice") == NULL)
			continue;

		int len = snprintf(reply, sizeof(reply), "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nLOCATION: http://127.0.0.1:%u/igd.xml\r\nSERVER: Windows/10 UPnP/1.1 coretest/1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:7e1a3b1c-0000-4000-8000-000000000079::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n", g->HttpPort);
		if (len > 0 && sendto(g->Ssdp, reply, len, 0, (const SOCKADDR *)&from, from_len) == len)
			InterlockedIncrement(&g->Searches);
	}
}

// The number in the element <name> of the request, 0 for none
static UINT HomeGwXmlNumber(const char *req, const char *name) {
	char tag[64];

	snprintf(tag, sizeof(tag), "<%s>", name);
	const char *p = strstr(req, tag);

	return (p != NULL ? (UINT)strtoul(p + strlen(tag), NULL, 10) : 0);
}

// Send an HTTP response with the body body
static void HomeGwRespond(SOCKET s, int code, const char *body) {
	char head[256];
	int body_len = (int)strlen(body);

	int len = snprintf(head, sizeof(head), "HTTP/1.0 %d %s\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", code, (code == 200 ? "OK" : "Internal Server Error"), body_len);
	if (len > 0)
		send(s, head, len, 0);
	if (body_len > 0)
		send(s, body, body_len, 0);
}

// A SOAP response of the WANIPConnection service with the content content
static void HomeGwSoap(SOCKET s, int code, const char *content) {
	char body[1024];

	snprintf(body, sizeof(body), "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>%s</s:Body></s:Envelope>\r\n", content);
	HomeGwRespond(s, code, body);
}

// Map the public port external on 127.0.0.1 to the internal port on ::1; false when the gateway has another
// mapping or the port is taken. The thread of the gateway only.
static bool HomeGwMap(HOMEGW *g, USHORT external, USHORT internal) {
	bool ok = false;

	EnterCriticalSection(&g->Lock);
	if (g->Wan != INVALID_SOCKET) {
		ok = (g->External == external);
		if (ok)
			g->Internal = internal;
	} else if (external != 0) {
		g->Wan = HomeGwUdp(AF_INET, external);
		ok = (g->Wan != INVALID_SOCKET);
		if (ok) {
			g->External = external;
			g->Internal = internal;
		}
	}
	LeaveCriticalSection(&g->Lock);

	return ok;
}

// Remove the mapping and its flows. The thread of the gateway only.
static void HomeGwUnmap(HOMEGW *g) {
	EnterCriticalSection(&g->Lock);
	if (g->Wan != INVALID_SOCKET)
		closesocket(g->Wan);
	g->Wan = INVALID_SOCKET;
	g->External = 0;
	g->Internal = 0;
	for (UINT i = 0; i < g->NumFlows; i++)
		closesocket(g->Flows[i].Inside);
	g->NumFlows = 0;
	LeaveCriticalSection(&g->Lock);
}

// One HTTP request: the description, or a SOAP action on the control URL
static void HomeGwHttp(HOMEGW *g) {
	static const char description[] = "<?xml version=\"1.0\"?>\r\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>coretest home gateway</friendlyName><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl</controlURL><eventSubURL>/evt</eventSubURL><SCPDURL>/scpd.xml</SCPDURL></service></serviceList></device></deviceList></device></deviceList></device></root>\r\n";
	char req[HOMEGW_BUFFER];
	int len = 0;
	u_long blocking = 0;
	DWORD timeout = 2000;

	SOCKET s = accept(g->Http, NULL, NULL);
	if (s == INVALID_SOCKET)
		return;

	// The request: its head, then the body of its Content-Length
	ioctlsocket(s, FIONBIO, &blocking);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	while (len < (int)sizeof(req) - 1) {
		int n = recv(s, req + len, (int)sizeof(req) - 1 - len, 0);
		if (n <= 0)
			break;
		len += n;
		req[len] = 0;

		const char *end = strstr(req, "\r\n\r\n");
		const char *length = strstr(req, "Content-Length:");
		if (end != NULL && (end + 4 - req) + (length != NULL ? atoi(length + 15) : 0) <= len)
			break;
	}
	req[len] = 0;

	if (strncmp(req, "GET /igd.xml ", 13) == 0) {
		HomeGwRespond(s, 200, description);
	} else if (strncmp(req, "POST /ctl ", 10) == 0 && strstr(req, "#GetExternalIPAddress") != NULL) {
		HomeGwSoap(s, 200, "<u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalIPAddress>127.0.0.1</NewExternalIPAddress></u:GetExternalIPAddressResponse>");
	} else if (strncmp(req, "POST /ctl ", 10) == 0 && strstr(req, "#AddPortMapping") != NULL) {
		UINT external = HomeGwXmlNumber(req, "NewExternalPort");
		UINT internal = HomeGwXmlNumber(req, "NewInternalPort");

		// 718: ConflictInMappingEntry, upon which libplum asks for another public port
		if (strstr(req, "<NewProtocol>UDP</NewProtocol>") != NULL && external <= 65535 && internal != 0 && internal <= 65535 && HomeGwMap(g, (USHORT)external, (USHORT)internal))
			HomeGwSoap(s, 200, "<u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse>");
		else
			HomeGwSoap(s, 500, "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault>");
	} else if (strncmp(req, "POST /ctl ", 10) == 0 && strstr(req, "#DeletePortMapping") != NULL) {
		HomeGwUnmap(g);
		HomeGwSoap(s, 200, "<u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse>");
	} else {
		HomeGwSoap(s, 500, "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>401</errorCode><errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault>");
	}

	shutdown(s, SD_SEND);
	closesocket(s);
}

// The flow of the WAN address from: the one there is, or a new one with a port of its own on ::1; NULL when the
// gateway has no room for another one
static HOMEGW_FLOW *HomeGwFlow(HOMEGW *g, const SOCKADDR_IN *from) {
	for (UINT i = 0; i < g->NumFlows; i++)
		if (g->Flows[i].Remote.sin_addr.s_addr == from->sin_addr.s_addr && g->Flows[i].Remote.sin_port == from->sin_port)
			return &g->Flows[i];

	if (g->NumFlows == HOMEGW_MAX_FLOWS)
		return NULL;

	SOCKET s = HomeGwUdp(AF_INET6, 0);
	if (s == INVALID_SOCKET)
		return NULL;

	EnterCriticalSection(&g->Lock);
	HOMEGW_FLOW *f = &g->Flows[g->NumFlows++];
	f->Remote = *from;
	f->Inside = s;
	LeaveCriticalSection(&g->Lock);

	return f;
}

// What came to the public port: to the internal port on ::1, from the flow of its source
static void HomeGwFromWan(HOMEGW *g) {
	char buf[HOMEGW_BUFFER];
	SOCKADDR_STORAGE from;
	SOCKADDR_IN6 to;

	ZeroMemory(&to, sizeof(to));
	to.sin6_family = AF_INET6;
	to.sin6_addr.s6_addr[15] = 1;
	to.sin6_port = htons(g->Internal);

	while (true) {
		int from_len = sizeof(from);
		int n = recvfrom(g->Wan, buf, sizeof(buf), 0, (SOCKADDR *)&from, &from_len);

		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEMSGSIZE)
				continue;
			break;
		}

		if (InterlockedCompareExchange(&g->Link, 0, 0) == 0 || from.ss_family != AF_INET)
			continue;

		HOMEGW_FLOW *f = HomeGwFlow(g, (const SOCKADDR_IN *)&from);
		if (f != NULL && sendto(f->Inside, buf, n, 0, (const SOCKADDR *)&to, sizeof(to)) == n)
			InterlockedIncrement(&g->Forwarded);
	}
}

// What the node sent back to the port of the flow f: to the WAN address of the flow, from the public port
static void HomeGwFromInside(HOMEGW *g, HOMEGW_FLOW *f) {
	char buf[HOMEGW_BUFFER];
	SOCKADDR_STORAGE from;

	while (true) {
		int from_len = sizeof(from);
		int n = recvfrom(f->Inside, buf, sizeof(buf), 0, (SOCKADDR *)&from, &from_len);

		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEMSGSIZE)
				continue;
			break;
		}

		// Only from the internal port of the mapping
		const SOCKADDR_IN6 *in6 = (const SOCKADDR_IN6 *)&from;
		if (InterlockedCompareExchange(&g->Link, 0, 0) == 0 || from.ss_family != AF_INET6 || ntohs(in6->sin6_port) != g->Internal)
			continue;

		if (sendto(g->Wan, buf, n, 0, (const SOCKADDR *)&f->Remote, sizeof(f->Remote)) == n)
			InterlockedIncrement(&g->Forwarded);
	}
}

// The thread of the gateway: datagrams first, then SSDP, then one HTTP request, which may change the mapping and
// so comes last before the next poll
static DWORD WINAPI HomeGwThread(void *param) {
	HOMEGW *g = (HOMEGW *)param;
	WSAPOLLFD fds[3 + HOMEGW_MAX_FLOWS];

	while (InterlockedCompareExchange(&g->Stop, 0, 0) == 0) {
		UINT n = 0;
		UINT flows = g->NumFlows;

		ZeroMemory(fds, sizeof(fds));
		fds[n].fd = g->Ssdp;
		fds[n++].events = POLLRDNORM;
		fds[n].fd = g->Http;
		fds[n++].events = POLLRDNORM;
		if (g->Wan != INVALID_SOCKET) {
			fds[n].fd = g->Wan;
			fds[n++].events = POLLRDNORM;
		}
		for (UINT i = 0; i < flows; i++) {
			fds[n].fd = g->Flows[i].Inside;
			fds[n++].events = POLLRDNORM;
		}

		if (WSAPoll(fds, n, 50) <= 0)
			continue;

		if (g->Wan != INVALID_SOCKET && fds[2].revents != 0)
			HomeGwFromWan(g);
		for (UINT i = 0; i < flows && g->Wan != INVALID_SOCKET; i++)
			if (fds[3 + i].revents != 0)
				HomeGwFromInside(g, &g->Flows[i]);
		if (fds[0].revents != 0)
			HomeGwSsdp(g);
		if (fds[1].revents != 0)
			HomeGwHttp(g);
	}

	return 0;
}

// Stop the gateway and close its sockets
void HomeGwFree(HOMEGW *g) {
	if (g == NULL)
		return;

	if (g->Thread != NULL) {
		InterlockedExchange(&g->Stop, 1);
		WaitForSingleObject(g->Thread, INFINITE);
		CloseHandle(g->Thread);
	}

	HomeGwUnmap(g);
	if (g->Ssdp != INVALID_SOCKET)
		closesocket(g->Ssdp);
	if (g->Http != INVALID_SOCKET)
		closesocket(g->Http);

	DeleteCriticalSection(&g->Lock);
	if (g->WsaStarted)
		WSACleanup();

	HeapFree(GetProcessHeap(), 0, g);
}

// A gateway with its link up and no mapping yet; NULL when UDP 1900 or the HTTP listener cannot be opened
HOMEGW *HomeGwNew() {
	WSADATA wsa;
	SOCKADDR_IN sa;
	int sa_len = sizeof(sa);
	BOOL reuse = TRUE;
	u_long nonblocking = 1;

	HOMEGW *g = (HOMEGW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOMEGW));
	if (g == NULL)
		return NULL;

	g->Ssdp = INVALID_SOCKET;
	g->Http = INVALID_SOCKET;
	g->Wan = INVALID_SOCKET;
	g->Link = 1;
	InitializeCriticalSection(&g->Lock);
	g->WsaStarted = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);

	// SSDP, beside any other listener of the host on UDP 1900
	g->Ssdp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(HOMEGW_SSDP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (g->Ssdp == INVALID_SOCKET || setsockopt(g->Ssdp, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) != 0 || bind(g->Ssdp, (const SOCKADDR *)&sa, sizeof(sa)) != 0) {
		HomeGwFree(g);
		return NULL;
	}
	HomeGwJoinAll(g->Ssdp);
	ioctlsocket(g->Ssdp, FIONBIO, &nonblocking);

	// HTTP on a port of the system's choice
	g->Http = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sa.sin_port = 0;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (g->Http == INVALID_SOCKET || bind(g->Http, (const SOCKADDR *)&sa, sizeof(sa)) != 0 || listen(g->Http, 4) != 0 || getsockname(g->Http, (SOCKADDR *)&sa, &sa_len) != 0) {
		HomeGwFree(g);
		return NULL;
	}
	g->HttpPort = ntohs(sa.sin_port);
	ioctlsocket(g->Http, FIONBIO, &nonblocking);

	g->Thread = CreateThread(NULL, 0, HomeGwThread, g, 0, NULL);
	if (g->Thread == NULL) {
		HomeGwFree(g);
		return NULL;
	}

	return g;
}

// The mapping that the gateway granted: its public port on 127.0.0.1 and the internal port on ::1; false for none
bool HomeGwMapped(HOMEGW *g, USHORT *external, USHORT *internal) {
	EnterCriticalSection(&g->Lock);
	bool ret = (g->Wan != INVALID_SOCKET);
	*external = g->External;
	*internal = g->Internal;
	LeaveCriticalSection(&g->Lock);

	return ret;
}

// Bring the WAN link of the gateway up or down: down, it forwards nothing
void HomeGwSetLink(HOMEGW *g, bool up) {
	InterlockedExchange(&g->Link, up ? 1 : 0);
}

// The datagrams that the mapping forwarded so far, either way
UINT HomeGwForwarded(HOMEGW *g) {
	return (UINT)InterlockedCompareExchange(&g->Forwarded, 0, 0);
}

// The M-SEARCH requests that the gateway answered so far
UINT HomeGwSearches(HOMEGW *g) {
	return (UINT)InterlockedCompareExchange(&g->Searches, 0, 0);
}
