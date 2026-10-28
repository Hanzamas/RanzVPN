// homegw.c
// The simulated home gateway of a NAT of the NAT simulator (natsim.c; CORE-S5-3, #79; CORE-S5-6, #412): a UPnP Internet
// Gateway Device (UPnP Device Architecture 1.0, WANIPConnection:1) that libplum finds with SSDP and asks for a port
// mapping, which it grants as a port forward of its NAT on the network of the simulator (NatSimForward). libplum runs on
// real sockets of the host, so the gateway answers there: SSDP on UDP 1900 of the loopback interfaces, and its
// description and control URL over HTTP on 127.0.0.1. Its external address is the public address of its NAT, and the
// port forward leads to the host behind the NAT whose port is the internal port of the mapping, the port of the socket
// of its peer layer, so a peer reaches that host at the public port.
//
// The gateway answers M-SEARCH on 239.255.255.250:1900, joined on every IPv4 interface since multicast loops back to
// the host on the interface it leaves by; it serves its description and its control URL; and it takes
// GetExternalIPAddress, AddPortMapping and DeletePortMapping. It counts the searches and the requests that it answered,
// so a test sees that a node with port mapping off asked nothing. HomeGwDrop loses the mapping, as a gateway that
// restarts does, without telling libplum.
//
// One thread serves everything: the SSDP socket and the HTTP listener.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>

#include "natsim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HOMEGW_SSDP_PORT 1900
#define HOMEGW_BUFFER    4096 // The largest SSDP datagram, and the largest HTTP request

struct HOMEGW {
	bool WsaStarted;        // WSAStartup succeeded
	NATSIM *Sim;            // The network of the simulator
	NATSIM_NAT *Nat;        // The NAT of the gateway, whose public address is its external address
	SOCKET Ssdp;            // UDP 1900, in the SSDP multicast group
	SOCKET Http;            // The HTTP listener on 127.0.0.1
	USHORT HttpPort;        // ... its port
	CRITICAL_SECTION Lock;  // The mapping
	USHORT External;        // The public port of the mapping, 0 for none
	USHORT Internal;        // The port of the host behind the NAT that it forwards to
	volatile LONG Searches; // M-SEARCH requests answered
	volatile LONG Requests; // HTTP requests answered: the description and the actions
	volatile LONG Stop;     // Ends the thread
	HANDLE Thread;          // The thread
};

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

// Map the public port external of the NAT to the host behind it with the port internal: false when the gateway has
// another mapping, or the NAT cannot forward that port. The thread of the gateway only.
static bool HomeGwMap(HOMEGW *g, USHORT external, USHORT internal) {
	bool ok = false;

	EnterCriticalSection(&g->Lock);
	if (g->External != 0) {
		ok = (g->External == external && g->Internal == internal);
	} else if (external != 0 && NatSimForward(g->Sim, g->Nat, external, internal)) {
		g->External = external;
		g->Internal = internal;
		ok = true;
	}
	LeaveCriticalSection(&g->Lock);

	return ok;
}

// Remove the mapping: false when there is none
static bool HomeGwUnmap(HOMEGW *g) {
	bool had = false;

	EnterCriticalSection(&g->Lock);
	if (g->External != 0) {
		NatSimUnforward(g->Sim, g->Nat, g->External);
		had = true;
	}
	g->External = 0;
	g->Internal = 0;
	LeaveCriticalSection(&g->Lock);

	return had;
}

// One HTTP request: the description, or a SOAP action on the control URL
static void HomeGwHttp(HOMEGW *g) {
	static const char description[] = "<?xml version=\"1.0\"?>\r\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>coretest home gateway</friendlyName><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl</controlURL><eventSubURL>/evt</eventSubURL><SCPDURL>/scpd.xml</SCPDURL></service></serviceList></device></deviceList></device></deviceList></device></root>\r\n";
	char req[HOMEGW_BUFFER];
	char content[256];
	PEER_ADDR pub;
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

	InterlockedIncrement(&g->Requests);

	if (strncmp(req, "GET /igd.xml ", 13) == 0) {
		HomeGwRespond(s, 200, description);
	} else if (strncmp(req, "POST /ctl ", 10) == 0 && strstr(req, "#GetExternalIPAddress") != NULL) {
		// The public address of the NAT
		NatSimPublic(g->Nat, &pub);
		snprintf(content, sizeof(content), "<u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalIPAddress>%u.%u.%u.%u</NewExternalIPAddress></u:GetExternalIPAddressResponse>", pub.Ip[12], pub.Ip[13], pub.Ip[14], pub.Ip[15]);
		HomeGwSoap(s, 200, content);
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

// The thread of the gateway: SSDP first, then one HTTP request, which may change the mapping
static DWORD WINAPI HomeGwThread(void *param) {
	HOMEGW *g = (HOMEGW *)param;
	WSAPOLLFD fds[2];

	while (InterlockedCompareExchange(&g->Stop, 0, 0) == 0) {
		ZeroMemory(fds, sizeof(fds));
		fds[0].fd = g->Ssdp;
		fds[0].events = POLLRDNORM;
		fds[1].fd = g->Http;
		fds[1].events = POLLRDNORM;

		if (WSAPoll(fds, 2, 50) <= 0)
			continue;

		if (fds[0].revents != 0)
			HomeGwSsdp(g);
		if (fds[1].revents != 0)
			HomeGwHttp(g);
	}

	return 0;
}

// Stop the gateway and close its sockets; its port forward goes
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

// The gateway of the NAT nat on the network s, with no mapping yet; NULL when UDP 1900 or the HTTP listener cannot be
// opened
HOMEGW *HomeGwNew(NATSIM *s, NATSIM_NAT *nat) {
	WSADATA wsa;
	SOCKADDR_IN sa;
	int sa_len = sizeof(sa);
	BOOL reuse = TRUE;
	u_long nonblocking = 1;

	if (s == NULL || nat == NULL)
		return NULL;

	HOMEGW *g = (HOMEGW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOMEGW));
	if (g == NULL)
		return NULL;

	g->Sim = s;
	g->Nat = nat;
	g->Ssdp = INVALID_SOCKET;
	g->Http = INVALID_SOCKET;
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

// The mapping that the gateway granted: its public port on the NAT and the port of the host that it forwards to; false
// for none
bool HomeGwMapped(HOMEGW *g, USHORT *external, USHORT *internal) {
	EnterCriticalSection(&g->Lock);
	bool ret = (g->External != 0);
	*external = g->External;
	*internal = g->Internal;
	LeaveCriticalSection(&g->Lock);

	return ret;
}

// Lose the mapping, as a gateway that restarts does: the port forward is gone, and libplum is not told. False when the
// gateway had none.
bool HomeGwDrop(HOMEGW *g) {
	return HomeGwUnmap(g);
}

// The M-SEARCH requests that the gateway answered so far
UINT HomeGwSearches(HOMEGW *g) {
	return (UINT)InterlockedCompareExchange(&g->Searches, 0, 0);
}

// The HTTP requests that the gateway answered so far: the description and the actions of the control URL
UINT HomeGwRequests(HOMEGW *g) {
	return (UINT)InterlockedCompareExchange(&g->Requests, 0, 0);
}
