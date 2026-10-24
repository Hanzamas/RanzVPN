// NodeWintun.c
// The Wintun adapter of a node (CORE-S3-1, #71): the L3 adapter of the client role (ADR-0009, ADR-0022 Client adapters)
// on wintun.dll of WireGuard LLC, the pinned release of THIRD_PARTY.TXT. The node loads the DLL from the directory of
// its executable, where CI puts it for the vpntest harness and ONE-3 (#312) will install it, and calls it only through
// the API of the wintun.h of that release (its functions by GetProcAddress), as the licence of the DLL asks. An adapter
// that the node creates goes when the node closes it, or with the process. A session of an adapter has two rings: the
// I/O thread of an adapter queue (NodeAddQueue) waits for the read event of the session and takes the IP packets of the
// host's own stack from one ring, and NodeWintunSend puts the packets for the host into the other. The addresses, the
// routes and the DNS servers of an adapter are set through IP Helper.

#include "Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"

#include <iphlpapi.h>

// The API of the wintun.h of the pinned release (0.14.1), which the node takes from the DLL by name
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _TUN_SESSION *WINTUN_SESSION_HANDLE;
typedef WINTUN_ADAPTER_HANDLE(WINAPI WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR name, LPCWSTR tunnel_type, const GUID *requested_guid);
typedef void(WINAPI WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE adapter);
typedef void(WINAPI WINTUN_GET_ADAPTER_LUID_FUNC)(WINTUN_ADAPTER_HANDLE adapter, NET_LUID *luid);
typedef DWORD(WINAPI WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)(void);
typedef WINTUN_SESSION_HANDLE(WINAPI WINTUN_START_SESSION_FUNC)(WINTUN_ADAPTER_HANDLE adapter, DWORD capacity);
typedef void(WINAPI WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE session);
typedef HANDLE(WINAPI WINTUN_GET_READ_WAIT_EVENT_FUNC)(WINTUN_SESSION_HANDLE session);
typedef BYTE *(WINAPI WINTUN_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE session, DWORD *packet_size);
typedef void(WINAPI WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(WINTUN_SESSION_HANDLE session, const BYTE *packet);
typedef BYTE *(WINAPI WINTUN_ALLOCATE_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE session, DWORD packet_size);
typedef void(WINAPI WINTUN_SEND_PACKET_FUNC)(WINTUN_SESSION_HANDLE session, const BYTE *packet);

// wintun.dll and its functions, loaded once per process and kept until the process ends
typedef struct NODE_WINTUN_API {
	HMODULE Module;
	WINTUN_CREATE_ADAPTER_FUNC *CreateAdapter;
	WINTUN_CLOSE_ADAPTER_FUNC *CloseAdapter;
	WINTUN_GET_ADAPTER_LUID_FUNC *GetAdapterLuid;
	WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *GetRunningDriverVersion;
	WINTUN_START_SESSION_FUNC *StartSession;
	WINTUN_END_SESSION_FUNC *EndSession;
	WINTUN_GET_READ_WAIT_EVENT_FUNC *GetReadWaitEvent;
	WINTUN_RECEIVE_PACKET_FUNC *ReceivePacket;
	WINTUN_RELEASE_RECEIVE_PACKET_FUNC *ReleaseReceivePacket;
	WINTUN_ALLOCATE_SEND_PACKET_FUNC *AllocateSendPacket;
	WINTUN_SEND_PACKET_FUNC *SendPacket;
} NODE_WINTUN_API;

static INIT_ONCE node_wintun_once = INIT_ONCE_STATIC_INIT;
static NODE_WINTUN_API node_wintun;
static bool node_wintun_loaded = false;
static UINT node_wintun_error = 0;

// The DNS settings of an interface: DNS_INTERFACE_SETTINGS (version 1) of netioapi.h, which the SDK declares from the API
// level of Windows 10 version 2004 on, above the one Cedar builds for. The node names the structure itself and takes
// SetInterfaceDnsSettings from iphlpapi.dll, which every Windows that runs the new core has (ADR-0022: Windows 11, Server
// 2022).
typedef struct NODE_DNS_SETTINGS {
	ULONG Version;
	ULONG64 Flags;
	PWSTR Domain;
	PWSTR NameServer;
	PWSTR SearchList;
	ULONG RegistrationEnabled;
	ULONG RegisterAdapterName;
	ULONG EnableLLMNR;
	ULONG QueryAdapterName;
	PWSTR ProfileNameServer;
} NODE_DNS_SETTINGS;

typedef DWORD(WINAPI NODE_SET_DNS_FUNC)(GUID iface, const NODE_DNS_SETTINGS *settings);

#define NODE_DNS_SETTINGS_VERSION1  0x0001 // DNS_INTERFACE_SETTINGS_VERSION1
#define NODE_DNS_SETTING_IPV6       0x0001 // DNS_SETTING_IPV6: the IPv6 name servers, not the IPv4 ones
#define NODE_DNS_SETTING_NAMESERVER 0x0002 // DNS_SETTING_NAMESERVER
#define NODE_DNS_SETTING_DOMAIN     0x0020 // DNS_SETTING_DOMAIN: the connection-specific suffix

// An adapter of the node
struct NODE_WINTUN {
	NODE *Node;                                     // The node
	wchar_t Name[MAX_SIZE];                         // The name of the adapter
	WINTUN_ADAPTER_HANDLE Adapter;                  // The adapter, which goes when it is closed
	NET_LUID Luid;                                  // Its interface
	UINT Index;                                     // ... the index of that interface
	GUID Guid;                                      // ... and its GUID
	WINTUN_SESSION_HANDLE Session;                  // The session of its rings, NULL for an adapter without one
	HANDLE ReadEvent;                               // The read event of the session, which the session owns
	NODE_QUEUE *Queue;                              // The adapter queue that takes the packets of the host, NULL once halted
	NODE_WINTUN_PROC *Proc;                         // Takes each packet of the host
	void *Param;                                    // ... and its second parameter
	LOCK *Lock;                                     // Addresses and Routes
	NODE_PREFIX Addresses[NODE_WINTUN_MAX_ADDRESSES]; // The addresses that the node set on the adapter
	UINT NumAddresses;                              // ... their number
	NODE_PREFIX Routes[NODE_WINTUN_MAX_ROUTES];     // The routes that the node installed through the adapter
	UINT NumRoutes;                                 // ... their number
	volatile LONG64 FromHost;                       // Packets of the host taken from the ring
	volatile LONG64 ToHost;                         // Packets put into the ring for the host
	volatile LONG64 Dropped;                        // Packets for the host that found the ring full
};

// Load wintun.dll from the directory of the executable, its imports from System32, and take its functions
static BOOL CALLBACK NodeWintunLoad(PINIT_ONCE once, void *param, void **context) {
	HMODULE m = LoadLibraryExW(NODE_WINTUN_DLL, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

	if (m == NULL) {
		node_wintun_error = (UINT)GetLastError();
		return TRUE;
	}

	node_wintun.CreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC *)(void *)GetProcAddress(m, "WintunCreateAdapter");
	node_wintun.CloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC *)(void *)GetProcAddress(m, "WintunCloseAdapter");
	node_wintun.GetAdapterLuid = (WINTUN_GET_ADAPTER_LUID_FUNC *)(void *)GetProcAddress(m, "WintunGetAdapterLUID");
	node_wintun.GetRunningDriverVersion = (WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *)(void *)GetProcAddress(m, "WintunGetRunningDriverVersion");
	node_wintun.StartSession = (WINTUN_START_SESSION_FUNC *)(void *)GetProcAddress(m, "WintunStartSession");
	node_wintun.EndSession = (WINTUN_END_SESSION_FUNC *)(void *)GetProcAddress(m, "WintunEndSession");
	node_wintun.GetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC *)(void *)GetProcAddress(m, "WintunGetReadWaitEvent");
	node_wintun.ReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC *)(void *)GetProcAddress(m, "WintunReceivePacket");
	node_wintun.ReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC *)(void *)GetProcAddress(m, "WintunReleaseReceivePacket");
	node_wintun.AllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC *)(void *)GetProcAddress(m, "WintunAllocateSendPacket");
	node_wintun.SendPacket = (WINTUN_SEND_PACKET_FUNC *)(void *)GetProcAddress(m, "WintunSendPacket");

	if (node_wintun.CreateAdapter == NULL || node_wintun.CloseAdapter == NULL || node_wintun.GetAdapterLuid == NULL ||
	    node_wintun.GetRunningDriverVersion == NULL || node_wintun.StartSession == NULL || node_wintun.EndSession == NULL ||
	    node_wintun.GetReadWaitEvent == NULL || node_wintun.ReceivePacket == NULL || node_wintun.ReleaseReceivePacket == NULL ||
	    node_wintun.AllocateSendPacket == NULL || node_wintun.SendPacket == NULL) {
		node_wintun_error = ERROR_PROC_NOT_FOUND;
		Zero(&node_wintun, sizeof(node_wintun));
		FreeLibrary(m);
		return TRUE;
	}

	node_wintun.Module = m;
	node_wintun_loaded = true;

	return TRUE;
}

// Whether wintun.dll is there and has the API of wintun.h; error (when not NULL) gets why not: the error of the load,
// ERROR_PROC_NOT_FOUND for a DLL without that API
bool NodeWintunAvailable(UINT *error) {
	InitOnceExecuteOnce(&node_wintun_once, NodeWintunLoad, NULL, NULL);

	if (error != NULL)
		*error = node_wintun_error;

	return node_wintun_loaded;
}

// The version of the Wintun driver that runs, major in the high 16 bits; 0 while no adapter brought it up
UINT NodeWintunDriverVersion() {
	if (NodeWintunAvailable(NULL) == false)
		return 0;

	return (UINT)node_wintun.GetRunningDriverVersion();
}

// The GUID that the node asks for an adapter of name: the same name gives the same interface across restarts, so the
// network profile and the settings of Windows stay attached to it (ADR-0025 decision 3). A name-based GUID (RFC 4122
// section 4.3) of the SHA-256 of the name.
static void NodeWintunGuid(GUID *guid, const wchar_t *name) {
	UCHAR hash[SHA256_SIZE];

	Sha2_256(hash, (void *)name, UniStrLen(name) * (UINT)sizeof(wchar_t));
	Copy(guid, hash, sizeof(GUID));
	guid->Data3 = (USHORT)((guid->Data3 & 0x0FFF) | 0x5000);
	guid->Data4[0] = (UCHAR)((guid->Data4[0] & 0x3F) | 0x80);
}

// The I/O thread of the adapter queue: the packets of the host's own stack from the ring of the session, each to the
// owner of the adapter, NODE_WINTUN_BATCH at most per run. A full run sets the read event again, so the thread passes a
// quiescent point of the table snapshot between two runs; a run that emptied the ring has the adapter set the event for
// the next packet.
static void NodeWintunDrain(NODE_QUEUE *q, void *param) {
	NODE_WINTUN *w = (NODE_WINTUN *)param;

	for (UINT i = 0; i < NODE_WINTUN_BATCH; i++) {
		DWORD size = 0;
		BYTE *packet = node_wintun.ReceivePacket(w->Session, &size);

		// ERROR_NO_MORE_ITEMS: the ring is empty; ERROR_HANDLE_EOF: the adapter goes
		if (packet == NULL)
			return;

		InterlockedIncrement64(&w->FromHost);
		w->Proc(w, w->Param, packet, (UINT)size);
		node_wintun.ReleaseReceivePacket(w->Session, packet);
	}

	SetEvent(w->ReadEvent);
}

// A Wintun adapter of the node named name, which goes with NodeWintunFree. With proc, a session of its rings and an
// adapter queue whose I/O thread gives each packet of the host to proc (from NodeStart to NodeStop only); without, an
// adapter that carries no packet. An adapter of the same name that is still going away is waited for. NULL when
// wintun.dll is missing or the adapter cannot come up (the node log says why).
NODE_WINTUN *NodeWintunNew(NODE *n, const wchar_t *name, NODE_WINTUN_PROC *proc, void *param) {
	char queue_name[MAX_SIZE];
	GUID guid;
	UINT error = 0;
	DWORD err = 0;
	ULONG index = 0;

	if (n == NULL || UniIsEmptyStr(name))
		return NULL;

	if (NodeWintunAvailable(&error) == false) {
		NodeLog(n, "Wintun adapter %S not created: %S cannot be loaded (error %u)", name, NODE_WINTUN_DLL, error);
		return NULL;
	}

	NodeWintunGuid(&guid, name);

	// An adapter of this name that the node closed a moment ago may still hold the GUID
	WINTUN_ADAPTER_HANDLE a = NULL;
	for (UINT64 end = GetTickCount64() + NODE_WINTUN_CREATE_WAIT;;) {
		a = node_wintun.CreateAdapter(name, NODE_WINTUN_TYPE, &guid);
		err = GetLastError();
		if (a != NULL || GetTickCount64() >= end)
			break;
		Sleep(NODE_WINTUN_CREATE_RETRY);
	}

	if (a == NULL) {
		NodeLog(n, "Wintun adapter %S not created: error %u", name, (UINT)err);
		return NULL;
	}

	NODE_WINTUN *w = ZeroMalloc(sizeof(NODE_WINTUN));
	w->Node = n;
	UniStrCpy(w->Name, sizeof(w->Name), name);
	w->Adapter = a;
	w->Lock = NewLock();
	node_wintun.GetAdapterLuid(a, &w->Luid);
	if (ConvertInterfaceLuidToIndex(&w->Luid, &index) == NO_ERROR)
		w->Index = (UINT)index;
	if (ConvertInterfaceLuidToGuid(&w->Luid, &w->Guid) != NO_ERROR)
		w->Guid = guid;

	if (proc != NULL) {
		w->Proc = proc;
		w->Param = param;
		w->Session = node_wintun.StartSession(a, NODE_WINTUN_RING);
		w->ReadEvent = (w->Session != NULL ? node_wintun.GetReadWaitEvent(w->Session) : NULL);

		Format(queue_name, sizeof(queue_name), "wintun %S", name);
		w->Queue = (w->ReadEvent != NULL ? NodeAddQueue(n, queue_name, w->ReadEvent, NodeWintunDrain, w) : NULL);

		if (w->Queue == NULL) {
			NodeLog(n, "Wintun adapter %S: its session or its adapter queue could not start (error %u)", name, (UINT)GetLastError());
			NodeWintunFree(w);
			return NULL;
		}

		// The adapter sets the read event only after a receive found the ring empty: the first run of the I/O thread
		// empties it, and from then on each packet of the host sets the event
		SetEvent(w->ReadEvent);
	}

	UINT version = NodeWintunDriverVersion();
	NodeLog(n, "Wintun adapter %S up: interface %u, driver %u.%u%s", name, w->Index, version >> 16, version & 0xFFFF,
	        w->Session != NULL ? ", its rings attached as an adapter queue" : "");

	return w;
}

// Stop the packets of the host: the adapter queue is detached and its I/O thread joined. The adapter stays.
void NodeWintunHalt(NODE_WINTUN *w) {
	if (w == NULL || w->Queue == NULL)
		return;

	NodeDelQueue(w->Node, w->Queue);
	w->Queue = NULL;
}

// Remove an adapter: its queue, its session, then the adapter, with the addresses and routes it held. No packet may be
// sent into it any more (NodeWintunSend).
void NodeWintunFree(NODE_WINTUN *w) {
	if (w == NULL)
		return;

	NodeWintunHalt(w);

	if (w->Session != NULL)
		node_wintun.EndSession(w->Session);

	node_wintun.CloseAdapter(w->Adapter);

	NodeLog(w->Node, "Wintun adapter %S removed: %I64u packets of the host taken, %I64u put into it, %I64u dropped", w->Name,
	        (UINT64)w->FromHost, (UINT64)w->ToHost, (UINT64)w->Dropped);

	DeleteLock(w->Lock);
	Free(w);
}

// Put a packet for the host into the ring of the session; false when the adapter has no session or the ring is full
bool NodeWintunSend(NODE_WINTUN *w, const UCHAR *packet, UINT size) {
	if (w == NULL || w->Session == NULL || packet == NULL || size == 0 || size > NODE_WINTUN_MAX_PACKET)
		return false;

	BYTE *p = node_wintun.AllocateSendPacket(w->Session, size);
	if (p == NULL) {
		InterlockedIncrement64(&w->Dropped);
		return false;
	}

	Copy(p, packet, size);
	node_wintun.SendPacket(w->Session, p);
	InterlockedIncrement64(&w->ToHost);

	return true;
}

// The interface index of an adapter, 0 for none
UINT NodeWintunIndex(NODE_WINTUN *w) {
	return (w != NULL ? w->Index : 0);
}

// The LUID of the interface of an adapter, 0 for none
UINT64 NodeWintunLuid(NODE_WINTUN *w) {
	return (w != NULL ? w->Luid.Value : 0);
}

// The packets of an adapter: of the host taken, put into it for the host, and dropped on a full ring
void NodeWintunCounters(NODE_WINTUN *w, UINT64 *from_host, UINT64 *to_host, UINT64 *dropped) {
	*from_host = (w != NULL ? (UINT64)ReadAcquire64(&w->FromHost) : 0);
	*to_host = (w != NULL ? (UINT64)ReadAcquire64(&w->ToHost) : 0);
	*dropped = (w != NULL ? (UINT64)ReadAcquire64(&w->Dropped) : 0);
}

// The address of a prefix as a SOCKADDR_INET
static void NodeWintunSockaddr(SOCKADDR_INET *s, const NODE_PREFIX *p) {
	Zero(s, sizeof(SOCKADDR_INET));

	if (p->AddressSize == 4) {
		s->Ipv4.sin_family = AF_INET;
		Copy(&s->Ipv4.sin_addr, p->Address, 4);
	} else {
		s->Ipv6.sin6_family = AF_INET6;
		Copy(&s->Ipv6.sin6_addr, p->Address, 16);
	}
}

// Whether p is one of the num prefixes of list, by family, address and length
static bool NodeWintunHas(const NODE_PREFIX *list, UINT num, const NODE_PREFIX *p) {
	for (UINT i = 0; i < num; i++)
		if (list[i].AddressSize == p->AddressSize && list[i].Length == p->Length && Cmp(list[i].Address, p->Address, p->AddressSize) == 0)
			return true;

	return false;
}

// Whether a prefix is one that the adapter takes: IPv4 or IPv6, its length in range
static bool NodeWintunValid(const NODE_PREFIX *p) {
	return ((p->AddressSize == 4 && p->Length <= 32) || (p->AddressSize == 16 && p->Length <= 128));
}

// The row of an address of the adapter: a host address (/32, /128), at once preferred
static void NodeWintunAddressRow(NODE_WINTUN *w, MIB_UNICASTIPADDRESS_ROW *row, const NODE_PREFIX *p) {
	InitializeUnicastIpAddressEntry(row);
	row->InterfaceLuid = w->Luid;
	NodeWintunSockaddr(&row->Address, p);
	row->OnLinkPrefixLength = (UINT8)(p->AddressSize * 8);
	row->DadState = IpDadStatePreferred;
}

// The row of a route through the adapter: on-link, its next hop the unspecified address of its family
static void NodeWintunRouteRow(NODE_WINTUN *w, MIB_IPFORWARD_ROW2 *row, const NODE_PREFIX *p) {
	InitializeIpForwardEntry(row);
	row->InterfaceLuid = w->Luid;
	NodeWintunSockaddr(&row->DestinationPrefix.Prefix, p);
	row->DestinationPrefix.PrefixLength = (UINT8)p->Length;
	row->NextHop.si_family = (ADDRESS_FAMILY)(p->AddressSize == 4 ? AF_INET : AF_INET6);
	row->Metric = 0;
	row->Protocol = MIB_IPPROTO_NETMGMT;
}

// Set the addresses of an adapter to addrs, each a host address: the ones that it held and addrs leaves out go, the new
// ones come (their Length is ignored). False when one could not be set or removed; the node log says which.
bool NodeWintunSetAddresses(NODE_WINTUN *w, const NODE_PREFIX *addrs, UINT num) {
	NODE_PREFIX set[NODE_WINTUN_MAX_ADDRESSES];
	UINT num_set = 0;
	bool ok = true;

	if (w == NULL || (addrs == NULL && num != 0))
		return false;

	Lock(w->Lock);
	{
		for (UINT i = 0; i < w->NumAddresses; i++) {
			NODE_PREFIX *p = &w->Addresses[i];
			bool stays = false;

			for (UINT j = 0; j < num && stays == false; j++)
				stays = (addrs[j].AddressSize == p->AddressSize && Cmp(addrs[j].Address, p->Address, p->AddressSize) == 0);

			if (stays) {
				set[num_set++] = *p;
				continue;
			}

			MIB_UNICASTIPADDRESS_ROW row;
			NodeWintunAddressRow(w, &row, p);
			DWORD err = DeleteUnicastIpAddressEntry(&row);
			if (err != NO_ERROR && err != ERROR_NOT_FOUND) {
				NodeLog(w->Node, "Wintun adapter %S: an address could not be removed (error %u)", w->Name, (UINT)err);
				ok = false;
			}
		}

		for (UINT i = 0; i < num && num_set < NODE_WINTUN_MAX_ADDRESSES; i++) {
			NODE_PREFIX p = addrs[i];
			bool held = false;

			p.Length = p.AddressSize * 8;
			if (NodeWintunValid(&p) == false)
				continue;
			for (UINT j = 0; j < num_set && held == false; j++)
				held = (set[j].AddressSize == p.AddressSize && Cmp(set[j].Address, p.Address, p.AddressSize) == 0);
			if (held)
				continue;

			MIB_UNICASTIPADDRESS_ROW row;
			NodeWintunAddressRow(w, &row, &p);
			DWORD err = CreateUnicastIpAddressEntry(&row);
			if (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS) {
				set[num_set++] = p;
			} else {
				NodeLog(w->Node, "Wintun adapter %S: an address could not be set (error %u)", w->Name, (UINT)err);
				ok = false;
			}
		}

		Copy(w->Addresses, set, sizeof(NODE_PREFIX) * num_set);
		w->NumAddresses = num_set;
	}
	Unlock(w->Lock);

	return ok;
}

// Set the routes through an adapter to routes: the ones that it installed and routes leaves out go, the new ones come,
// each on-link. A route that Windows has already is left to Windows. False when one could not be installed or removed.
bool NodeWintunSetRoutes(NODE_WINTUN *w, const NODE_PREFIX *routes, UINT num) {
	NODE_PREFIX set[NODE_WINTUN_MAX_ROUTES];
	UINT num_set = 0;
	bool ok = true;

	if (w == NULL || (routes == NULL && num != 0))
		return false;

	Lock(w->Lock);
	{
		for (UINT i = 0; i < w->NumRoutes; i++) {
			NODE_PREFIX *p = &w->Routes[i];

			if (NodeWintunHas(routes, num, p)) {
				set[num_set++] = *p;
				continue;
			}

			MIB_IPFORWARD_ROW2 row;
			NodeWintunRouteRow(w, &row, p);
			DWORD err = DeleteIpForwardEntry2(&row);
			if (err != NO_ERROR && err != ERROR_NOT_FOUND) {
				NodeLog(w->Node, "Wintun adapter %S: a route could not be removed (error %u)", w->Name, (UINT)err);
				ok = false;
			}
		}

		for (UINT i = 0; i < num && num_set < NODE_WINTUN_MAX_ROUTES; i++) {
			const NODE_PREFIX *p = &routes[i];

			if (NodeWintunValid(p) == false || NodeWintunHas(set, num_set, p))
				continue;

			MIB_IPFORWARD_ROW2 row;
			NodeWintunRouteRow(w, &row, p);
			DWORD err = CreateIpForwardEntry2(&row);
			if (err == NO_ERROR) {
				set[num_set++] = *p;
			} else if (err != ERROR_OBJECT_ALREADY_EXISTS) {
				NodeLog(w->Node, "Wintun adapter %S: a route could not be installed (error %u)", w->Name, (UINT)err);
				ok = false;
			}
		}

		Copy(w->Routes, set, sizeof(NODE_PREFIX) * num_set);
		w->NumRoutes = num_set;
	}
	Unlock(w->Lock);

	return ok;
}

// Set the DNS servers of one family of the interface of an adapter (NODE_DNS_SETTING_IPV6 in flags for IPv6), and with
// suffix, the connection-specific DNS suffix
static DWORD NodeWintunSetDnsFamily(NODE_WINTUN *w, NODE_SET_DNS_FUNC *set, wchar_t *servers, wchar_t *suffix, ULONG64 flags) {
	NODE_DNS_SETTINGS s;

	Zero(&s, sizeof(s));
	s.Version = NODE_DNS_SETTINGS_VERSION1;
	s.Flags = flags | NODE_DNS_SETTING_NAMESERVER;
	s.NameServer = servers;
	if (suffix != NULL) {
		s.Flags |= NODE_DNS_SETTING_DOMAIN;
		s.Domain = suffix;
	}

	return set(w->Guid, &s);
}

// Set the DNS servers of the interface of an adapter (servers: addresses separated by commas, of either family) and its
// connection-specific suffix (empty for none), through SetInterfaceDnsSettings. False when Windows has no such function
// or it failed.
bool NodeWintunSetDns(NODE_WINTUN *w, const char *servers, const char *suffix) {
	wchar_t v4[MAX_SIZE];
	wchar_t v6[MAX_SIZE];
	wchar_t suffix_w[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];

	if (w == NULL || servers == NULL)
		return false;

	HMODULE iphlpapi = GetModuleHandleW(L"iphlpapi.dll");
	NODE_SET_DNS_FUNC *set = (iphlpapi != NULL ? (NODE_SET_DNS_FUNC *)(void *)GetProcAddress(iphlpapi, "SetInterfaceDnsSettings") : NULL);
	if (set == NULL) {
		NodeLog(w->Node, "Wintun adapter %S: no DNS servers set: Windows has no SetInterfaceDnsSettings", w->Name);
		return false;
	}

	// The servers of each family, comma-separated
	UniStrCpy(v4, sizeof(v4), L"");
	UniStrCpy(v6, sizeof(v6), L"");
	TOKEN_LIST *t = ParseToken(servers, ", \t");
	for (UINT i = 0; i < t->NumTokens; i++) {
		wchar_t *list = (InStr(t->Token[i], ":") ? v6 : v4);

		StrToUni(tmp, sizeof(tmp), t->Token[i]);
		if (UniIsEmptyStr(list) == false)
			UniStrCat(list, sizeof(v4), L",");
		UniStrCat(list, sizeof(v4), tmp);
	}
	FreeToken(t);

	StrToUni(suffix_w, sizeof(suffix_w), suffix != NULL ? suffix : "");
	wchar_t *domain = (UniIsEmptyStr(suffix_w) ? NULL : suffix_w);

	DWORD err = NodeWintunSetDnsFamily(w, set, v4, domain, 0);
	if (err == NO_ERROR)
		err = NodeWintunSetDnsFamily(w, set, v6, NULL, NODE_DNS_SETTING_IPV6);

	if (err != NO_ERROR) {
		NodeLog(w->Node, "Wintun adapter %S: the DNS servers could not be set (error %u)", w->Name, (UINT)err);
		return false;
	}

	NodeLog(w->Node, "Wintun adapter %S: DNS servers %s, suffix %s", w->Name, servers, IsEmptyStr(suffix) ? "none" : suffix);
	return true;
}
