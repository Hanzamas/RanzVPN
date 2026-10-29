// NodeWireGuard.c
// The WireGuard Devices of a node (SDN-80, #375; spec #374): a phone, a laptop or a router that joins one Network over
// standard WireGuard, without ranz.exe, through a gateway node. The gateway terminates WireGuard with WireGuardNT: the
// wireguard.dll of the pinned SDK 0.10.1 (THIRD_PARTY.TXT), which the node loads from the directory of its executable, where
// ranz install puts it, and calls only through the API of the wireguard.h of that SDK (its functions by
// GetProcAddress), as the licence of the DLL asks. A node on which the DLL loads reports the Capability wireguard with
// the public key of its WireGuard interface (NodeWireGuardCaps), and the controller gives the Devices of a Network only
// to a gateway that reports it (ADR-0033).
// - The key. The WireGuard key pair of a node is derived from its static key and is never stored: its scalar is the
//   HKDF of the shared secret of the static key with the point that the SHA-256 of NODE_WIREGUARD_LABEL names. The node
//   finds the same pair at every start, also when its static key is the node identity in the key storage provider, and
//   only the holder of the static key can find it.
// - The interface. A state in which the node is the gateway of a Device brings up one WireGuard interface with the
//   requested GUID of the node's static key and VRF id 0, which no VRF has (NodeVrfAdapterGuid): it listens on the UDP
//   port of the state, and each Device that it terminates is a peer of it whose allowed IPs are its addresses, and whose
//   PresharedKey is the one that its state carries, for a Device that has one (SDN-82, #377; a secret, wiped with the
//   Devices of the state that goes, and never logged). Windows
//   forwards between it and the Wintun adapter of the VRF of each Device (SDN-5): both have forwarding and the weak host
//   model on, and the addresses of the Devices are routes through the WireGuard interface. A packet of a Device to an
//   overlay host leaves the host through the adapter of its VRF, where the overlay takes it, judges it by the policy of
//   the VRF as a packet of the Device (NodePolicy.c) and sends it to the peer of its destination; a packet of a peer to a
//   Device goes to the host of its gateway, which forwards it to the WireGuard interface. Windows does not forward between
//   two Devices on the WireGuard interface itself, which the policy would not see, unless the rules of the state let them
//   meet (NodeWireGuardFilter.c). A state without a Device whose gateway the node is takes the interface away, with its
//   routes.
// - The counters. A thread reads the last handshake and the traffic of each Device from the interface and hands them to
//   the control stream (ControlSetDevices), which reports them to the controller.

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"
#include "Core/Crypto.h"

#include "NodeCaps.h"
#include "NodeInternal.h"

#include <iphlpapi.h>

// The API of the wireguard.h of the pinned SDK (1.1), which the node takes from the DLL by name. The structures have the
// layout of the header, 8-byte aligned.
typedef struct _WIREGUARD_ADAPTER *WIREGUARD_ADAPTER_HANDLE;
typedef WIREGUARD_ADAPTER_HANDLE(WINAPI WIREGUARD_CREATE_ADAPTER_FUNC)(LPCWSTR name, LPCWSTR tunnel_type, const GUID *requested_guid);
typedef void(WINAPI WIREGUARD_CLOSE_ADAPTER_FUNC)(WIREGUARD_ADAPTER_HANDLE adapter);
typedef void(WINAPI WIREGUARD_GET_ADAPTER_LUID_FUNC)(WIREGUARD_ADAPTER_HANDLE adapter, NET_LUID *luid);
typedef DWORD(WINAPI WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC)(void);
typedef BOOL(WINAPI WIREGUARD_SET_ADAPTER_STATE_FUNC)(WIREGUARD_ADAPTER_HANDLE adapter, int state);
typedef BOOL(WINAPI WIREGUARD_SET_CONFIGURATION_FUNC)(WIREGUARD_ADAPTER_HANDLE adapter, const void *config, DWORD bytes);
typedef BOOL(WINAPI WIREGUARD_GET_CONFIGURATION_FUNC)(WIREGUARD_ADAPTER_HANDLE adapter, void *config, DWORD *bytes);

#define NODE_WG_ADAPTER_UP              1      // WIREGUARD_ADAPTER_STATE_UP
#define NODE_WG_INTERFACE_HAS_PRIVATE   0x0002 // WIREGUARD_INTERFACE_HAS_PRIVATE_KEY
#define NODE_WG_INTERFACE_HAS_PORT      0x0004 // WIREGUARD_INTERFACE_HAS_LISTEN_PORT
#define NODE_WG_INTERFACE_REPLACE_PEERS 0x0008 // WIREGUARD_INTERFACE_REPLACE_PEERS
#define NODE_WG_PEER_HAS_PUBLIC_KEY     0x0001 // WIREGUARD_PEER_HAS_PUBLIC_KEY
#define NODE_WG_PEER_HAS_PRESHARED_KEY  0x0002 // WIREGUARD_PEER_HAS_PRESHARED_KEY
#define NODE_WG_PEER_REPLACE_ALLOWED    0x0020 // WIREGUARD_PEER_REPLACE_ALLOWED_IPS

// WIREGUARD_ALLOWED_IP: an allowed IP of a peer; Flags is 0, which adds it
typedef struct NODE_WG_ALLOWED_IP NODE_WG_ALLOWED_IP;
struct __declspec(align(8)) NODE_WG_ALLOWED_IP {
	union {
		IN_ADDR V4;
		IN6_ADDR V6;
	} Address;
	ADDRESS_FAMILY AddressFamily;
	BYTE Cidr;
	DWORD Flags;
};

// WIREGUARD_PEER: a peer, followed by its AllowedIPsCount allowed IPs
typedef struct NODE_WG_PEER NODE_WG_PEER;
struct __declspec(align(8)) NODE_WG_PEER {
	DWORD Flags;
	DWORD Reserved;
	BYTE PublicKey[NODE_WIREGUARD_KEY_SIZE];
	BYTE PresharedKey[NODE_WIREGUARD_KEY_SIZE];
	WORD PersistentKeepalive;
	SOCKADDR_INET Endpoint;
	DWORD64 TxBytes;
	DWORD64 RxBytes;
	DWORD64 LastHandshake;
	DWORD AllowedIPsCount;
};

// WIREGUARD_INTERFACE: the interface, followed by its PeersCount peers
typedef struct NODE_WG_INTERFACE NODE_WG_INTERFACE;
struct __declspec(align(8)) NODE_WG_INTERFACE {
	DWORD Flags;
	WORD ListenPort;
	BYTE PrivateKey[NODE_WIREGUARD_KEY_SIZE];
	BYTE PublicKey[NODE_WIREGUARD_KEY_SIZE];
	DWORD PeersCount;
};

// wireguard.dll and its functions, loaded once per process and kept until the process ends
typedef struct NODE_WG_API {
	HMODULE Module;
	WIREGUARD_CREATE_ADAPTER_FUNC *CreateAdapter;
	WIREGUARD_CLOSE_ADAPTER_FUNC *CloseAdapter;
	WIREGUARD_GET_ADAPTER_LUID_FUNC *GetAdapterLuid;
	WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *GetRunningDriverVersion;
	WIREGUARD_SET_ADAPTER_STATE_FUNC *SetAdapterState;
	WIREGUARD_SET_CONFIGURATION_FUNC *SetConfiguration;
	WIREGUARD_GET_CONFIGURATION_FUNC *GetConfiguration;
} NODE_WG_API;

static INIT_ONCE node_wg_once = INIT_ONCE_STATIC_INIT;
static NODE_WG_API node_wg;
static bool node_wg_loaded = false;
static UINT node_wg_error = 0;

// A Device that the WireGuard interface of the node terminates
typedef struct NODE_WG_DEVICE {
	char Name[CONTROL_NAME_SIZE];
	UCHAR Key[NODE_WIREGUARD_KEY_SIZE];
	// Its PresharedKey, when it has one: a secret that goes to the interface and is wiped when the Device goes
	bool HasPreshared;
	UCHAR Preshared[NODE_WIREGUARD_KEY_SIZE];
	UINT VrfId;
	UINT NumAddresses;
	NODE_PREFIX Addresses[CONTROL_DEVICE_ADDRESSES];
} NODE_WG_DEVICE;

// The WireGuard end of a node, while its overlay runs
struct NODE_WIREGUARD {
	NODE *Node;
	// The node's static key, which the overlay owns
	PEER_KEY *Key;
	// The WireGuard key pair of the node, once it is derived
	bool HasKey;
	UCHAR Private[NODE_WIREGUARD_KEY_SIZE];
	UCHAR Public[NODE_WIREGUARD_KEY_SIZE];
	// The counters that the control stream reports
	CONTROL_DEVICES *Report;
	// Adapter, Luid, Index, Port, Devices and Routes
	LOCK *Lock;
	// The WireGuard interface, NULL while the node is the gateway of no Device
	WIREGUARD_ADAPTER_HANDLE Adapter;
	NET_LUID Luid;
	UINT Index;
	UINT Port;
	// The Devices that it terminates
	UINT NumDevices;
	NODE_WG_DEVICE *Devices;
	// The routes that the node installed through it: the addresses of the Devices
	UINT NumRoutes;
	NODE_PREFIX *Routes;
	// The filter engine whose filters block the forwarding between two Devices on it but for the pairs of Devices that the
	// policy lets meet, their number in Pairs (NodeWireGuardFilter.c); NULL for none
	HANDLE Isolation;
	UINT Pairs;
	// The thread of the counters, and its halt event
	HANDLE Thread;
	HANDLE Halt;
};

// Load wireguard.dll from the directory of the executable, its imports from System32, and take its functions
static BOOL CALLBACK NodeWireGuardLoad(PINIT_ONCE once, void *param, void **context) {
	HMODULE m = LoadLibraryExW(NODE_WIREGUARD_DLL, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

	if (m == NULL) {
		node_wg_error = (UINT)GetLastError();
		return TRUE;
	}

	node_wg.CreateAdapter = (WIREGUARD_CREATE_ADAPTER_FUNC *)(void *)GetProcAddress(m, "WireGuardCreateAdapter");
	node_wg.CloseAdapter = (WIREGUARD_CLOSE_ADAPTER_FUNC *)(void *)GetProcAddress(m, "WireGuardCloseAdapter");
	node_wg.GetAdapterLuid = (WIREGUARD_GET_ADAPTER_LUID_FUNC *)(void *)GetProcAddress(m, "WireGuardGetAdapterLUID");
	node_wg.GetRunningDriverVersion = (WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *)(void *)GetProcAddress(m, "WireGuardGetRunningDriverVersion");
	node_wg.SetAdapterState = (WIREGUARD_SET_ADAPTER_STATE_FUNC *)(void *)GetProcAddress(m, "WireGuardSetAdapterState");
	node_wg.SetConfiguration = (WIREGUARD_SET_CONFIGURATION_FUNC *)(void *)GetProcAddress(m, "WireGuardSetConfiguration");
	node_wg.GetConfiguration = (WIREGUARD_GET_CONFIGURATION_FUNC *)(void *)GetProcAddress(m, "WireGuardGetConfiguration");

	if (node_wg.CreateAdapter == NULL || node_wg.CloseAdapter == NULL || node_wg.GetAdapterLuid == NULL || node_wg.GetRunningDriverVersion == NULL ||
	    node_wg.SetAdapterState == NULL || node_wg.SetConfiguration == NULL || node_wg.GetConfiguration == NULL) {
		node_wg_error = ERROR_PROC_NOT_FOUND;
		Zero(&node_wg, sizeof(node_wg));
		FreeLibrary(m);
		return TRUE;
	}

	node_wg.Module = m;
	node_wg_loaded = true;

	return TRUE;
}

// Whether wireguard.dll is there and has the API of wireguard.h; error (when not NULL) gets why not: the error of the
// load, ERROR_PROC_NOT_FOUND for a DLL without that API
bool NodeWireGuardAvailable(UINT *error) {
	InitOnceExecuteOnce(&node_wg_once, NodeWireGuardLoad, NULL, NULL);

	if (error != NULL)
		*error = node_wg_error;

	return node_wg_loaded;
}

// The WireGuard key pair of the node of the static key key (see above): false when the static key cannot give one
bool NodeWireGuardKey(const PEER_KEY *key, UCHAR *priv, UCHAR *pub) {
	UCHAR point[CRYPTO_SHA256_SIZE];
	UCHAR shared[CRYPTO_X25519_SIZE];

	if (key == NULL || priv == NULL || pub == NULL)
		return false;

	bool ok = CryptoSha256(point, NODE_WIREGUARD_LABEL, sizeof(NODE_WIREGUARD_LABEL) - 1);
	if (ok)
		ok = (key->Identity != NULL ? CryptoIdentityDh(key->Identity, shared, point) : CryptoX25519(shared, key->Private, point));
	if (ok)
		ok = CryptoHkdf(priv, NODE_WIREGUARD_KEY_SIZE, NODE_WIREGUARD_LABEL, sizeof(NODE_WIREGUARD_LABEL) - 1, shared, sizeof(shared), "wireguard key", 13);
	if (ok) {
		// The clamping of X25519 (RFC 7748), as wg genkey writes a private key
		priv[0] &= 248;
		priv[31] = (UCHAR)((priv[31] & 127) | 64);
		ok = CryptoX25519PublicKey(pub, priv);
	}

	SecureZeroMemory(shared, sizeof(shared));
	if (ok == false) {
		SecureZeroMemory(priv, NODE_WIREGUARD_KEY_SIZE);
		Zero(pub, NODE_WIREGUARD_KEY_SIZE);
	}

	return ok;
}

// The Capabilities of the node of param (CONTROL_CAPS_PROC): those of its host (NodeCapsProc), and wireguard with the
// public key of its WireGuard interface when wireguard.dll loads
void NodeWireGuardCaps(void *param, CONTROL_CAPS *caps) {
	NODE *n = (NODE *)param;
	NODE_WIREGUARD *wg = (n != NULL ? n->WireGuard : NULL);

	NodeCapsProc(NULL, caps);

	if (wg == NULL || wg->HasKey == false || NodeWireGuardAvailable(NULL) == false)
		return;

	caps->WireGuard = true;
	Copy(caps->WireGuardKey, wg->Public, NODE_WIREGUARD_KEY_SIZE);
}

// Set Forwarding, WeakHostSend and WeakHostReceive of the IPv4 and the IPv6 interface of luid on, as a gateway takes them
// (SDN-5, #181): an interface of a family that it does not have is left alone. False when one could not be set; the
// node log says which.
static bool NodeWireGuardForward(NODE *n, const NET_LUID *luid, const char *what) {
	bool ok = true;

	for (UINT i = 0; i < 2; i++) {
		MIB_IPINTERFACE_ROW row;
		ADDRESS_FAMILY family = (ADDRESS_FAMILY)(i == 0 ? AF_INET : AF_INET6);

		InitializeIpInterfaceEntry(&row);
		row.Family = family;
		row.InterfaceLuid = *luid;
		DWORD err = GetIpInterfaceEntry(&row);
		if (err == ERROR_NOT_FOUND && family == AF_INET6)
			continue;

		if (err == NO_ERROR && row.ForwardingEnabled && row.WeakHostSend && row.WeakHostReceive)
			continue;

		if (err == NO_ERROR) {
			row.ForwardingEnabled = TRUE;
			row.WeakHostSend = TRUE;
			row.WeakHostReceive = TRUE;
			// SetIpInterfaceEntry refuses the site prefix length that GetIpInterfaceEntry gives (NodeWintunSetForwarding)
			row.SitePrefixLength = 0;
			err = SetIpInterfaceEntry(&row);
		}

		if (err != NO_ERROR) {
			NodeLog(n, "WireGuard: the forwarding of %s of %s could not be set on (error %u)", family == AF_INET ? "IPv4" : "IPv6", what, (UINT)err);
			ok = false;
		}
	}

	return ok;
}

// The row of a route of an address of a Device through the WireGuard interface: on-link, its next hop the unspecified
// address of its family
static void NodeWireGuardRouteRow(NODE_WIREGUARD *wg, MIB_IPFORWARD_ROW2 *row, const NODE_PREFIX *p) {
	InitializeIpForwardEntry(row);
	row->InterfaceLuid = wg->Luid;
	if (p->AddressSize == 4) {
		row->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
		Copy(&row->DestinationPrefix.Prefix.Ipv4.sin_addr, p->Address, 4);
		row->NextHop.si_family = AF_INET;
	} else {
		row->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
		Copy(&row->DestinationPrefix.Prefix.Ipv6.sin6_addr, p->Address, 16);
		row->NextHop.si_family = AF_INET6;
	}
	row->DestinationPrefix.PrefixLength = (UINT8)p->Length;
	row->Metric = 0;
	row->Protocol = MIB_IPPROTO_NETMGMT;
}

// Whether p is one of the num prefixes of list
static bool NodeWireGuardHas(const NODE_PREFIX *list, UINT num, const NODE_PREFIX *p) {
	for (UINT i = 0; i < num; i++)
		if (list[i].AddressSize == p->AddressSize && list[i].Length == p->Length && Cmp(list[i].Address, p->Address, p->AddressSize) == 0)
			return true;

	return false;
}

// Make the routes through the WireGuard interface the addresses of the Devices: the ones that it installed and no
// Device holds any more go, the new ones come. False when one could not be installed or removed. The caller holds the
// lock.
static bool NodeWireGuardSetRoutes(NODE_WIREGUARD *wg) {
	UINT max = wg->NumDevices * CONTROL_DEVICE_ADDRESSES;
	NODE_PREFIX *want = ZeroMalloc(sizeof(NODE_PREFIX) * MAX(max, 1));
	NODE_PREFIX *set = ZeroMalloc(sizeof(NODE_PREFIX) * MAX(max, 1));
	UINT num_want = 0, num_set = 0;
	bool ok = true;

	for (UINT i = 0; i < wg->NumDevices; i++)
		for (UINT j = 0; j < wg->Devices[i].NumAddresses; j++)
			if (NodeWireGuardHas(want, num_want, &wg->Devices[i].Addresses[j]) == false)
				want[num_want++] = wg->Devices[i].Addresses[j];

	for (UINT i = 0; i < wg->NumRoutes; i++) {
		MIB_IPFORWARD_ROW2 row;

		if (NodeWireGuardHas(want, num_want, &wg->Routes[i]))
			continue;

		NodeWireGuardRouteRow(wg, &row, &wg->Routes[i]);
		DWORD err = DeleteIpForwardEntry2(&row);
		if (err != NO_ERROR && err != ERROR_NOT_FOUND) {
			NodeLog(wg->Node, "WireGuard: a route of a Device could not be removed (error %u)", (UINT)err);
			ok = false;
		}
	}

	for (UINT i = 0; i < num_want; i++) {
		MIB_IPFORWARD_ROW2 row;

		NodeWireGuardRouteRow(wg, &row, &want[i]);
		DWORD err = CreateIpForwardEntry2(&row);
		if (err == NO_ERROR || err == ERROR_OBJECT_ALREADY_EXISTS) {
			set[num_set++] = want[i];
		} else {
			NodeLog(wg->Node, "WireGuard: a route of a Device could not be installed (error %u)", (UINT)err);
			ok = false;
		}
	}

	Free(wg->Routes);
	Free(want);
	wg->Routes = set;
	wg->NumRoutes = num_set;

	return ok;
}

// The configuration of the WireGuard interface for the Devices: its private key, its port and each Device as a peer
// whose allowed IPs are its addresses, in place of the peers before. Its size in size; Free frees it.
static NODE_WG_INTERFACE *NodeWireGuardConfig(NODE_WIREGUARD *wg, DWORD *size) {
	UINT bytes = (UINT)sizeof(NODE_WG_INTERFACE);

	for (UINT i = 0; i < wg->NumDevices; i++)
		bytes += (UINT)(sizeof(NODE_WG_PEER) + sizeof(NODE_WG_ALLOWED_IP) * wg->Devices[i].NumAddresses);

	UCHAR *buf = ZeroMalloc(bytes);
	NODE_WG_INTERFACE *iface = (NODE_WG_INTERFACE *)buf;
	UINT pos = (UINT)sizeof(NODE_WG_INTERFACE);

	iface->Flags = NODE_WG_INTERFACE_HAS_PRIVATE | NODE_WG_INTERFACE_HAS_PORT | NODE_WG_INTERFACE_REPLACE_PEERS;
	iface->ListenPort = (WORD)wg->Port;
	Copy(iface->PrivateKey, wg->Private, NODE_WIREGUARD_KEY_SIZE);
	iface->PeersCount = wg->NumDevices;

	for (UINT i = 0; i < wg->NumDevices; i++) {
		const NODE_WG_DEVICE *d = &wg->Devices[i];
		NODE_WG_PEER *peer = (NODE_WG_PEER *)(buf + pos);

		peer->Flags = NODE_WG_PEER_HAS_PUBLIC_KEY | NODE_WG_PEER_REPLACE_ALLOWED;
		Copy(peer->PublicKey, d->Key, NODE_WIREGUARD_KEY_SIZE);
		if (d->HasPreshared) {
			peer->Flags |= NODE_WG_PEER_HAS_PRESHARED_KEY;
			Copy(peer->PresharedKey, d->Preshared, NODE_WIREGUARD_KEY_SIZE);
		}
		peer->AllowedIPsCount = d->NumAddresses;
		pos += (UINT)sizeof(NODE_WG_PEER);

		for (UINT j = 0; j < d->NumAddresses; j++) {
			NODE_WG_ALLOWED_IP *ip = (NODE_WG_ALLOWED_IP *)(buf + pos);

			if (d->Addresses[j].AddressSize == 4) {
				ip->AddressFamily = AF_INET;
				Copy(&ip->Address.V4, d->Addresses[j].Address, 4);
			} else {
				ip->AddressFamily = AF_INET6;
				Copy(&ip->Address.V6, d->Addresses[j].Address, 16);
			}
			ip->Cidr = (BYTE)d->Addresses[j].Length;
			pos += (UINT)sizeof(NODE_WG_ALLOWED_IP);
		}
	}

	*size = bytes;
	return iface;
}

// Take the WireGuard interface away, with its routes, and forget its Devices. The caller holds the lock.
static void NodeWireGuardDown(NODE_WIREGUARD *wg) {
	if (wg->Adapter != NULL) {
		node_wg.CloseAdapter(wg->Adapter);
		wg->Adapter = NULL;
		NodeLog(wg->Node, "WireGuard: the interface went down: the node is the gateway of no Device");
	}
	NodeWireGuardRelease(wg->Isolation);
	wg->Isolation = NULL;
	wg->Pairs = 0;

	if (wg->Devices != NULL)
		SecureZeroMemory(wg->Devices, sizeof(NODE_WG_DEVICE) * wg->NumDevices);
	Free(wg->Devices);
	wg->Devices = NULL;
	wg->NumDevices = 0;
	Free(wg->Routes);
	wg->Routes = NULL;
	wg->NumRoutes = 0;
	wg->Port = 0;
	Zero(&wg->Luid, sizeof(wg->Luid));
	wg->Index = 0;
}

// Bring the WireGuard interface up for the state st, of the node named name: one is created when there is none. The
// caller holds the lock. False when it cannot come up.
static bool NodeWireGuardUp(NODE_WIREGUARD *wg, const CONTROL_STATE *st) {
	wchar_t name[NODE_VRF_ADAPTER_NAME];
	GUID guid;
	ULONG index = 0;

	if (wg->Adapter != NULL)
		return true;

	UniFormat(name, sizeof(name), L"%s %S", NODE_WIREGUARD_ADAPTER, st->Name);
	NodeVrfAdapterGuid(&guid, wg->Key->Public, 0);

	// An interface of this name that the node closed a moment ago may still hold the GUID
	for (UINT64 end = GetTickCount64() + NODE_WINTUN_CREATE_WAIT;;) {
		wg->Adapter = node_wg.CreateAdapter(name, NODE_WINTUN_TYPE, &guid);
		if (wg->Adapter != NULL || GetTickCount64() >= end)
			break;
		Sleep(NODE_WINTUN_CREATE_RETRY);
	}

	if (wg->Adapter == NULL) {
		NodeLog(wg->Node, "WireGuard: the interface %S could not be created (error %u)", name, (UINT)GetLastError());
		return false;
	}

	node_wg.GetAdapterLuid(wg->Adapter, &wg->Luid);
	if (ConvertInterfaceLuidToIndex(&wg->Luid, &index) == NO_ERROR)
		wg->Index = (UINT)index;

	UINT version = (UINT)node_wg.GetRunningDriverVersion();
	NodeLog(wg->Node, "WireGuard: the interface %S is up: interface %u, driver %u.%u", name, wg->Index, version >> 16, version & 0xFFFF);

	return true;
}

// The Devices of the state st whose gateway the node is, into the list of the WireGuard end: their number
static UINT NodeWireGuardDevices(NODE_WIREGUARD *wg, const CONTROL_STATE *st) {
	if (wg->Devices != NULL)
		SecureZeroMemory(wg->Devices, sizeof(NODE_WG_DEVICE) * wg->NumDevices);
	Free(wg->Devices);
	wg->Devices = ZeroMalloc(sizeof(NODE_WG_DEVICE) * MAX(st->NumDevices, 1));
	wg->NumDevices = 0;

	for (UINT i = 0; i < st->NumDevices; i++) {
		const CONTROL_DEVICE *cd = &st->Devices[i];
		NODE_WG_DEVICE *d = &wg->Devices[wg->NumDevices];

		if (cd->HasKey == false || StrCmp(cd->Gateway, st->Name) != 0 || wg->NumDevices >= CONTROL_MAX_DEVICES)
			continue;

		StrCpy(d->Name, sizeof(d->Name), cd->Name);
		Copy(d->Key, cd->Key, NODE_WIREGUARD_KEY_SIZE);
		d->HasPreshared = cd->HasPreshared;
		if (cd->HasPreshared)
			Copy(d->Preshared, cd->Preshared, NODE_WIREGUARD_KEY_SIZE);
		d->VrfId = cd->VrfId;
		for (UINT j = 0; j < cd->NumAddresses && j < CONTROL_DEVICE_ADDRESSES; j++) {
			NODE_PREFIX *p = &d->Addresses[d->NumAddresses++];

			Copy(p->Address, cd->Addresses[j].Address, cd->Addresses[j].AddressSize);
			p->AddressSize = cd->Addresses[j].AddressSize;
			p->Length = cd->Addresses[j].AddressSize * 8;
		}
		wg->NumDevices++;
	}

	return wg->NumDevices;
}

// The state st that the overlay applied, once its forwarding tables are in: the WireGuard interface terminates the
// Devices whose gateway the node is, on the port of the state, and Windows forwards between it and the adapter of the
// VRF of each of them; a state without one takes the interface away (see above)
void NodeWireGuardApplied(NODE *n, const CONTROL_STATE *st) {
	NODE_WIREGUARD *wg = (n != NULL ? n->WireGuard : NULL);
	UINT error = 0;

	if (wg == NULL || st == NULL)
		return;

	Lock(wg->Lock);
	{
		UINT num = NodeWireGuardDevices(wg, st);

		if (num == 0 || st->WireGuardPort == 0 || st->WireGuardPort > 65535) {
			NodeWireGuardDown(wg);
		} else if (wg->HasKey == false || NodeWireGuardAvailable(&error) == false) {
			NodeLog(n, "WireGuard: generation %I64u: %u Devices, and no interface: %S cannot be loaded (error %u)", st->Generation, num, NODE_WIREGUARD_DLL, error);
			NodeWireGuardDown(wg);
		} else {
			bool ok = NodeWireGuardUp(wg, st);
			DWORD size = 0;

			wg->Port = st->WireGuardPort;
			if (ok) {
				NODE_WG_INTERFACE *config = NodeWireGuardConfig(wg, &size);

				ok = node_wg.SetConfiguration(wg->Adapter, config, size) && node_wg.SetAdapterState(wg->Adapter, NODE_WG_ADAPTER_UP);
				if (ok == false)
					NodeLog(n, "WireGuard: generation %I64u: the configuration of the interface could not be set (error %u)", st->Generation, (UINT)GetLastError());
				SecureZeroMemory(config, size);
				Free(config);
			}

			// Windows forwards between the WireGuard interface and the adapter of the VRF of each Device
			if (ok) {
				ok = NodeWireGuardForward(n, &wg->Luid, "the WireGuard interface") && ok;
				for (UINT i = 0; i < wg->NumDevices; i++) {
					GUID guid;
					NET_LUID luid;

					NodeVrfAdapterGuid(&guid, wg->Key->Public, wg->Devices[i].VrfId);
					if (ConvertInterfaceGuidToLuid(&guid, &luid) == NO_ERROR)
						ok = NodeWireGuardForward(n, &luid, "the adapter of the VRF of a Device") && ok;
				}
				ok = NodeWireGuardSetRoutes(wg) && ok;
				// ... but not between two Devices on the WireGuard interface itself, which the policy would not see, unless the
				// rules of the state let them meet: the filters of this state go in before the ones of the state before go
				UINT pairs = 0;
				HANDLE isolation = NodeWireGuardIsolate(n, wg->Index, st, &pairs);
				if (isolation != NULL) {
					NodeWireGuardRelease(wg->Isolation);
					wg->Isolation = isolation;
					wg->Pairs = pairs;
				}
				ok = (isolation != NULL) && ok;
			}

			NodeLog(n, "WireGuard: generation %I64u: %u Devices on UDP port %u%s", st->Generation, wg->NumDevices, wg->Port,
			        ok ? "" : " (not all of it set, see the lines before)");
		}
	}
	Unlock(wg->Lock);
}

// The counters of the Devices from the configuration of the interface, which the caller holds the lock of: the last
// handshake and the bytes of each peer that is a Device, into the report of the control stream
static void NodeWireGuardCount(NODE_WIREGUARD *wg) {
	DWORD size = 0;
	UCHAR *buf = NULL;
	CONTROL_DEVICE_COUNTERS *counters = NULL;
	UINT num = 0;

	if (wg->Adapter == NULL) {
		ControlSetDevices(wg->Report, NULL, 0);
		return;
	}

	// The first call gives the size that the configuration takes, the second the configuration
	if (node_wg.GetConfiguration(wg->Adapter, NULL, &size) == FALSE && GetLastError() == ERROR_MORE_DATA && size >= sizeof(NODE_WG_INTERFACE)) {
		buf = ZeroMalloc(size);
		if (node_wg.GetConfiguration(wg->Adapter, buf, &size) == FALSE) {
			Free(buf);
			buf = NULL;
		}
	}

	if (buf == NULL)
		return;

	const NODE_WG_INTERFACE *iface = (const NODE_WG_INTERFACE *)buf;
	UINT64 pos = sizeof(NODE_WG_INTERFACE);

	counters = ZeroMalloc(sizeof(CONTROL_DEVICE_COUNTERS) * MAX(wg->NumDevices, 1));
	for (UINT i = 0; i < iface->PeersCount && pos + sizeof(NODE_WG_PEER) <= size; i++) {
		const NODE_WG_PEER *peer = (const NODE_WG_PEER *)(buf + pos);

		for (UINT j = 0; j < wg->NumDevices && num < wg->NumDevices; j++) {
			CONTROL_DEVICE_COUNTERS *c = &counters[num];

			if (Cmp(wg->Devices[j].Key, peer->PublicKey, NODE_WIREGUARD_KEY_SIZE) != 0)
				continue;

			StrCpy(c->Name, sizeof(c->Name), wg->Devices[j].Name);
			// LastHandshake is a FILETIME: 100 ns intervals since 1601
			if (peer->LastHandshake > NODE_WIREGUARD_UNIX_EPOCH)
				c->LastHandshake = (peer->LastHandshake - NODE_WIREGUARD_UNIX_EPOCH) / 10000;
			c->TxBytes = peer->TxBytes;
			c->RxBytes = peer->RxBytes;
			num++;
			break;
		}

		pos += sizeof(NODE_WG_PEER) + sizeof(NODE_WG_ALLOWED_IP) * (UINT64)peer->AllowedIPsCount;
	}

	ControlSetDevices(wg->Report, counters, num);

	SecureZeroMemory(buf, size);
	Free(buf);
	Free(counters);
}

// The thread of the counters: every NODE_WIREGUARD_COUNT ms until the halt event
static DWORD WINAPI NodeWireGuardThread(LPVOID param) {
	NODE_WIREGUARD *wg = (NODE_WIREGUARD *)param;

	while (WaitForSingleObject(wg->Halt, NODE_WIREGUARD_COUNT) == WAIT_TIMEOUT) {
		Lock(wg->Lock);
		NodeWireGuardCount(wg);
		Unlock(wg->Lock);
	}

	return 0;
}

// Start the WireGuard end of a node with the overlay (NodeOverlayStart): its key pair from the static key of the
// configuration, and the thread of the counters. It returns the counters that the control stream reports
// (CONTROL_CONFIG.Devices), NULL when there is no memory for them.
CONTROL_DEVICES *NodeWireGuardStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg) {
	DWORD thread_id = 0;

	if (n == NULL || cfg == NULL || cfg->Key == NULL || n->WireGuard != NULL)
		return NULL;

	NODE_WIREGUARD *wg = ZeroMalloc(sizeof(NODE_WIREGUARD));
	wg->Node = n;
	wg->Key = cfg->Key;
	wg->Lock = NewLock();
	wg->Report = ControlNewDevices();
	wg->HasKey = NodeWireGuardKey(cfg->Key, wg->Private, wg->Public);
	wg->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	wg->Thread = (wg->Halt != NULL ? CreateThread(NULL, 0, NodeWireGuardThread, wg, 0, &thread_id) : NULL);

	n->WireGuard = wg;

	if (wg->HasKey == false)
		NodeLog(n, "WireGuard: no key pair: the static key of the node gives none, so the node is the gateway of no Device");

	return wg->Report;
}

// Stop the WireGuard end of a node (NodeOverlayStop), after the control stream that reported its counters: the thread of
// the counters ends and the interface goes, with its routes
void NodeWireGuardStop(NODE *n) {
	NODE_WIREGUARD *wg = (n != NULL ? n->WireGuard : NULL);

	if (wg == NULL)
		return;

	if (wg->Thread != NULL) {
		SetEvent(wg->Halt);
		WaitForSingleObject(wg->Thread, INFINITE);
		CloseHandle(wg->Thread);
	}
	if (wg->Halt != NULL)
		CloseHandle(wg->Halt);

	n->WireGuard = NULL;

	Lock(wg->Lock);
	NodeWireGuardDown(wg);
	Unlock(wg->Lock);

	ControlFreeDevices(wg->Report);
	DeleteLock(wg->Lock);
	SecureZeroMemory(wg->Private, sizeof(wg->Private));
	Free(wg);
}

// How the WireGuard end of a node stands
void NodeWireGuardGetStatus(NODE *n, NODE_WIREGUARD_STATUS *st) {
	NODE_WIREGUARD *wg = (n != NULL ? n->WireGuard : NULL);

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_WIREGUARD_STATUS));
	st->Available = NodeWireGuardAvailable(NULL);
	if (wg == NULL)
		return;

	Lock(wg->Lock);
	{
		st->HasKey = wg->HasKey;
		Copy(st->Key, wg->Public, NODE_WIREGUARD_KEY_SIZE);
		st->Up = (wg->Adapter != NULL);
		st->Port = wg->Port;
		st->InterfaceIndex = wg->Index;
		st->InterfaceLuid = wg->Luid.Value;
		st->NumDevices = wg->NumDevices;
		st->NumRoutes = wg->NumRoutes;
		st->Isolated = (wg->Isolation != NULL);
		st->NumPairs = wg->Pairs;
	}
	Unlock(wg->Lock);
}

// The routes of the WireGuard Devices of the state st in the forwarding tables of their VRFs (NodeOverlay.c): the
// addresses of a Device whose gateway the node is lead to the host, which forwards them to its WireGuard interface,
// those of any other Device to the peer that is its gateway, next hop i of the tables being st->Peers[i]. A Device whose
// gateway is no peer is left out. Without routes, their number.
UINT NodeDeviceRoutes(const CONTROL_STATE *st, NODE_VRF_ROUTE *routes) {
	UINT num = 0;

	if (st == NULL || st->Devices == NULL)
		return 0;

	for (UINT i = 0; i < st->NumDevices; i++) {
		const CONTROL_DEVICE *d = &st->Devices[i];
		UINT hop = NODE_VRF_NONE;

		if (d->HasKey && StrCmp(d->Gateway, st->Name) == 0) {
			hop = NODE_VRF_LOCAL;
		} else {
			for (UINT j = 0; j < st->NumPeers && hop == NODE_VRF_NONE; j++)
				if (StrCmp(st->Peers[j].Name, d->Gateway) == 0)
					hop = j;
		}

		if (hop == NODE_VRF_NONE)
			continue;

		for (UINT j = 0; j < d->NumAddresses; j++) {
			const CONTROL_ADDRESS *a = &d->Addresses[j];

			if (a->AddressSize != 4 && a->AddressSize != 16)
				continue;

			if (routes != NULL) {
				NODE_VRF_ROUTE *r = &routes[num];

				Zero(r, sizeof(NODE_VRF_ROUTE));
				r->VrfId = d->VrfId;
				Copy(r->Address, a->Address, a->AddressSize);
				r->AddressSize = a->AddressSize;
				r->Length = a->AddressSize * 8;
				r->NextHop = hop;
			}
			num++;
		}
	}

	return num;
}
