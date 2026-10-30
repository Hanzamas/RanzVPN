// NodeEgressNat.c
// The Egress tiers on the NAT of Windows (SDN-12, #188; ADR-0025 decisions 6 and 13): what the internet exit of a VRF
// (NodeEgress.c) configures when its host gives it tier 1 or 2, and what the Capabilities of the host read to give it
// (NodeCaps.c).
// - Tier 1, the NAT of Routing and Remote Access, on a Windows Server whose RRAS runs as an IPv4 router of LAN interfaces:
//   the node adds the NAT routing protocol to the IPv4 router of RRAS where it lacks it, makes the adapter of each VRF
//   whose exit it is a private interface of the NAT and each interface that carries the egress a public one, a boundary
//   with address and port translation (IP_NAT_INTERFACE_INFO under MS_IP_NAT, MS-RRASM 2.2.1.2.197), through the MprConfig
//   functions, which keep the configuration of the router, and the MprAdmin ones, which give it to the running router, as
//   netsh routing ip nat does. RRAS knows the interfaces of the adapters that it found when it started: where it lacks the
//   interface of an adapter that came after, as the adapter of a VRF does, or the IPv4 transport of the interface, the node
//   adds them with the NAT information, as netsh routing ip add interface does, and takes out again what it added.
//   mprapi.dll is loaded at run time: Windows documents the configuration of the router for Windows Server only, so a node
//   of another edition never imports it.
// - Tier 2, WinNAT: the node creates the NAT network of WinNAT of its own name (NODE_EGRESS_NETNAT_NAME) over one supernet
//   that holds every IPv4 prefix of the VRFs whose exit it is, as an instance of MSFT_NetNat of the WMI namespace
//   ROOT\StandardCimv2, which is what New-NetNat creates. WinNAT allows one NAT network per host, and Ranz never touches
//   one of another name: one that the reconcile finds makes the Egress fall back to the proxy (NodeEgressNatForeign), and
//   once a look of the node found one, its Capabilities give the proxy (NodeEgressForeignNetNat).
//   Only tier 2 asks WMI. A process that uses WMI loads the provider of the Antimalware Scan Interface of the antivirus of the
//   host, which Microsoft Defender keeps outside System32 (MpOav.dll), and the node loads DLLs from System32 only (ADR-0039
//   decision 3): the Capabilities, which every node reads at each start and for each Hello, ask WMI nothing, so a node that
//   serves no VRF on WinNAT never loads that provider.
// The thread of the Egress reconciles the NAT against the Generation applied last every NODE_EGRESS_NAT_SCAN
// (NodeEgressNatApply): what something else removed or changed, an operator or a reset of RRAS by an update of Windows, it
// sets again, and counts. It undoes what it configured once the node is the exit of no VRF, or stops (NodeEgressNatFree).

// COBJMACROS: the IWbemLocator_*, IWbemServices_*, IEnumWbemClassObject_* and IWbemClassObject_* call macros of wbemcli.h
// (the COM interfaces are C structs here)
#define COBJMACROS

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeEgress.h"
#include "NodeInternal.h"

#include <iphlpapi.h>
#include <objbase.h>
#include <oleauto.h>
#include <rtinfo.h>
#include <wbemidl.h>

// The NAT routing protocol of the IPv4 router of RRAS: the type of its global and interface information (MS_IP_NAT of
// MS-RRASM 2.2.1.2.3)
#define NODE_EGRESS_MS_IP_NAT 0x81372715
// The status of an interface in its IPv4 information (IP_INTERFACE_STATUS_INFO of ipinfoid.h), and the status of one that is
// up (MIB_IF_ADMIN_STATUS_UP)
#define NODE_EGRESS_IP_STATUS 0xFFFF0004
#define NODE_EGRESS_ADMIN_UP  1
// The IPv4 router manager of RRAS (PID_IP of mprapi.h)
#define NODE_EGRESS_PID_IP 0x00000021
// The type of the interface of a LAN adapter in RRAS (ROUTER_IF_TYPE_DEDICATED of mprapi.h)
#define NODE_EGRESS_IF_DEDICATED 3
// The characters of the name of an interface of the router at level 0, with its end (MAX_INTERFACE_NAME_LEN + 1 of mprapi.h)
#define NODE_EGRESS_MPR_NAME 257
// The errors with which the router says that it lacks the interface, or the IPv4 transport of the interface, that it was asked
// for (ERROR_UNKNOWN_PROTOCOL_ID and ERROR_NO_SUCH_INTERFACE of mprerror.h)
#define NODE_EGRESS_MPR_NO_PROTOCOL  902
#define NODE_EGRESS_MPR_NO_INTERFACE 905
// What the node added to RRAS for an interface beside its NAT information, which it takes out again: the interface, which RRAS
// lacks for an adapter that came after the router started, or the IPv4 transport of the interface
#define NODE_EGRESS_MADE_INTERFACE 0x01
#define NODE_EGRESS_MADE_TRANSPORT 0x02
// The error with which the node says that the running router of RRAS kept the NAT information that it was told to delete
#define NODE_EGRESS_RRAS_KEPT ERROR_CAN_NOT_COMPLETE
// The logging level that the node gives the NAT routing protocol: errors only (IPNATHLP_LOGGING_ERROR, MS-RRASM 2.2.1.2.195)
#define NODE_EGRESS_NAT_LOGGING 1
// The router types of RRAS (RouterType, MS-RRASM 2.2.3.4.1): IPv4 routing over LAN interfaces, and over demand-dial ones too
#define NODE_EGRESS_ROUTER_LAN 0x00000002
#define NODE_EGRESS_ROUTER_WAN 0x00000004
// The key of the parameters of RRAS, which holds its router type
#define NODE_EGRESS_RRAS_KEY L"SYSTEM\\CurrentControlSet\\Services\\RemoteAccess\\Parameters"
// The characters of the name of an interface in RRAS, the GUID of its adapter in braces, with its end
#define NODE_EGRESS_RRAS_NAME 40
// The interfaces of the NAT of RRAS that the node keeps configured at most: the adapters of the VRFs whose exit it is and the
// interfaces that carry the egress
#define NODE_EGRESS_RRAS_MAX (NODE_EGRESS_MAX_PRIVATE + NODE_EGRESS_MAX_UPLINKS)

// The WMI namespace of the NAT networks of WinNAT and their class, which New-NetNat and Get-NetNat use
#define NODE_EGRESS_WMI_NAMESPACE L"ROOT\\StandardCimv2"
#define NODE_EGRESS_NETNAT_CLASS  L"MSFT_NetNat"
// The NAT networks of WinNAT that one look counts at most
#define NODE_EGRESS_NETNAT_MAX 64
// The characters of the internal prefix of a NAT network of WinNAT, "255.255.255.255/32" and room
#define NODE_EGRESS_PREFIX 64

// The class and the interface of the WMI locator. wbemcli.h only declares their CLSID_ and IID_ constants; this file defines
// its own copies, so it needs no library that defines them (as MicrosoftFirewall.c does).
static const CLSID node_egress_clsid_wbem_locator = {0x4590F811, 0x1D3A, 0x11D0, {0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};
static const IID node_egress_iid_wbem_locator = {0xDC12A687, 0x737F, 0x11CF, {0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}};

// The global information of the NAT routing protocol (IP_NAT_GLOBAL_INFO, MS-RRASM 2.2.1.2.195): a logging level, flags that
// are 0, and an information header that holds no timeouts
typedef struct NODE_EGRESS_NAT_GLOBAL {
	ULONG LoggingLevel;
	ULONG Flags;
	RTR_INFO_BLOCK_HEADER Header;
} NODE_EGRESS_NAT_GLOBAL;

// The NAT information of an interface (IP_NAT_INTERFACE_INFO, MS-RRASM 2.2.1.2.197): its index, its flags, and an information
// header that holds no port or address mapping
typedef struct NODE_EGRESS_NAT_INTERFACE {
	ULONG Index;
	ULONG Flags;
	RTR_INFO_BLOCK_HEADER Header;
} NODE_EGRESS_NAT_INTERFACE;

// An interface of the router at level 0 (MPR_INTERFACE_0 of mprapi.h): what MprAdminInterfaceCreate and MprConfigInterfaceCreate
// take for the interface of an adapter that RRAS lacks
typedef struct NODE_EGRESS_MPR_INTERFACE {
	WCHAR Name[NODE_EGRESS_MPR_NAME]; // The name of the interface: the GUID of its adapter in braces
	HANDLE Interface;                 // What the router gives back ...
	BOOL Enabled;                     // ... the interface is enabled ...
	DWORD Type;                       // ... its type, NODE_EGRESS_IF_DEDICATED (ROUTER_INTERFACE_TYPE) ...
	DWORD ConnectionState;            // ... and what the router gives back (ROUTER_CONNECTION_STATE ...)
	DWORD UnreachabilityReasons;
	DWORD LastError;
} NODE_EGRESS_MPR_INTERFACE;

// The functions of mprapi.dll that the NAT of RRAS uses
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONNECT_FUNC)(LPWSTR server, HANDLE *handle);
typedef VOID(APIENTRY NODE_EGRESS_MPR_DISCONNECT_FUNC)(HANDLE handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_FREE_FUNC)(LPVOID buffer);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_TRANSPORT_FUNC)(HANDLE config, DWORD transport, HANDLE *handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_GET_FUNC)(HANDLE config, HANDLE transport, LPBYTE *global, LPDWORD global_size, LPBYTE *client, LPDWORD client_size, LPWSTR *dll);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_SET_FUNC)(HANDLE config, HANDLE transport, LPBYTE global, DWORD global_size, LPBYTE client, DWORD client_size, LPWSTR dll);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_FUNC)(HANDLE config, LPWSTR name, HANDLE *handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_TRANSPORT_FUNC)(HANDLE config, HANDLE iface, DWORD transport, HANDLE *handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_GET_FUNC)(HANDLE config, HANDLE iface, HANDLE transport, LPBYTE *info, LPDWORD size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_SET_FUNC)(HANDLE config, HANDLE iface, HANDLE transport, LPBYTE info, DWORD size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_GET_FUNC)(HANDLE server, DWORD transport, LPBYTE *global, LPDWORD global_size, LPBYTE *client, LPDWORD client_size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_SET_FUNC)(HANDLE server, DWORD transport, LPBYTE global, DWORD global_size, LPBYTE client, DWORD client_size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_IF_FUNC)(HANDLE server, LPWSTR name, HANDLE *handle, BOOL clients);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_IF_GET_FUNC)(HANDLE server, HANDLE iface, DWORD transport, LPBYTE *info, LPDWORD size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_IF_SET_FUNC)(HANDLE server, HANDLE iface, DWORD transport, LPBYTE info, DWORD size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_IF_CREATE_FUNC)(HANDLE server, DWORD level, LPBYTE buffer, HANDLE *handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_IF_DELETE_FUNC)(HANDLE server, HANDLE iface);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_ADD_FUNC)(HANDLE config, HANDLE iface, DWORD transport, LPWSTR name, LPBYTE info, DWORD size, HANDLE *handle);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CONFIG_IF_REMOVE_FUNC)(HANDLE config, HANDLE iface, HANDLE transport);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_IF_ADD_FUNC)(HANDLE server, HANDLE iface, DWORD transport, LPBYTE info, DWORD size);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADMIN_IF_REMOVE_FUNC)(HANDLE server, HANDLE iface, DWORD transport);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_CREATE_FUNC)(DWORD version, LPVOID *header);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_DUPLICATE_FUNC)(LPVOID header, LPVOID *copy);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_FIND_FUNC)(LPVOID header, DWORD type, LPDWORD item_size, LPDWORD count, LPBYTE *data);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_ADD_FUNC)(LPVOID header, DWORD type, DWORD item_size, DWORD count, LPBYTE data, LPVOID *next);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_REMOVE_FUNC)(LPVOID header, DWORD type, LPVOID *next);
typedef DWORD(APIENTRY NODE_EGRESS_MPR_SIZE_FUNC)(LPVOID header);

// mprapi.dll with the functions that the NAT of RRAS uses, and the connections to the configuration of the router and to the
// running router
typedef struct NODE_EGRESS_MPR {
	HMODULE Module;                                              // mprapi.dll
	NODE_EGRESS_MPR_CONNECT_FUNC *ConfigConnect;                 // MprConfigServerConnect
	NODE_EGRESS_MPR_DISCONNECT_FUNC *ConfigDisconnect;           // MprConfigServerDisconnect
	NODE_EGRESS_MPR_FREE_FUNC *ConfigFree;                       // MprConfigBufferFree
	NODE_EGRESS_MPR_TRANSPORT_FUNC *ConfigTransport;             // MprConfigTransportGetHandle
	NODE_EGRESS_MPR_CONFIG_GET_FUNC *ConfigGet;                  // MprConfigTransportGetInfo
	NODE_EGRESS_MPR_CONFIG_SET_FUNC *ConfigSet;                  // MprConfigTransportSetInfo
	NODE_EGRESS_MPR_CONFIG_IF_FUNC *ConfigIf;                    // MprConfigInterfaceGetHandle
	NODE_EGRESS_MPR_CONFIG_IF_TRANSPORT_FUNC *ConfigIfTransport; // MprConfigInterfaceTransportGetHandle
	NODE_EGRESS_MPR_CONFIG_IF_GET_FUNC *ConfigIfGet;             // MprConfigInterfaceTransportGetInfo
	NODE_EGRESS_MPR_CONFIG_IF_SET_FUNC *ConfigIfSet;             // MprConfigInterfaceTransportSetInfo
	NODE_EGRESS_MPR_IF_CREATE_FUNC *ConfigIfCreate;              // MprConfigInterfaceCreate
	NODE_EGRESS_MPR_IF_DELETE_FUNC *ConfigIfDelete;              // MprConfigInterfaceDelete
	NODE_EGRESS_MPR_CONFIG_IF_ADD_FUNC *ConfigIfAdd;             // MprConfigInterfaceTransportAdd
	NODE_EGRESS_MPR_CONFIG_IF_REMOVE_FUNC *ConfigIfRemove;       // MprConfigInterfaceTransportRemove
	NODE_EGRESS_MPR_CONNECT_FUNC *AdminConnect;                  // MprAdminServerConnect
	NODE_EGRESS_MPR_DISCONNECT_FUNC *AdminDisconnect;            // MprAdminServerDisconnect
	NODE_EGRESS_MPR_FREE_FUNC *AdminFree;                        // MprAdminBufferFree
	NODE_EGRESS_MPR_ADMIN_GET_FUNC *AdminGet;                    // MprAdminTransportGetInfo
	NODE_EGRESS_MPR_ADMIN_SET_FUNC *AdminSet;                    // MprAdminTransportSetInfo
	NODE_EGRESS_MPR_ADMIN_IF_FUNC *AdminIf;                      // MprAdminInterfaceGetHandle
	NODE_EGRESS_MPR_ADMIN_IF_GET_FUNC *AdminIfGet;               // MprAdminInterfaceTransportGetInfo
	NODE_EGRESS_MPR_ADMIN_IF_SET_FUNC *AdminIfSet;               // MprAdminInterfaceTransportSetInfo
	NODE_EGRESS_MPR_IF_CREATE_FUNC *AdminIfCreate;               // MprAdminInterfaceCreate
	NODE_EGRESS_MPR_IF_DELETE_FUNC *AdminIfDelete;               // MprAdminInterfaceDelete
	NODE_EGRESS_MPR_ADMIN_IF_ADD_FUNC *AdminIfAdd;               // MprAdminInterfaceTransportAdd
	NODE_EGRESS_MPR_ADMIN_IF_REMOVE_FUNC *AdminIfRemove;         // MprAdminInterfaceTransportRemove
	NODE_EGRESS_MPR_CREATE_FUNC *InfoCreate;                     // MprInfoCreate
	NODE_EGRESS_MPR_DUPLICATE_FUNC *InfoDuplicate;               // MprInfoDuplicate
	NODE_EGRESS_MPR_FIND_FUNC *BlockFind;                        // MprInfoBlockFind
	NODE_EGRESS_MPR_ADD_FUNC *BlockAdd;                          // MprInfoBlockAdd
	NODE_EGRESS_MPR_ADD_FUNC *BlockSet;                          // MprInfoBlockSet
	NODE_EGRESS_MPR_REMOVE_FUNC *BlockRemove;                    // MprInfoBlockRemove
	NODE_EGRESS_MPR_SIZE_FUNC *BlockSize;                        // MprInfoBlockQuerySize
	NODE_EGRESS_MPR_FREE_FUNC *InfoDelete;                       // MprInfoDelete
	HANDLE Config;                                               // The configuration of the router (MprConfigServerConnect)
	HANDLE Admin;                                                // The running router (MprAdminServerConnect)
} NODE_EGRESS_MPR;

// The IPv4 information of an interface of the running router or of the configuration of the router (NodeEgressRrasGet), with
// the handles that NodeEgressRrasPut takes
typedef struct NODE_EGRESS_RRAS_INFO {
	bool Config;      // Of the configuration of the router, else of the running router
	UINT Lacks;       // Without the information: the router lacks the interface or its IPv4 transport (NODE_EGRESS_MADE_*), 0 for neither
	HANDLE Interface; // The interface
	HANDLE Transport; // ... and its IPv4 transport in the configuration
	LPBYTE Info;      // Its IPv4 information, which NodeEgressRrasDone frees ...
	DWORD Size;       // ... and its bytes
} NODE_EGRESS_RRAS_INFO;

// An interface of the NAT of RRAS that the node keeps configured
typedef struct NODE_EGRESS_RRAS_IF {
	UINT64 Luid;                         // The interface
	wchar_t Name[NODE_EGRESS_RRAS_NAME]; // ... and its name in RRAS, which the node keeps for when its adapter is gone
	UINT Flags;                          // Its NAT flags: 0 for a private interface, NODE_EGRESS_RRAS_PUBLIC for a public one
	bool Done;                           // The running router took them from the node
	UINT Made[2];                        // What the node added for it to the running router [0] and to the configuration [1] (NODE_EGRESS_MADE_*)
} NODE_EGRESS_RRAS_IF;

// A connection to the WMI namespace of WinNAT, with COM initialized on the calling thread for it
typedef struct NODE_EGRESS_WMI {
	IWbemServices *Services; // The namespace
	bool Com;                // CoInitializeEx took a reference that NodeEgressWmiClose gives back
} NODE_EGRESS_WMI;

// The NAT networks of WinNAT on the host, as one look sees them (NodeEgressNetNats)
typedef struct NODE_EGRESS_NETNATS {
	UINT NumOthers;                     // The NAT networks of another name than the one looked for
	UINT NumForeign;                    // The NAT networks of another name than the node's (NODE_EGRESS_NETNAT_NAME)
	bool Found;                         // The one of the name exists ...
	wchar_t Prefix[NODE_EGRESS_PREFIX]; // ... with this internal prefix ...
	BSTR Path;                          // ... and this object path, which NodeEgressNetNatsFree frees
} NODE_EGRESS_NETNATS;

// What the node configured in the NAT of Windows, the thread of the Egress's alone
struct NODE_EGRESS_NAT {
	NODE *Node;                                    // The node
	UINT Tier;                                     // CONTROL_EGRESS_RRAS or CONTROL_EGRESS_WINNAT
	UINT NumIfs;                                   // RRAS: the interfaces that the node configured ...
	NODE_EGRESS_RRAS_IF Ifs[NODE_EGRESS_RRAS_MAX]; // ...
	bool Protocol;                                 // RRAS: the node added the NAT routing protocol to the router
	bool NetNat;                                   // WinNAT: the node created its NAT network ...
	wchar_t Prefix[NODE_EGRESS_PREFIX];            // ... over this internal prefix
	bool Foreign;                                  // WinNAT: a NAT network of another name exists, which the node leaves alone
	DWORD LastError;                               // The error of the last reconcile that failed, which the node log said
};

//
// WinNAT
//

// What the last look of the process at the NAT networks of WinNAT saw (NodeEgressNetNats): 1 when one of another name than the
// node's existed, which the Capabilities take without asking WMI (NodeEgressForeignNetNat)
static volatile LONG node_egress_foreign = 0;

// The calls through a proxy of WMI impersonate the node, as the provider of WinNAT needs: the process sets no default
static HRESULT NodeEgressWmiBlanket(IUnknown *proxy) {
	return CoSetProxyBlanket(proxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
}

// Close the connection to the WMI namespace of WinNAT, and give back the reference to COM that it took
static void NodeEgressWmiClose(NODE_EGRESS_WMI *w) {
	if (w->Services != NULL)
		IWbemServices_Release(w->Services);
	w->Services = NULL;

	if (w->Com)
		CoUninitialize();
	w->Com = false;
}

// Connect to the WMI namespace of WinNAT, with COM initialized for it: S_OK and S_FALSE both take a reference that
// NodeEgressWmiClose gives back, and RPC_E_CHANGED_MODE means that the thread runs in another apartment already, which stays
// as it is
static HRESULT NodeEgressWmiConnect(NODE_EGRESS_WMI *w) {
	IWbemLocator *locator = NULL;

	Zero(w, sizeof(NODE_EGRESS_WMI));

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr))
		w->Com = true;
	else if (hr != RPC_E_CHANGED_MODE)
		return hr;

	hr = CoCreateInstance(&node_egress_clsid_wbem_locator, NULL, CLSCTX_INPROC_SERVER, &node_egress_iid_wbem_locator, (void **)&locator);
	if (SUCCEEDED(hr)) {
		BSTR ns = SysAllocString(NODE_EGRESS_WMI_NAMESPACE);

		hr = (ns != NULL ? IWbemLocator_ConnectServer(locator, ns, NULL, NULL, NULL, 0, NULL, NULL, &w->Services) : E_OUTOFMEMORY);
		SysFreeString(ns);
		IWbemLocator_Release(locator);
	}
	if (SUCCEEDED(hr) && w->Services == NULL)
		hr = E_POINTER;
	if (SUCCEEDED(hr))
		hr = NodeEgressWmiBlanket((IUnknown *)w->Services);

	if (FAILED(hr))
		NodeEgressWmiClose(w);

	return hr;
}

// The string property of the WMI object o into str (size bytes), "" when it has none
static void NodeEgressWmiString(IWbemClassObject *o, const wchar_t *property, wchar_t *str, UINT size) {
	VARIANT v;

	VariantInit(&v);
	str[0] = 0;
	if (SUCCEEDED(IWbemClassObject_Get(o, property, 0, &v, NULL, NULL)) && v.vt == VT_BSTR && v.bstrVal != NULL)
		UniStrCpy(str, size, v.bstrVal);
	VariantClear(&v);
}

// Free what a look at the NAT networks of WinNAT holds
static void NodeEgressNetNatsFree(NODE_EGRESS_NETNATS *nn) {
	if (nn->Path != NULL)
		SysFreeString(nn->Path);
	nn->Path = NULL;
}

// Look at the NAT networks of WinNAT through the namespace svc into nn: the one named name, and how many others exist. The
// caller frees nn with NodeEgressNetNatsFree, whatever the result.
static HRESULT NodeEgressNetNats(IWbemServices *svc, const wchar_t *name, NODE_EGRESS_NETNATS *nn) {
	IEnumWbemClassObject *list = NULL;

	Zero(nn, sizeof(NODE_EGRESS_NETNATS));

	BSTR cls = SysAllocString(NODE_EGRESS_NETNAT_CLASS);
	HRESULT hr = (cls != NULL ? IWbemServices_CreateInstanceEnum(svc, cls, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &list) : E_OUTOFMEMORY);
	SysFreeString(cls);
	if (SUCCEEDED(hr) && list == NULL)
		hr = E_POINTER;
	if (SUCCEEDED(hr))
		hr = NodeEgressWmiBlanket((IUnknown *)list);

	for (UINT i = 0; SUCCEEDED(hr) && i < NODE_EGRESS_NETNAT_MAX; i++) {
		IWbemClassObject *o = NULL;
		ULONG got = 0;
		wchar_t n[MAX_PATH];

		// WBEM_S_FALSE with none returned: the list ends
		hr = IEnumWbemClassObject_Next(list, WBEM_INFINITE, 1, &o, &got);
		if (FAILED(hr) || got == 0 || o == NULL)
			break;

		NodeEgressWmiString(o, L"Name", n, sizeof(n));
		if (UniStrCmpi(n, NODE_EGRESS_NETNAT_NAME) != 0)
			nn->NumForeign++;
		if (nn->Found == false && UniStrCmpi(n, name) == 0) {
			VARIANT path;

			nn->Found = true;
			NodeEgressWmiString(o, L"InternalIPInterfaceAddressPrefix", nn->Prefix, sizeof(nn->Prefix));
			VariantInit(&path);
			if (SUCCEEDED(IWbemClassObject_Get(o, L"__PATH", 0, &path, NULL, NULL)) && path.vt == VT_BSTR && path.bstrVal != NULL)
				nn->Path = SysAllocString(path.bstrVal);
			VariantClear(&path);
		} else {
			nn->NumOthers++;
		}

		IWbemClassObject_Release(o);
	}

	if (list != NULL)
		IEnumWbemClassObject_Release(list);

	// What a look saw, whatever it looked for, is what the Capabilities take next (NodeEgressForeignNetNat)
	if (SUCCEEDED(hr))
		InterlockedExchange(&node_egress_foreign, nn->NumForeign != 0 ? 1 : 0);

	return (FAILED(hr) ? hr : S_OK);
}

// Put the string str into the property of the WMI object o
static HRESULT NodeEgressWmiPut(IWbemClassObject *o, const wchar_t *property, const wchar_t *str) {
	VARIANT v;

	VariantInit(&v);
	v.vt = VT_BSTR;
	v.bstrVal = SysAllocString(str);

	HRESULT hr = (v.bstrVal != NULL ? IWbemClassObject_Put(o, property, 0, &v, 0) : E_OUTOFMEMORY);
	VariantClear(&v);

	return hr;
}

// Create the NAT network of WinNAT name over the internal prefix, through the namespace svc: an instance of MSFT_NetNat, as
// New-NetNat creates it
static HRESULT NodeEgressNetNatCreate(IWbemServices *svc, const wchar_t *name, const wchar_t *prefix) {
	IWbemClassObject *cls = NULL;
	IWbemClassObject *o = NULL;
	BSTR path = SysAllocString(NODE_EGRESS_NETNAT_CLASS);

	HRESULT hr = (path != NULL ? IWbemServices_GetObject(svc, path, 0, NULL, &cls, NULL) : E_OUTOFMEMORY);
	SysFreeString(path);
	if (SUCCEEDED(hr) && cls == NULL)
		hr = E_POINTER;
	if (SUCCEEDED(hr))
		hr = IWbemClassObject_SpawnInstance(cls, 0, &o);
	if (SUCCEEDED(hr) && o == NULL)
		hr = E_POINTER;
	if (SUCCEEDED(hr))
		hr = NodeEgressWmiPut(o, L"Name", name);
	if (SUCCEEDED(hr))
		hr = NodeEgressWmiPut(o, L"InternalIPInterfaceAddressPrefix", prefix);
	if (SUCCEEDED(hr))
		hr = IWbemServices_PutInstance(svc, o, WBEM_FLAG_CREATE_ONLY, NULL, NULL);

	if (o != NULL)
		IWbemClassObject_Release(o);
	if (cls != NULL)
		IWbemClassObject_Release(cls);

	return hr;
}

// Whether a NAT network of WinNAT that is not the node's exists on the host, as the last look of the process at the NAT networks
// saw it (NodeCaps.c): WinNAT allows one per host, and Ranz never touches one of another program (ADR-0025 decision 6). It asks
// WMI nothing, so the Capabilities load nothing of WMI; a process that has not looked counts none. The Egress that serves tier
// 2 looks at each reconcile and falls back to the proxy on one that it finds (NodeEgressNatWinNat).
bool NodeEgressForeignNetNat(void) {
	return (ReadAcquire(&node_egress_foreign) != 0);
}

// Whether the NAT network of WinNAT name exists, with its internal prefix into prefix (size bytes) when it does
bool NodeEgressNetNatPrefix(const wchar_t *name, wchar_t *prefix, UINT size) {
	NODE_EGRESS_WMI w;
	NODE_EGRESS_NETNATS nn;
	bool found = false;

	if (prefix != NULL && size >= sizeof(wchar_t))
		prefix[0] = 0;
	if (name == NULL || FAILED(NodeEgressWmiConnect(&w)))
		return false;

	if (SUCCEEDED(NodeEgressNetNats(w.Services, name, &nn)) && nn.Found) {
		found = true;
		if (prefix != NULL)
			UniStrCpy(prefix, size, nn.Prefix);
	}

	NodeEgressNetNatsFree(&nn);
	NodeEgressWmiClose(&w);

	return found;
}

// Create the NAT network of WinNAT name over the internal prefix, such as "192.168.0.0/24", as New-NetNat does: what a test
// makes of the NAT network of another program
bool NodeEgressNetNatAdd(const wchar_t *name, const wchar_t *prefix) {
	NODE_EGRESS_WMI w;

	if (name == NULL || prefix == NULL || FAILED(NodeEgressWmiConnect(&w)))
		return false;

	HRESULT hr = NodeEgressNetNatCreate(w.Services, name, prefix);
	NodeEgressWmiClose(&w);

	return SUCCEEDED(hr);
}

// Remove the NAT network of WinNAT name, as Remove-NetNat does: true when none of the name is left
bool NodeEgressNetNatRemove(const wchar_t *name) {
	NODE_EGRESS_WMI w;
	NODE_EGRESS_NETNATS nn;
	bool ok = false;

	if (name == NULL || FAILED(NodeEgressWmiConnect(&w)))
		return false;

	if (SUCCEEDED(NodeEgressNetNats(w.Services, name, &nn)))
		ok = (nn.Found == false || (nn.Path != NULL && SUCCEEDED(IWbemServices_DeleteInstance(w.Services, nn.Path, 0, NULL, NULL))));

	NodeEgressNetNatsFree(&nn);
	NodeEgressWmiClose(&w);

	return ok;
}

//
// RRAS
//

// Whether Routing and Remote Access runs on the host as an IPv4 router of LAN interfaces (NodeCaps.c): its service RemoteAccess
// runs, and its router type has LAN routing. The service and the key of its parameters are readable by any account.
bool NodeEgressRrasRouter(void) {
	SERVICE_STATUS status;
	DWORD type = 0;
	DWORD size = sizeof(type);
	bool running = false;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	SC_HANDLE service = (scm != NULL ? OpenServiceW(scm, L"RemoteAccess", SERVICE_QUERY_STATUS) : NULL);

	Zero(&status, sizeof(status));
	if (service != NULL && QueryServiceStatus(service, &status))
		running = (status.dwCurrentState == SERVICE_RUNNING);
	if (service != NULL)
		CloseServiceHandle(service);
	if (scm != NULL)
		CloseServiceHandle(scm);

	if (running == false || RegGetValueW(HKEY_LOCAL_MACHINE, NODE_EGRESS_RRAS_KEY, L"RouterType", RRF_RT_REG_DWORD, NULL, &type, &size) != ERROR_SUCCESS)
		return false;

	return ((type & (NODE_EGRESS_ROUTER_LAN | NODE_EGRESS_ROUTER_WAN)) != 0);
}

// Disconnect from the router and free mprapi.dll
static void NodeEgressMprDisconnect(NODE_EGRESS_MPR *m) {
	if (m->Admin != NULL)
		m->AdminDisconnect(m->Admin);
	if (m->Config != NULL)
		m->ConfigDisconnect(m->Config);
	if (m->Module != NULL)
		FreeLibrary(m->Module);

	Zero(m, sizeof(NODE_EGRESS_MPR));
}

// The function name of mprapi.dll of m; *missing becomes true when the library lacks it
static void *NodeEgressMprProc(NODE_EGRESS_MPR *m, const char *name, bool *missing) {
	void *proc = (void *)GetProcAddress(m->Module, name);

	if (proc == NULL)
		*missing = true;

	return proc;
}

// Load mprapi.dll into m with the functions that the NAT of RRAS uses, and connect to the configuration of the router and to
// the running router: NO_ERROR, or the error of Windows when one of them cannot be had
static DWORD NodeEgressMprConnect(NODE_EGRESS_MPR *m) {
	bool missing = false;

	Zero(m, sizeof(NODE_EGRESS_MPR));

	m->Module = LoadLibraryExW(L"mprapi.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (m->Module == NULL)
		return GetLastError();

	m->ConfigConnect = (NODE_EGRESS_MPR_CONNECT_FUNC *)NodeEgressMprProc(m, "MprConfigServerConnect", &missing);
	m->ConfigDisconnect = (NODE_EGRESS_MPR_DISCONNECT_FUNC *)NodeEgressMprProc(m, "MprConfigServerDisconnect", &missing);
	m->ConfigFree = (NODE_EGRESS_MPR_FREE_FUNC *)NodeEgressMprProc(m, "MprConfigBufferFree", &missing);
	m->ConfigTransport = (NODE_EGRESS_MPR_TRANSPORT_FUNC *)NodeEgressMprProc(m, "MprConfigTransportGetHandle", &missing);
	m->ConfigGet = (NODE_EGRESS_MPR_CONFIG_GET_FUNC *)NodeEgressMprProc(m, "MprConfigTransportGetInfo", &missing);
	m->ConfigSet = (NODE_EGRESS_MPR_CONFIG_SET_FUNC *)NodeEgressMprProc(m, "MprConfigTransportSetInfo", &missing);
	m->ConfigIf = (NODE_EGRESS_MPR_CONFIG_IF_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceGetHandle", &missing);
	m->ConfigIfTransport = (NODE_EGRESS_MPR_CONFIG_IF_TRANSPORT_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceTransportGetHandle", &missing);
	m->ConfigIfGet = (NODE_EGRESS_MPR_CONFIG_IF_GET_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceTransportGetInfo", &missing);
	m->ConfigIfSet = (NODE_EGRESS_MPR_CONFIG_IF_SET_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceTransportSetInfo", &missing);
	m->ConfigIfCreate = (NODE_EGRESS_MPR_IF_CREATE_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceCreate", &missing);
	m->ConfigIfDelete = (NODE_EGRESS_MPR_IF_DELETE_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceDelete", &missing);
	m->ConfigIfAdd = (NODE_EGRESS_MPR_CONFIG_IF_ADD_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceTransportAdd", &missing);
	m->ConfigIfRemove = (NODE_EGRESS_MPR_CONFIG_IF_REMOVE_FUNC *)NodeEgressMprProc(m, "MprConfigInterfaceTransportRemove", &missing);
	m->AdminConnect = (NODE_EGRESS_MPR_CONNECT_FUNC *)NodeEgressMprProc(m, "MprAdminServerConnect", &missing);
	m->AdminDisconnect = (NODE_EGRESS_MPR_DISCONNECT_FUNC *)NodeEgressMprProc(m, "MprAdminServerDisconnect", &missing);
	m->AdminFree = (NODE_EGRESS_MPR_FREE_FUNC *)NodeEgressMprProc(m, "MprAdminBufferFree", &missing);
	m->AdminGet = (NODE_EGRESS_MPR_ADMIN_GET_FUNC *)NodeEgressMprProc(m, "MprAdminTransportGetInfo", &missing);
	m->AdminSet = (NODE_EGRESS_MPR_ADMIN_SET_FUNC *)NodeEgressMprProc(m, "MprAdminTransportSetInfo", &missing);
	m->AdminIf = (NODE_EGRESS_MPR_ADMIN_IF_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceGetHandle", &missing);
	m->AdminIfGet = (NODE_EGRESS_MPR_ADMIN_IF_GET_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceTransportGetInfo", &missing);
	m->AdminIfSet = (NODE_EGRESS_MPR_ADMIN_IF_SET_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceTransportSetInfo", &missing);
	m->AdminIfCreate = (NODE_EGRESS_MPR_IF_CREATE_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceCreate", &missing);
	m->AdminIfDelete = (NODE_EGRESS_MPR_IF_DELETE_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceDelete", &missing);
	m->AdminIfAdd = (NODE_EGRESS_MPR_ADMIN_IF_ADD_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceTransportAdd", &missing);
	m->AdminIfRemove = (NODE_EGRESS_MPR_ADMIN_IF_REMOVE_FUNC *)NodeEgressMprProc(m, "MprAdminInterfaceTransportRemove", &missing);
	m->InfoCreate = (NODE_EGRESS_MPR_CREATE_FUNC *)NodeEgressMprProc(m, "MprInfoCreate", &missing);
	m->InfoDuplicate = (NODE_EGRESS_MPR_DUPLICATE_FUNC *)NodeEgressMprProc(m, "MprInfoDuplicate", &missing);
	m->BlockFind = (NODE_EGRESS_MPR_FIND_FUNC *)NodeEgressMprProc(m, "MprInfoBlockFind", &missing);
	m->BlockAdd = (NODE_EGRESS_MPR_ADD_FUNC *)NodeEgressMprProc(m, "MprInfoBlockAdd", &missing);
	m->BlockSet = (NODE_EGRESS_MPR_ADD_FUNC *)NodeEgressMprProc(m, "MprInfoBlockSet", &missing);
	m->BlockRemove = (NODE_EGRESS_MPR_REMOVE_FUNC *)NodeEgressMprProc(m, "MprInfoBlockRemove", &missing);
	m->BlockSize = (NODE_EGRESS_MPR_SIZE_FUNC *)NodeEgressMprProc(m, "MprInfoBlockQuerySize", &missing);
	m->InfoDelete = (NODE_EGRESS_MPR_FREE_FUNC *)NodeEgressMprProc(m, "MprInfoDelete", &missing);

	if (missing) {
		NodeEgressMprDisconnect(m);
		return ERROR_PROC_NOT_FOUND;
	}

	DWORD err = m->ConfigConnect(NULL, &m->Config);
	if (err == NO_ERROR)
		err = m->AdminConnect(NULL, &m->Admin);
	if (err != NO_ERROR)
		NodeEgressMprDisconnect(m);

	return err;
}

// The NAT routing protocol in the global IPv4 information info of the router: a new information with it into *next
// (MprInfoDelete), NULL when info holds it already. An empty NAT block, which tells the running router to take the protocol
// out (NodeEgressRrasEmpty), holds no protocol.
static DWORD NodeEgressRrasGlobalBlock(NODE_EGRESS_MPR *m, LPBYTE info, LPVOID *next) {
	NODE_EGRESS_NAT_GLOBAL g;
	DWORD item = 0;
	DWORD count = 0;
	LPBYTE data = NULL;

	*next = NULL;
	DWORD found = m->BlockFind(info, NODE_EGRESS_MS_IP_NAT, &item, &count, &data);
	if (found == NO_ERROR && item != 0 && count != 0)
		return NO_ERROR;

	Zero(&g, sizeof(g));
	g.LoggingLevel = NODE_EGRESS_NAT_LOGGING;
	g.Header.Version = RTR_INFO_BLOCK_VERSION;
	g.Header.Size = FIELD_OFFSET(RTR_INFO_BLOCK_HEADER, TocEntry);

	if (found == NO_ERROR)
		return m->BlockSet(info, NODE_EGRESS_MS_IP_NAT, sizeof(g), 1, (LPBYTE)&g, next);

	return m->BlockAdd(info, NODE_EGRESS_MS_IP_NAT, sizeof(g), 1, (LPBYTE)&g, next);
}

// A new IPv4 information from info, which holds the NAT block, without the NAT information into *next (MprInfoDelete), for the
// running router (config false) or for the configuration of the router (config true). The configuration of the router holds the
// whole information, from which the block goes. A running router keeps the information of a block that an information leaves
// out, and an empty block tells a router manager of RRAS to delete the information of its type: the entry of the block in the
// table of contents with a size and a count of 0, which the node writes into a copy of info. In the egress (RRAS NAT) job the
// running router kept the NAT information of an interface that it got without the NAT block, and with the block of
// MprInfoBlockSet of no item alike, so what it holds after the empty block is read back (NodeEgressRrasDrop,
// NodeEgressRrasProtocolDrop).
static DWORD NodeEgressRrasEmpty(NODE_EGRESS_MPR *m, LPBYTE info, bool config, LPVOID *next) {
	if (config)
		return m->BlockRemove(info, NODE_EGRESS_MS_IP_NAT, next);

	*next = NULL;
	DWORD err = m->InfoDuplicate(info, next);
	if (err != NO_ERROR) {
		*next = NULL;
		return err;
	}

	// The entries of the table of contents of the copy that its size holds
	RTR_INFO_BLOCK_HEADER *h = (RTR_INFO_BLOCK_HEADER *)*next;
	LPBYTE toc = (LPBYTE)*next + FIELD_OFFSET(RTR_INFO_BLOCK_HEADER, TocEntry);
	for (ULONG i = 0; i < h->TocEntriesCount && FIELD_OFFSET(RTR_INFO_BLOCK_HEADER, TocEntry) + (i + 1) * sizeof(RTR_TOC_ENTRY) <= h->Size; i++) {
		RTR_TOC_ENTRY *e = (RTR_TOC_ENTRY *)(toc + i * sizeof(RTR_TOC_ENTRY));

		if (e->InfoType == NODE_EGRESS_MS_IP_NAT) {
			e->InfoSize = 0;
			e->Count = 0;
		}
	}

	return NO_ERROR;
}

// Whether the global IPv4 information of the running router holds the NAT routing protocol: a NAT block of an item at least
static bool NodeEgressRrasProtocolIn(NODE_EGRESS_MPR *m) {
	LPBYTE info = NULL;
	DWORD size = 0;
	DWORD item = 0;
	DWORD count = 0;
	LPBYTE data = NULL;
	bool held = false;

	if (m->AdminGet(m->Admin, NODE_EGRESS_PID_IP, &info, &size, NULL, NULL) == NO_ERROR && info != NULL)
		held = (m->BlockFind(info, NODE_EGRESS_MS_IP_NAT, &item, &count, &data) == NO_ERROR && item != 0 && count != 0);
	if (info != NULL)
		m->AdminFree(info);

	return held;
}

// The NAT routing protocol in the IPv4 router of RRAS, running and configured: added where it lacks it, so the router has it
// again after a restart. *added says whether the running router lacked it. The error of the running router.
static DWORD NodeEgressRrasProtocol(NODE_EGRESS_MPR *m, bool *added) {
	LPBYTE info = NULL;
	DWORD size = 0;
	LPVOID next = NULL;
	HANDLE transport = NULL;

	*added = false;
	DWORD err = m->AdminGet(m->Admin, NODE_EGRESS_PID_IP, &info, &size, NULL, NULL);
	if (err == NO_ERROR)
		err = NodeEgressRrasGlobalBlock(m, info, &next);
	if (err == NO_ERROR && next != NULL) {
		err = m->AdminSet(m->Admin, NODE_EGRESS_PID_IP, (LPBYTE)next, m->BlockSize(next), NULL, 0);
		*added = (err == NO_ERROR);
		m->InfoDelete(next);
	}
	if (info != NULL)
		m->AdminFree(info);

	info = NULL;
	next = NULL;
	if (m->ConfigTransport(m->Config, NODE_EGRESS_PID_IP, &transport) == NO_ERROR && m->ConfigGet(m->Config, transport, &info, &size, NULL, NULL, NULL) == NO_ERROR &&
	    NodeEgressRrasGlobalBlock(m, info, &next) == NO_ERROR && next != NULL) {
		m->ConfigSet(m->Config, transport, (LPBYTE)next, m->BlockSize(next), NULL, 0, NULL);
		m->InfoDelete(next);
	}
	if (info != NULL)
		m->ConfigFree(info);

	return err;
}

// Take the NAT routing protocol out of the IPv4 router of RRAS, running and configured: the node added it. The running router
// gets the global information with an empty NAT block (NodeEgressRrasEmpty) and, where it holds the protocol still, the
// information without the block. Whether the running router holds the protocol no more.
static bool NodeEgressRrasProtocolDrop(NODE_EGRESS_MPR *m) {
	LPBYTE info = NULL;
	DWORD size = 0;
	LPVOID next = NULL;
	HANDLE transport = NULL;
	bool gone = (NodeEgressRrasProtocolIn(m) == false);

	for (UINT i = 0; i < 2 && gone == false; i++) {
		info = NULL;
		next = NULL;
		if (m->AdminGet(m->Admin, NODE_EGRESS_PID_IP, &info, &size, NULL, NULL) == NO_ERROR &&
		    (i == 0 ? NodeEgressRrasEmpty(m, info, false, &next) : m->BlockRemove(info, NODE_EGRESS_MS_IP_NAT, &next)) == NO_ERROR && next != NULL) {
			m->AdminSet(m->Admin, NODE_EGRESS_PID_IP, (LPBYTE)next, m->BlockSize(next), NULL, 0);
			m->InfoDelete(next);
		}
		if (info != NULL)
			m->AdminFree(info);
		gone = (NodeEgressRrasProtocolIn(m) == false);
	}

	info = NULL;
	next = NULL;
	if (m->ConfigTransport(m->Config, NODE_EGRESS_PID_IP, &transport) == NO_ERROR && m->ConfigGet(m->Config, transport, &info, &size, NULL, NULL, NULL) == NO_ERROR &&
	    NodeEgressRrasEmpty(m, info, true, &next) == NO_ERROR && next != NULL) {
		m->ConfigSet(m->Config, transport, (LPBYTE)next, m->BlockSize(next), NULL, 0, NULL);
		m->InfoDelete(next);
	}
	if (info != NULL)
		m->ConfigFree(info);

	return gone;
}

// The name of the interface of luid in RRAS into name (size bytes): the GUID of its adapter in braces
static bool NodeEgressRrasName(UINT64 luid, wchar_t *name, UINT size) {
	NET_LUID l;
	GUID guid;

	l.Value = luid;
	if (ConvertInterfaceLuidToGuid(&l, &guid) != NO_ERROR)
		return false;

	return (StringFromGUID2(&guid, name, (int)(size / sizeof(wchar_t))) != 0);
}

// Whether err of the router says that it lacks the interface, or the IPv4 transport of the interface, that it was asked for
static bool NodeEgressRrasLacks(DWORD err) {
	return (err == NODE_EGRESS_MPR_NO_INTERFACE || err == NODE_EGRESS_MPR_NO_PROTOCOL || err == ERROR_NOT_FOUND || err == ERROR_FILE_NOT_FOUND);
}

// The IPv4 information of the interface named name in the running router (config false) or in the configuration of the
// router (config true) into f, which NodeEgressRrasDone frees whatever the result. Without it, f->Lacks says whether the
// router lacks the interface or its IPv4 transport, as it lacks those of an adapter that came after it started.
static DWORD NodeEgressRrasGet(NODE_EGRESS_MPR *m, wchar_t *name, bool config, NODE_EGRESS_RRAS_INFO *f) {
	Zero(f, sizeof(NODE_EGRESS_RRAS_INFO));
	f->Config = config;

	DWORD err = (config ? m->ConfigIf(m->Config, name, &f->Interface) : m->AdminIf(m->Admin, name, &f->Interface, FALSE));
	if (err != NO_ERROR) {
		f->Interface = NULL;
		if (NodeEgressRrasLacks(err))
			f->Lacks = NODE_EGRESS_MADE_INTERFACE;
		return err;
	}

	if (config) {
		err = m->ConfigIfTransport(m->Config, f->Interface, NODE_EGRESS_PID_IP, &f->Transport);
		if (err == NO_ERROR)
			err = m->ConfigIfGet(m->Config, f->Interface, f->Transport, &f->Info, &f->Size);
		else if (NodeEgressRrasLacks(err))
			f->Lacks = NODE_EGRESS_MADE_TRANSPORT;
	} else {
		err = m->AdminIfGet(m->Admin, f->Interface, NODE_EGRESS_PID_IP, &f->Info, &f->Size);
		if (NodeEgressRrasLacks(err))
			f->Lacks = NODE_EGRESS_MADE_TRANSPORT;
	}

	if (err == NO_ERROR && f->Info == NULL)
		err = ERROR_NOT_FOUND;

	return err;
}

// Give the interface of f the IPv4 information info, where f was taken from
static DWORD NodeEgressRrasPut(NODE_EGRESS_MPR *m, const NODE_EGRESS_RRAS_INFO *f, LPVOID info) {
	DWORD size = m->BlockSize(info);

	if (f->Config)
		return m->ConfigIfSet(m->Config, f->Interface, f->Transport, (LPBYTE)info, size);

	return m->AdminIfSet(m->Admin, f->Interface, NODE_EGRESS_PID_IP, (LPBYTE)info, size);
}

// Free the IPv4 information of f
static void NodeEgressRrasDone(NODE_EGRESS_MPR *m, NODE_EGRESS_RRAS_INFO *f) {
	if (f->Info != NULL) {
		if (f->Config)
			m->ConfigFree(f->Info);
		else
			m->AdminFree(f->Info);
	}

	f->Info = NULL;
}

// The NAT flags of the IPv4 information info into *flags: false when it holds no NAT information
static bool NodeEgressRrasHolds(NODE_EGRESS_MPR *m, LPBYTE info, UINT *flags) {
	DWORD item = 0;
	DWORD count = 0;
	LPBYTE data = NULL;

	if (m->BlockFind(info, NODE_EGRESS_MS_IP_NAT, &item, &count, &data) != NO_ERROR || data == NULL || count == 0 || item < 2 * sizeof(ULONG))
		return false;

	*flags = ((const NODE_EGRESS_NAT_INTERFACE *)data)->Flags;

	return true;
}

// The NAT flags of the interface named name in the running router into *flags: false when the router holds no NAT information
// for it, or cannot be asked
static bool NodeEgressRrasNat(NODE_EGRESS_MPR *m, wchar_t *name, UINT *flags) {
	NODE_EGRESS_RRAS_INFO f;
	bool held = (NodeEgressRrasGet(m, name, false, &f) == NO_ERROR && NodeEgressRrasHolds(m, f.Info, flags));

	NodeEgressRrasDone(m, &f);

	return held;
}

// A new IPv4 information of the interface of luid whose NAT information holds flags, from its information info into *next
// (MprInfoDelete): NULL when info holds them already
static DWORD NodeEgressRrasBlock(NODE_EGRESS_MPR *m, LPBYTE info, UINT64 luid, UINT flags, LPVOID *next) {
	NODE_EGRESS_NAT_INTERFACE n;
	NET_LUID l;
	NET_IFINDEX index = 0;
	DWORD item = 0;
	DWORD count = 0;
	LPBYTE data = NULL;
	UINT held = 0;

	*next = NULL;
	if (NodeEgressRrasHolds(m, info, &held) && held == flags)
		return NO_ERROR;

	l.Value = luid;
	ConvertInterfaceLuidToIndex(&l, &index);

	Zero(&n, sizeof(n));
	n.Index = index;
	n.Flags = flags;
	n.Header.Version = RTR_INFO_BLOCK_VERSION;
	n.Header.Size = FIELD_OFFSET(RTR_INFO_BLOCK_HEADER, TocEntry);

	if (m->BlockFind(info, NODE_EGRESS_MS_IP_NAT, &item, &count, &data) == NO_ERROR)
		return m->BlockSet(info, NODE_EGRESS_MS_IP_NAT, sizeof(n), 1, (LPBYTE)&n, next);

	return m->BlockAdd(info, NODE_EGRESS_MS_IP_NAT, sizeof(n), 1, (LPBYTE)&n, next);
}

// Add what the router of f lacks for the interface named name, of luid: the interface of a LAN adapter with its IPv4 transport,
// or the transport alone, whose IPv4 information holds the interface up and its NAT flags, as netsh routing ip add interface
// and netsh routing ip nat add interface give it. *made takes what the node added (NODE_EGRESS_MADE_*).
static DWORD NodeEgressRrasMake(NODE_EGRESS_MPR *m, wchar_t *name, NODE_EGRESS_RRAS_INFO *f, UINT64 luid, UINT flags, UINT *made) {
	NODE_EGRESS_MPR_INTERFACE iface;
	ULONG status = NODE_EGRESS_ADMIN_UP;
	LPVOID empty = NULL;
	LPVOID up = NULL;
	LPVOID info = NULL;
	DWORD err;

	if (f->Lacks == NODE_EGRESS_MADE_INTERFACE) {
		Zero(&iface, sizeof(iface));
		UniStrCpy(iface.Name, sizeof(iface.Name), name);
		iface.Enabled = TRUE;
		iface.Type = NODE_EGRESS_IF_DEDICATED;

		err = (f->Config ? m->ConfigIfCreate(m->Config, 0, (LPBYTE)&iface, &f->Interface) : m->AdminIfCreate(m->Admin, 0, (LPBYTE)&iface, &f->Interface));
		if (err != NO_ERROR) {
			f->Interface = NULL;
			return err;
		}
		*made |= NODE_EGRESS_MADE_INTERFACE;
	}

	err = m->InfoCreate(RTR_INFO_BLOCK_VERSION, &empty);
	if (err == NO_ERROR)
		err = m->BlockAdd(empty, NODE_EGRESS_IP_STATUS, sizeof(status), 1, (LPBYTE)&status, &up);
	if (err == NO_ERROR)
		err = NodeEgressRrasBlock(m, (LPBYTE)up, luid, flags, &info);
	if (err == NO_ERROR && info == NULL)
		err = ERROR_INVALID_DATA;
	if (err == NO_ERROR) {
		DWORD size = m->BlockSize(info);

		if (f->Config)
			err = m->ConfigIfAdd(m->Config, f->Interface, NODE_EGRESS_PID_IP, NULL, (LPBYTE)info, size, &f->Transport);
		else
			err = m->AdminIfAdd(m->Admin, f->Interface, NODE_EGRESS_PID_IP, (LPBYTE)info, size);
	}
	if (err == NO_ERROR)
		*made |= NODE_EGRESS_MADE_TRANSPORT;

	if (info != NULL)
		m->InfoDelete(info);
	if (up != NULL)
		m->InfoDelete(up);
	if (empty != NULL)
		m->InfoDelete(empty);

	return err;
}

// Make the NAT information of the interface named name, of luid, hold flags in the running router and in the configuration of
// the router. Where a router lacks the interface or its IPv4 transport, as it lacks those of an adapter that came after it
// started, the node adds them (NodeEgressRrasMake), and made takes what it added to each, the running router [0] and the
// configuration [1], which NodeEgressRrasDrop takes out again. *changed says whether the running router held other
// information. The error of the running router; the configuration keeps the setting where it can.
static DWORD NodeEgressRrasSet(NODE_EGRESS_MPR *m, wchar_t *name, UINT64 luid, UINT flags, UINT *made, bool *changed) {
	DWORD ret = NO_ERROR;

	*changed = false;
	if (name[0] == 0)
		return ERROR_NOT_FOUND;

	for (UINT i = 0; i < 2; i++) {
		NODE_EGRESS_RRAS_INFO f;
		LPVOID next = NULL;
		DWORD err = NodeEgressRrasGet(m, name, i == 1, &f);

		if (err == NO_ERROR) {
			err = NodeEgressRrasBlock(m, f.Info, luid, flags, &next);
			if (err == NO_ERROR && next != NULL) {
				err = NodeEgressRrasPut(m, &f, next);
				if (err == NO_ERROR && i == 0)
					*changed = true;
				m->InfoDelete(next);
			}
		} else if (f.Lacks != 0) {
			err = NodeEgressRrasMake(m, name, &f, luid, flags, &made[i]);
			if (err == NO_ERROR && i == 0)
				*changed = true;
		}
		NodeEgressRrasDone(m, &f);

		if (i == 0)
			ret = err;
	}

	return ret;
}

// Take what the node set for the interface named name out of the running router and of the configuration of the router: the
// interface where the node added it, else its IPv4 transport where the node added that, else its NAT information. made says
// what the node added to the running router [0] and to the configuration [1] (NODE_EGRESS_MADE_*), NULL for nothing. The
// error of the running router, NO_ERROR when it holds nothing of the node, NODE_EGRESS_RRAS_KEPT when it kept the NAT
// information after the empty NAT block (NodeEgressRrasEmpty).
static DWORD NodeEgressRrasDrop(NODE_EGRESS_MPR *m, wchar_t *name, const UINT *made) {
	DWORD ret = NO_ERROR;

	if (name[0] == 0)
		return ERROR_NOT_FOUND;

	for (UINT i = 0; i < 2; i++) {
		NODE_EGRESS_RRAS_INFO f;
		LPVOID next = NULL;
		UINT held = 0;
		UINT added = (made != NULL ? made[i] : 0);
		DWORD err = NodeEgressRrasGet(m, name, i == 1, &f);

		if (f.Lacks == NODE_EGRESS_MADE_INTERFACE) {
			err = NO_ERROR;
		} else if (f.Interface != NULL && (added & NODE_EGRESS_MADE_INTERFACE) != 0) {
			err = (f.Config ? m->ConfigIfDelete(m->Config, f.Interface) : m->AdminIfDelete(m->Admin, f.Interface));
		} else if (f.Lacks == NODE_EGRESS_MADE_TRANSPORT) {
			err = NO_ERROR;
		} else if (err == NO_ERROR && (added & NODE_EGRESS_MADE_TRANSPORT) != 0) {
			err = (f.Config ? m->ConfigIfRemove(m->Config, f.Interface, f.Transport) : m->AdminIfRemove(m->Admin, f.Interface, NODE_EGRESS_PID_IP));
		} else if (err == NO_ERROR && NodeEgressRrasHolds(m, f.Info, &held)) {
			err = NodeEgressRrasEmpty(m, f.Info, f.Config, &next);
			if (err == NO_ERROR && next != NULL) {
				err = NodeEgressRrasPut(m, &f, next);
				m->InfoDelete(next);
			}
			// What the running router holds after the empty block
			if (err == NO_ERROR && f.Config == false && NodeEgressRrasNat(m, name, &held))
				err = NODE_EGRESS_RRAS_KEPT;
		}
		NodeEgressRrasDone(m, &f);

		if (i == 0)
			ret = err;
	}

	return ret;
}

// Take the NAT information of the interface named name out of the running router that kept it after an empty NAT block
// (NodeEgressRrasDrop): the IPv4 transport of the interface goes and comes back with the information that it held, without the
// NAT block. The error of the running router, NODE_EGRESS_RRAS_KEPT when it holds the NAT information still.
static DWORD NodeEgressRrasAnew(NODE_EGRESS_MPR *m, wchar_t *name) {
	NODE_EGRESS_RRAS_INFO f;
	LPVOID next = NULL;
	UINT held = 0;

	DWORD err = NodeEgressRrasGet(m, name, false, &f);
	if (err == NO_ERROR)
		err = m->BlockRemove(f.Info, NODE_EGRESS_MS_IP_NAT, &next);
	if (err == NO_ERROR && next == NULL)
		err = ERROR_INVALID_DATA;
	if (err == NO_ERROR)
		err = m->AdminIfRemove(m->Admin, f.Interface, NODE_EGRESS_PID_IP);
	if (err == NO_ERROR)
		err = m->AdminIfAdd(m->Admin, f.Interface, NODE_EGRESS_PID_IP, (LPBYTE)next, m->BlockSize(next));
	if (next != NULL)
		m->InfoDelete(next);
	NodeEgressRrasDone(m, &f);

	if (err == NO_ERROR && NodeEgressRrasNat(m, name, &held))
		err = NODE_EGRESS_RRAS_KEPT;

	return err;
}

// The NAT flags of the interface of luid in the running router of RRAS into *flags: false when the router holds no NAT
// information for it, or cannot be asked
bool NodeEgressRrasFlags(UINT64 luid, UINT *flags) {
	NODE_EGRESS_MPR m;
	wchar_t name[NODE_EGRESS_RRAS_NAME];
	UINT held = 0;

	if (flags != NULL)
		*flags = 0;
	if (NodeEgressRrasName(luid, name, sizeof(name)) == false || NodeEgressMprConnect(&m) != NO_ERROR)
		return false;

	bool ok = NodeEgressRrasNat(&m, name, &held);
	NodeEgressMprDisconnect(&m);
	if (ok && flags != NULL)
		*flags = held;

	return ok;
}

// Whether the IPv4 router of RRAS that runs holds the NAT routing protocol: false when it does not, or cannot be asked
bool NodeEgressRrasProtocolHeld(void) {
	NODE_EGRESS_MPR m;

	if (NodeEgressMprConnect(&m) != NO_ERROR)
		return false;

	bool held = NodeEgressRrasProtocolIn(&m);
	NodeEgressMprDisconnect(&m);

	return held;
}

// Take the NAT information of the interface of luid out of the running router of RRAS and of its configuration, as an
// operator's netsh routing ip nat delete interface or a reset of RRAS does: what a test takes away for the reconcile of the
// node to set again. The running router gets the empty NAT block with which the node takes out what it set (NodeEgressRrasDrop)
// and, where it keeps the information after that, the IPv4 transport of the interface anew without it (NodeEgressRrasAnew).
// *how (NULL for none) says which of the two took it out (NODE_EGRESS_TAKEN_*). False when the running router held none, or
// holds it still.
bool NodeEgressRrasRemove(UINT64 luid, UINT *how) {
	NODE_EGRESS_MPR m;
	wchar_t name[NODE_EGRESS_RRAS_NAME];
	UINT held = 0;
	UINT taken = NODE_EGRESS_TAKEN_EMPTY;

	if (how != NULL)
		*how = 0;
	if (NodeEgressRrasName(luid, name, sizeof(name)) == false || NodeEgressMprConnect(&m) != NO_ERROR)
		return false;

	DWORD err = (NodeEgressRrasNat(&m, name, &held) ? NodeEgressRrasDrop(&m, name, NULL) : ERROR_NOT_FOUND);
	if (err == NODE_EGRESS_RRAS_KEPT) {
		taken = NODE_EGRESS_TAKEN_TRANSPORT;
		err = NodeEgressRrasAnew(&m, name);
	}
	NodeEgressMprDisconnect(&m);

	if (err == NO_ERROR && how != NULL)
		*how = taken;

	return (err == NO_ERROR);
}

//
// The NAT of the Egress
//

// Write a failure of the NAT of Windows to the node log, once for each error in a row: a reconcile that fails again with the
// same error says nothing new
static void NodeEgressNatError(NODE_EGRESS_NAT *nat, const char *what, DWORD err) {
	if (err == nat->LastError)
		return;

	nat->LastError = err;
	NodeLog(nat->Node, "Egress: %s (error 0x%x)", what, (UINT)err);
}

// What the node configures in the NAT of Windows for the tier, empty until the first reconcile
NODE_EGRESS_NAT *NodeEgressNatNew(NODE *n, UINT tier) {
	NODE_EGRESS_NAT *nat = ZeroMalloc(sizeof(NODE_EGRESS_NAT));

	nat->Node = n;
	nat->Tier = tier;

	return nat;
}

// Tier 1: the NAT of RRAS as want says, the NAT routing protocol, each adapter of a VRF a private interface and each interface
// that carries the egress a public one, with the interface or its IPv4 transport added where the router lacks them; an
// interface that the node configured before and that want leaves out loses what the node set. True when the running router
// holds all of it; *restored counts the interfaces that held it once and had lost it.
static bool NodeEgressNatRras(NODE_EGRESS_NAT *nat, const NODE_EGRESS_NAT_WANT *want, UINT *restored) {
	NODE_EGRESS_MPR m;
	NODE_EGRESS_RRAS_IF next[NODE_EGRESS_RRAS_MAX];
	char what[MAX_SIZE];
	UINT num = 0;
	bool added = false;

	DWORD err = NodeEgressMprConnect(&m);
	if (err != NO_ERROR) {
		NodeEgressNatError(nat, "Routing and Remote Access cannot be configured", err);
		return false;
	}

	err = NodeEgressRrasProtocol(&m, &added);
	if (added) {
		nat->Protocol = true;
		NodeLog(nat->Node, "Egress: the NAT routing protocol added to the IPv4 router of Routing and Remote Access");
	}
	bool ok = (err == NO_ERROR);
	if (ok == false)
		NodeEgressNatError(nat, "the NAT routing protocol cannot be added to the IPv4 router of Routing and Remote Access", err);

	// What want holds: the private interfaces, then the public ones
	Zero(next, sizeof(next));
	for (UINT i = 0; i < want->NumPrivate && i < NODE_EGRESS_MAX_PRIVATE && num < NODE_EGRESS_RRAS_MAX; i++) {
		next[num].Luid = want->Private[i];
		next[num].Flags = 0;
		num++;
	}
	for (UINT i = 0; i < want->NumPublic && i < NODE_EGRESS_MAX_UPLINKS && num < NODE_EGRESS_RRAS_MAX; i++) {
		next[num].Luid = want->Public[i];
		next[num].Flags = NODE_EGRESS_RRAS_PUBLIC;
		num++;
	}

	// Each with its name in RRAS, and what the node added for it before
	for (UINT i = 0; i < num; i++) {
		NodeEgressRrasName(next[i].Luid, next[i].Name, sizeof(next[i].Name));
		for (UINT j = 0; j < nat->NumIfs; j++) {
			if (nat->Ifs[j].Luid != next[i].Luid)
				continue;
			Copy(next[i].Made, nat->Ifs[j].Made, sizeof(next[i].Made));
			if (next[i].Name[0] == 0)
				UniStrCpy(next[i].Name, sizeof(next[i].Name), nat->Ifs[j].Name);
		}
	}

	// An interface that the node configured and that want leaves out
	for (UINT i = 0; i < nat->NumIfs; i++) {
		NODE_EGRESS_RRAS_IF *r = &nat->Ifs[i];
		bool kept = false;

		for (UINT j = 0; j < num && kept == false; j++)
			kept = (next[j].Luid == r->Luid);
		if (kept == false && (r->Done || r->Made[0] != 0 || r->Made[1] != 0)) {
			err = NodeEgressRrasDrop(&m, r->Name, r->Made);
			if (err != NO_ERROR)
				NodeLog(nat->Node, "Egress: what the node set in Routing and Remote Access for an interface that carries no egress any more could not be taken out (error 0x%x)", (UINT)err);
		}
	}

	// Each interface of want
	for (UINT i = 0; ok && i < num; i++) {
		NET_LUID l;
		NET_IFINDEX index = 0;
		bool changed = false;
		bool before = false;
		UINT made = next[i].Made[0];

		for (UINT j = 0; j < nat->NumIfs && before == false; j++)
			before = (nat->Ifs[j].Luid == next[i].Luid && nat->Ifs[j].Flags == next[i].Flags && nat->Ifs[j].Done);

		l.Value = next[i].Luid;
		ConvertInterfaceLuidToIndex(&l, &index);

		err = NodeEgressRrasSet(&m, next[i].Name, next[i].Luid, next[i].Flags, next[i].Made, &changed);
		next[i].Done = (err == NO_ERROR);
		if ((next[i].Made[0] & ~made & NODE_EGRESS_MADE_INTERFACE) != 0)
			NodeLog(nat->Node, "Egress: Routing and Remote Access had no interface %u, an adapter that came after the router started: the node added it to the router", (UINT)index);
		else if ((next[i].Made[0] & ~made & NODE_EGRESS_MADE_TRANSPORT) != 0)
			NodeLog(nat->Node, "Egress: interface %u of Routing and Remote Access had no IPv4 transport: the node added it", (UINT)index);

		if (err != NO_ERROR) {
			ok = false;
			Format(what, sizeof(what), "interface %u cannot be made a %s interface of the NAT of Routing and Remote Access", (UINT)index,
			       next[i].Flags != 0 ? "public" : "private");
			NodeEgressNatError(nat, what, err);
		} else if (changed && before) {
			(*restored)++;
			NodeLog(nat->Node, "Egress: the NAT of Routing and Remote Access had lost interface %u as a %s interface: the node set it again", (UINT)index,
			        next[i].Flags != 0 ? "public" : "private");
		} else if (changed) {
			NodeLog(nat->Node, "Egress: interface %u is a %s interface of the NAT of Routing and Remote Access", (UINT)index, next[i].Flags != 0 ? "public" : "private");
		}
	}

	// An interface that the loop did not reach keeps what the node knew of it
	for (UINT i = 0; i < num; i++) {
		for (UINT j = 0; ok == false && next[i].Done == false && j < nat->NumIfs; j++)
			if (nat->Ifs[j].Luid == next[i].Luid && nat->Ifs[j].Flags == next[i].Flags)
				next[i].Done = nat->Ifs[j].Done;
	}

	Copy(nat->Ifs, next, sizeof(NODE_EGRESS_RRAS_IF) * num);
	nat->NumIfs = num;
	NodeEgressMprDisconnect(&m);

	return ok;
}

// Tier 2: the NAT network of WinNAT of the node over the supernet of want, none while want holds none. A NAT network of another
// name stops it, which the node never touches (NodeEgressNatForeign). True when the NAT network of the node is as want says;
// *restored counts it when something else had removed or changed it.
static bool NodeEgressNatWinNat(NODE_EGRESS_NAT *nat, const NODE_EGRESS_NAT_WANT *want, UINT *restored) {
	NODE_EGRESS_WMI w;
	NODE_EGRESS_NETNATS nn;
	wchar_t prefix[NODE_EGRESS_PREFIX];
	bool ok = false;

	prefix[0] = 0;
	if (want->Length != 0 && want->Length <= 32)
		UniFormat(prefix, sizeof(prefix), L"%u.%u.%u.%u/%u", (UINT)want->Supernet[0], (UINT)want->Supernet[1], (UINT)want->Supernet[2], (UINT)want->Supernet[3],
		          want->Length);

	HRESULT hr = NodeEgressWmiConnect(&w);
	if (FAILED(hr)) {
		NodeEgressNatError(nat, "WMI cannot be had for the NAT network of WinNAT", (DWORD)hr);
		return false;
	}

	hr = NodeEgressNetNats(w.Services, NODE_EGRESS_NETNAT_NAME, &nn);
	if (FAILED(hr)) {
		NodeEgressNatError(nat, "the NAT networks of WinNAT cannot be listed", (DWORD)hr);
	} else if (prefix[0] == 0) {
		// No VRF: the NAT network of the node goes
		ok = true;
		if (nn.Found && nn.Path != NULL) {
			hr = IWbemServices_DeleteInstance(w.Services, nn.Path, 0, NULL, NULL);
			ok = SUCCEEDED(hr);
			if (ok == false)
				NodeEgressNatError(nat, "the NAT network of WinNAT of the node cannot be removed", (DWORD)hr);
		}
		if (ok)
			nat->NetNat = false;
	} else if (nn.NumOthers != 0) {
		// WinNAT allows one NAT network per host, and the node never touches one of another program
		if (nat->Foreign == false)
			NodeLog(nat->Node, "Egress: %u NAT networks of WinNAT of another name exist, which the node leaves alone", nn.NumOthers);
		nat->Foreign = true;
	} else if (nn.Found && UniStrCmpi(nn.Prefix, prefix) == 0) {
		ok = true;
	} else {
		// The NAT network of the node over another prefix goes first: a new Generation, or something else changed it
		bool same = (nat->NetNat && UniStrCmpi(nat->Prefix, prefix) == 0);

		if (nn.Found && nn.Path != NULL)
			IWbemServices_DeleteInstance(w.Services, nn.Path, 0, NULL, NULL);
		hr = NodeEgressNetNatCreate(w.Services, NODE_EGRESS_NETNAT_NAME, prefix);
		ok = SUCCEEDED(hr);
		if (ok == false) {
			NodeEgressNatError(nat, "the NAT network of WinNAT of the node cannot be created", (DWORD)hr);
		} else if (same) {
			(*restored)++;
			NodeLog(nat->Node, "Egress: the NAT network of WinNAT of the node over %S was gone or changed: the node created it again", prefix);
		} else {
			NodeLog(nat->Node, "Egress: the NAT network of WinNAT of the node over %S created", prefix);
		}
		if (ok) {
			nat->NetNat = true;
			UniStrCpy(nat->Prefix, sizeof(nat->Prefix), prefix);
		}
	}

	NodeEgressNetNatsFree(&nn);
	NodeEgressWmiClose(&w);

	return ok;
}

// Reconcile the NAT of Windows of the tier of nat with want: true when it holds what want says. *restored counts what the node
// set again after something else had removed or changed it.
bool NodeEgressNatApply(NODE_EGRESS_NAT *nat, const NODE_EGRESS_NAT_WANT *want, UINT *restored) {
	UINT n = 0;
	bool ok = false;

	if (nat == NULL || want == NULL)
		return false;

	if (nat->Tier == CONTROL_EGRESS_RRAS)
		ok = NodeEgressNatRras(nat, want, &n);
	else if (nat->Tier == CONTROL_EGRESS_WINNAT)
		ok = NodeEgressNatWinNat(nat, want, &n);

	if (ok)
		nat->LastError = 0;
	if (restored != NULL)
		*restored = n;

	return ok;
}

// Whether a NAT network of WinNAT of another name stopped the last reconcile: the node never touches one
bool NodeEgressNatForeign(const NODE_EGRESS_NAT *nat) {
	return (nat != NULL && nat->Foreign);
}

// Undo what the node configured in the NAT of Windows, and free nat: the NAT information of each interface of RRAS that it
// configured, the interfaces and IPv4 transports that it added to RRAS and the NAT routing protocol if it added it, or its NAT
// network of WinNAT
void NodeEgressNatFree(NODE_EGRESS_NAT *nat) {
	if (nat == NULL)
		return;

	if (nat->Tier == CONTROL_EGRESS_RRAS && (nat->NumIfs != 0 || nat->Protocol)) {
		NODE_EGRESS_MPR m;
		DWORD err = NodeEgressMprConnect(&m);

		if (err == NO_ERROR) {
			UINT left = 0;

			for (UINT i = 0; i < nat->NumIfs; i++) {
				NODE_EGRESS_RRAS_IF *r = &nat->Ifs[i];

				if ((r->Done || r->Made[0] != 0 || r->Made[1] != 0) && NodeEgressRrasDrop(&m, r->Name, r->Made) != NO_ERROR)
					left++;
			}
			bool gone = (nat->Protocol == false || NodeEgressRrasProtocolDrop(&m));
			NodeEgressMprDisconnect(&m);
			NodeLog(nat->Node, "Egress: the NAT of Routing and Remote Access holds no interface of the node any more (%u of %u could not be taken out)%s", left,
			        nat->NumIfs,
			        nat->Protocol == false ? "" : (gone ? ", and the NAT routing protocol that the node added is gone" : ", and the NAT routing protocol that the node added could not be taken out"));
		} else {
			NodeLog(nat->Node, "Egress: Routing and Remote Access cannot be had to take out the NAT of the node (error 0x%x)", (UINT)err);
		}
	}

	if (nat->Tier == CONTROL_EGRESS_WINNAT && nat->NetNat) {
		if (NodeEgressNetNatRemove(NODE_EGRESS_NETNAT_NAME))
			NodeLog(nat->Node, "Egress: the NAT network of WinNAT of the node over %S removed", nat->Prefix);
		else
			NodeLog(nat->Node, "Egress: the NAT network of WinNAT of the node over %S could not be removed", nat->Prefix);
	}

	Zero(nat, sizeof(NODE_EGRESS_NAT));
	Free(nat);
}
