// NodeCaps.c
// The Capabilities of a node (ADR-0033; ONE-3, #312): the facts about its host that the node tells the controller in
// the Hello of its control stream (NodeCapsProc, which the control client calls for each Hello) and writes to its node
// log at each start (NodeLogCaps), where what ranz install put on the machine can be read from outside. The node finds
// them by looking at the host, with the calls that Windows gives for it and that any account may make: the
// architecture from GetNativeSystemInfo, and a driver from the service that its package registers and the files that
// the package copies into System32. SeLow and the XDP runtime exist for x64 only (ADR-0013, ADR-0022), so a host of
// another architecture has neither, whatever it holds under those names. A fact that cannot be found counts as
// missing, which the controller reads as a Capability that the node lacks (ADR-0033).
// The Windows edition comes from the version of the host (RtlGetVersion, which tells it to any program) and the product
// of GetProductInfo, Hyper-V from the service of its Virtual Machine Management, and the Egress tier, how the node takes
// the traffic of a VRF whose internet exit it is to the outside (SDN-12, #188; ADR-0025 decisions 13 to 15), from them and
// from what the NAT of Windows has on the host: Routing and Remote Access running as a LAN router, the service of WinNAT
// and a NAT network of WinNAT of another program, as the last look of the node at them saw it (NodeEgressNat.c).
// The BGP peering is a fact of the install of the node more than of its host: NodeCapsPeering reports it when the sidecar
// is where the node looks for it (SDN-77-R2, #532).
// Whether the node can be the gateway of a Stretch of an L2 Network, the Capability evpn (SDN-63, #290), follows from the edition: a
// Windows Server whose VXLAN module runs, which every node does.

#include "Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"

#include "NodeCaps.h"
#include "NodeEgress.h"
#include "NodeInternal.h"

// The key of the services of Windows in the registry: the key of a service is named after it
#define NODE_CAPS_SERVICES L"SYSTEM\\CurrentControlSet\\Services\\"

// RtlGetVersion of ntdll.dll: the version of Windows as it is, which GetVersionExW tells only a program whose manifest
// names that version. 0 (STATUS_SUCCESS) when it filled info.
typedef LONG(WINAPI NODE_CAPS_GET_VERSION_FUNC)(OSVERSIONINFOEXW *info);

// Whether the service name is registered on the host. The Service Control Manager keeps the key of each service under
// Services, which every account can read, so the node needs no right on the service itself.
static bool NodeCapsService(const wchar_t *name) {
	wchar_t path[MAX_PATH];
	HKEY key = NULL;

	UniStrCpy(path, sizeof(path), NODE_CAPS_SERVICES);
	UniStrCat(path, sizeof(path), name);

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
		return false;

	RegCloseKey(key);

	return true;
}

// Whether the file name is in the folder of System32 that dir names, "" for System32 itself and "drivers\\" for the
// folder of its drivers
static bool NodeCapsFile(const wchar_t *dir, const wchar_t *name) {
	wchar_t path[MAX_PATH];
	DWORD len = GetSystemDirectoryW(path, MAX_PATH);
	DWORD attributes;

	if (len == 0 || len >= MAX_PATH)
		return false;

	UniStrCat(path, sizeof(path), L"\\");
	UniStrCat(path, sizeof(path), dir);
	UniStrCat(path, sizeof(path), name);

	attributes = GetFileAttributesW(path);

	return (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

// The edition of Windows into host: the product type of its version and the product of GetProductInfo, both 0 when
// they cannot be read
static void NodeCapsReadEdition(NODE_CAPS_HOST *host) {
	OSVERSIONINFOEXW v;
	DWORD product = 0;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	NODE_CAPS_GET_VERSION_FUNC *get = (ntdll != NULL ? (NODE_CAPS_GET_VERSION_FUNC *)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL);

	Zero(&v, sizeof(v));
	v.dwOSVersionInfoSize = sizeof(v);

	if (get == NULL || get(&v) != 0)
		return;

	host->ProductType = v.wProductType;
	if (GetProductInfo(v.dwMajorVersion, v.dwMinorVersion, v.wServicePackMajor, v.wServicePackMinor, &product))
		host->Product = product;
}

// The Windows edition of a workstation of the product of GetProductInfo (CONTROL_SKU_*): Home, Pro or Enterprise, with
// the editions that the control protocol counts with them (Sku of control.proto); CONTROL_SKU_UNSPECIFIED for another
static UINT NodeCapsEdition(UINT product) {
	switch (product) {
	case PRODUCT_CORE:
	case PRODUCT_CORE_N:
	case PRODUCT_CORE_COUNTRYSPECIFIC:
	case PRODUCT_CORE_SINGLELANGUAGE:
		return CONTROL_SKU_HOME;
	case PRODUCT_PROFESSIONAL:
	case PRODUCT_PROFESSIONAL_N:
	case PRODUCT_PRO_WORKSTATION:
	case PRODUCT_PRO_WORKSTATION_N:
	case PRODUCT_PRO_FOR_EDUCATION:
	case PRODUCT_PRO_FOR_EDUCATION_N:
		return CONTROL_SKU_PRO;
	case PRODUCT_ENTERPRISE:
	case PRODUCT_ENTERPRISE_N:
	case PRODUCT_ENTERPRISE_E:
	case PRODUCT_ENTERPRISE_EVALUATION:
	case PRODUCT_ENTERPRISE_N_EVALUATION:
	case PRODUCT_ENTERPRISE_S:
	case PRODUCT_ENTERPRISE_S_N:
	case PRODUCT_ENTERPRISE_S_EVALUATION:
	case PRODUCT_ENTERPRISE_S_N_EVALUATION:
	case PRODUCT_EDUCATION:
	case PRODUCT_EDUCATION_N:
	case PRODUCT_IOTENTERPRISE:
	case PRODUCT_SERVERRDSH:
		return CONTROL_SKU_ENTERPRISE;
	default:
		return CONTROL_SKU_UNSPECIFIED;
	}
}

void NodeCapsReadHost(NODE_CAPS_HOST *host) {
	SYSTEM_INFO info;

	if (host == NULL)
		return;

	Zero(host, sizeof(NODE_CAPS_HOST));
	Zero(&info, sizeof(info));

	// The native view: the same on x64 and arm64 hosts whichever architecture the node was built for
	GetNativeSystemInfo(&info);
	host->Machine = info.wProcessorArchitecture;

	host->SeLowService = NodeCapsService(L"SeLow");
	host->SeLowDriver = NodeCapsFile(L"drivers\\", L"SeLow_x64.sys");
	host->XdpService = NodeCapsService(L"xdp");
	host->XdpDriver = NodeCapsFile(L"drivers\\", L"xdp.sys");
	host->XdpApi = NodeCapsFile(L"", L"xdpapi.dll");

	// The edition and Hyper-V (SDN-12, #188)
	NodeCapsReadEdition(host);
	host->HyperV = NodeCapsService(L"vmms");

	// What the Egress tiers on the NAT of Windows need: RRAS as a LAN router, and WinNAT with no NAT network of another program,
	// as the last look of the node at the NAT networks saw it, since the Capabilities ask WMI nothing (NodeEgressForeignNetNat)
	host->Rras = NodeEgressRrasRouter();
	host->WinNat = NodeCapsService(L"WinNat");
	host->NetNat = (host->HyperV && host->WinNat && NodeEgressForeignNetNat());
}

void NodeCapsDecide(const NODE_CAPS_HOST *host, CONTROL_CAPS *caps) {
	if (caps == NULL)
		return;

	Zero(caps, sizeof(CONTROL_CAPS));

	if (host == NULL)
		return;

	if (host->Machine == PROCESSOR_ARCHITECTURE_AMD64)
		caps->Architecture = CONTROL_ARCHITECTURE_X64;
	else if (host->Machine == PROCESSOR_ARCHITECTURE_ARM64)
		caps->Architecture = CONTROL_ARCHITECTURE_ARM64;

	// The edition: a host whose version is not a workstation's is a Windows Server (SDN-12, #188)
	if (host->ProductType == VER_NT_SERVER || host->ProductType == VER_NT_DOMAIN_CONTROLLER)
		caps->Sku = CONTROL_SKU_SERVER;
	else if (host->ProductType == VER_NT_WORKSTATION)
		caps->Sku = NodeCapsEdition(host->Product);
	caps->HyperV = host->HyperV;

	// The gateway of a Stretch of an L2 Network (SDN-63, #290; ADR-0032 amendment of 2026-10-22): a Windows Server, whose
	// VXLAN module runs on every host that the node runs on (NodeCapsProc tells it as the Capability plainLinks), so the
	// edition alone decides it. The licence that has EVPN and BGP is the controller's to check, since only it holds the key
	caps->Evpn = (caps->Sku == CONTROL_SKU_SERVER);

	// The Egress tier, the first that the host supports (ADR-0025 decision 13): RRAS NAT on a Windows Server whose RRAS runs as
	// a LAN router, WinNAT where Hyper-V and WinNAT are present and no NAT network of WinNAT exists, which the node then
	// leaves alone, and the proxy on the Windows TCP/IP stack, which runs on every host, Home, Pro and arm64 among them
	// (NodeEgress.c)
	if (caps->Sku == CONTROL_SKU_SERVER && host->Rras)
		caps->EgressTier = CONTROL_EGRESS_RRAS;
	else if (host->HyperV && host->WinNat && host->NetNat == false)
		caps->EgressTier = CONTROL_EGRESS_WINNAT;
	else
		caps->EgressTier = CONTROL_EGRESS_PROXY;

	// There is no SeLow package for arm64 and no production-signed XDP runtime (ADR-0022): a service of one of their names
	// on another host is not them
	if (caps->Architecture != CONTROL_ARCHITECTURE_X64)
		return;

	caps->SeLow = (host->SeLowService && host->SeLowDriver);
	caps->Xdp = (host->XdpService && host->XdpDriver && host->XdpApi);
}

void NodeCapsProc(void *param, CONTROL_CAPS *caps) {
	NODE_CAPS_HOST host;

	NodeCapsReadHost(&host);
	NodeCapsDecide(&host, caps);
	// The links of kind vxlan and geneve run on Winsock UDP, on every host (NodeLink.c; SDN-76, #356)
	if (caps != NULL)
		caps->PlainLinks = true;
	// The source groups travel with the packets of every node (NodeSourceGroup.c; SDN-87, #386)
	if (caps != NULL)
		caps->Tags = true;
	// TCP splitting runs on the Windows TCP stack and the filter engine of every host (NodeSplit.c; CORE-P2-3, #94)
	if (caps != NULL)
		caps->TcpSplit = true;
}

void NodeCapsPeering(NODE *n, CONTROL_CAPS *caps) {
	if (caps == NULL)
		return;

	// The peering is in this release (NodePeering.c); what it needs besides is the sidecar, which NodePeeringStartSidecar looks for
	// in the same place and with the same check, so a node that reports it can start one
	caps->BgpPeering = (n != NULL && IsFileExistsW(n->BgpSidecar));
}

// The architecture of the Capabilities as the node log names it
static const char *NodeCapsArchitecture(UINT architecture) {
	if (architecture == CONTROL_ARCHITECTURE_X64)
		return "x64";
	if (architecture == CONTROL_ARCHITECTURE_ARM64)
		return "arm64";

	return "unknown";
}

// The Windows edition of the Capabilities as the node log names it
static const char *NodeCapsSku(UINT sku) {
	switch (sku) {
	case CONTROL_SKU_HOME:
		return "Home";
	case CONTROL_SKU_PRO:
		return "Pro";
	case CONTROL_SKU_ENTERPRISE:
		return "Enterprise";
	case CONTROL_SKU_SERVER:
		return "Server";
	default:
		return "unknown";
	}
}

// The Egress tier of the Capabilities as the node log names it
static const char *NodeCapsEgress(UINT tier) {
	switch (tier) {
	case CONTROL_EGRESS_RRAS:
		return "RRAS NAT";
	case CONTROL_EGRESS_WINNAT:
		return "WinNAT";
	case CONTROL_EGRESS_PROXY:
		return "proxy";
	default:
		return "none";
	}
}

void NodeLogCaps(NODE *n) {
	CONTROL_CAPS caps;

	NodeCapsProc(NULL, &caps);

	NodeLog(n, "Capabilities: architecture %s, SeLow %s, XDP %s, SKU %s, Hyper-V %s, egress tier %s", NodeCapsArchitecture(caps.Architecture),
	        caps.SeLow ? "yes" : "no", caps.Xdp ? "yes" : "no", NodeCapsSku(caps.Sku), caps.HyperV ? "yes" : "no", NodeCapsEgress(caps.EgressTier));
}
