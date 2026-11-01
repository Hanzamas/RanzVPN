// capstest.c
// Named Capabilities test of vpntest ("caps" command, ONE-3 #312)
//
// The Capabilities that a node reports to the controller in the Hello of its control stream (ADR-0033, NodeCaps.c): the
// architecture of its host, and whether the host holds SeLow and the XDP runtime. The test gives NodeCapsDecide the
// hosts that ranz install leaves: x64 with SeLow and the XDP runtime, with SeLow alone (the XDP runtime that failed to
// install, or that ranz install --no-xdp left out) and with neither, and arm64, where Wintun is the only driver. It
// gives it the hosts that are not whole too: a service whose driver file is gone, a driver without its service, an XDP
// runtime without its API library, which are not there; an arm64 host that holds a service named SeLow or xdp, which is
// not them; and a host of another architecture, which is not told at all. Then it reads the host it runs on: the
// architecture is the one of this build, an arm64 host has neither driver, and NodeCapsProc, which the control client
// calls for each Hello, gives what NodeCapsDecide decides on what NodeCapsReadHost found. The install job and the
// default VRF tracer of windows.yml read the same Capabilities from a node on a machine that ranz install changed (the
// node log) and from the controller that its Hello reached (the API).
// The BGP peering is a Capability of the install of the node (SDN-77-R2, #532): NodeCapsPeering reports it for a node
// whose sidecar, ranz.exe, is where the node looks for it, and for no other, and with it the route reflectors of the peering,
// which the same sidecar runs (SDN-79, #359).
// The Windows edition, Hyper-V and the Egress tier (SDN-12, #188): the editions of Windows 11 and Windows Server that a
// node runs on, each as the product type of its version and the product of GetProductInfo, give the SKU of the control
// protocol, a product that it does not count gives none, and a version that cannot be read gives none either. Hyper-V is
// what the host holds. The Egress tier is the first that the host supports: RRAS NAT on a Windows Server whose Routing and
// Remote Access runs as a LAN router (and on no workstation, whatever runs there), WinNAT where Hyper-V and WinNAT are present
// and no NAT network of WinNAT of another program exists, and the proxy on every other host, Home, Pro and arm64 among them,
// and where such a NAT network exists. This host gives a tier, the proxy when it has neither RRAS on a Windows Server nor
// Hyper-V with WinNAT. Prints "CAPS TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

// A host, and the Capabilities that a node on it reports
typedef struct CAPS_CASE
{
	char *Name;
	NODE_CAPS_HOST Host;
	UINT Architecture;
	bool SeLow;
	bool Xdp;
} CAPS_CASE;

// The hosts: the architecture, then the service and the driver of SeLow, the service and the driver of the XDP runtime and
// its API library
static const CAPS_CASE caps_cases[] =
{
	{"x64 with SeLow and the XDP runtime", {PROCESSOR_ARCHITECTURE_AMD64, true, true, true, true, true}, CONTROL_ARCHITECTURE_X64, true, true},
	{"x64 with SeLow alone", {PROCESSOR_ARCHITECTURE_AMD64, true, true, false, false, false}, CONTROL_ARCHITECTURE_X64, true, false},
	{"x64 with neither", {PROCESSOR_ARCHITECTURE_AMD64, false, false, false, false, false}, CONTROL_ARCHITECTURE_X64, false, false},
	{"x64 with the service of SeLow and not its driver", {PROCESSOR_ARCHITECTURE_AMD64, true, false, true, true, true}, CONTROL_ARCHITECTURE_X64, false, true},
	{"x64 with the driver of SeLow and not its service", {PROCESSOR_ARCHITECTURE_AMD64, false, true, true, true, true}, CONTROL_ARCHITECTURE_X64, false, true},
	{"x64 with the XDP service and driver and not its API library", {PROCESSOR_ARCHITECTURE_AMD64, true, true, true, true, false}, CONTROL_ARCHITECTURE_X64, true, false},
	{"x64 with the XDP service and its API library and not its driver", {PROCESSOR_ARCHITECTURE_AMD64, true, true, true, false, true}, CONTROL_ARCHITECTURE_X64, true, false},
	{"x64 with the XDP driver and its API library and not its service", {PROCESSOR_ARCHITECTURE_AMD64, true, true, false, true, true}, CONTROL_ARCHITECTURE_X64, true, false},
	{"arm64 with nothing but Wintun", {PROCESSOR_ARCHITECTURE_ARM64, false, false, false, false, false}, CONTROL_ARCHITECTURE_ARM64, false, false},
	{"arm64 with services and files of the names of SeLow and the XDP runtime", {PROCESSOR_ARCHITECTURE_ARM64, true, true, true, true, true}, CONTROL_ARCHITECTURE_ARM64, false, false},
	{"a host of another architecture", {PROCESSOR_ARCHITECTURE_INTEL, true, true, true, true, true}, CONTROL_ARCHITECTURE_UNSPECIFIED, false, false},
};

// The edition of a host, and the Windows edition (CONTROL_SKU_*) that a node on it reports (SDN-12, #188)
typedef struct CAPS_SKU_CASE
{
	char *Name;
	UINT ProductType;
	UINT Product;
	UINT Machine;
	bool HyperV;
	UINT Sku;
} CAPS_SKU_CASE;

// The editions: the product type of the version, the product of GetProductInfo, the architecture and Hyper-V
static const CAPS_SKU_CASE caps_sku_cases[] =
{
	{"Windows 11 Home", VER_NT_WORKSTATION, PRODUCT_CORE, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_HOME},
	{"Windows 11 Home Single Language on arm64", VER_NT_WORKSTATION, PRODUCT_CORE_SINGLELANGUAGE, PROCESSOR_ARCHITECTURE_ARM64, false, CONTROL_SKU_HOME},
	{"Windows 11 Home N", VER_NT_WORKSTATION, PRODUCT_CORE_N, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_HOME},
	{"Windows 11 Pro with Hyper-V", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, true, CONTROL_SKU_PRO},
	{"Windows 11 Pro on arm64", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_ARM64, false, CONTROL_SKU_PRO},
	{"Windows 11 Pro for Workstations", VER_NT_WORKSTATION, PRODUCT_PRO_WORKSTATION, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_PRO},
	{"Windows 11 Pro Education", VER_NT_WORKSTATION, PRODUCT_PRO_FOR_EDUCATION, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_PRO},
	{"Windows 11 Enterprise", VER_NT_WORKSTATION, PRODUCT_ENTERPRISE, PROCESSOR_ARCHITECTURE_ARM64, false, CONTROL_SKU_ENTERPRISE},
	{"Windows 11 Enterprise LTSC", VER_NT_WORKSTATION, PRODUCT_ENTERPRISE_S, PROCESSOR_ARCHITECTURE_AMD64, true, CONTROL_SKU_ENTERPRISE},
	{"Windows 11 Education", VER_NT_WORKSTATION, PRODUCT_EDUCATION, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_ENTERPRISE},
	{"Windows 11 IoT Enterprise", VER_NT_WORKSTATION, PRODUCT_IOTENTERPRISE, PROCESSOR_ARCHITECTURE_ARM64, false, CONTROL_SKU_ENTERPRISE},
	{"Windows 11 Enterprise multi-session", VER_NT_WORKSTATION, PRODUCT_SERVERRDSH, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_ENTERPRISE},
	{"Windows Server 2025 Datacenter with Hyper-V", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true, CONTROL_SKU_SERVER},
	{"Windows Server 2022 Standard", VER_NT_SERVER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_SERVER},
	{"a domain controller", VER_NT_DOMAIN_CONTROLLER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_SERVER},
	{"a workstation of a product that the protocol does not count", VER_NT_WORKSTATION, PRODUCT_HOME_PREMIUM, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_UNSPECIFIED},
	{"a host whose version cannot be read", 0, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, false, CONTROL_SKU_UNSPECIFIED},
};

// What decides the Egress tier of a host, and the tier (CONTROL_EGRESS_*) that a node on it uses (SDN-12, #188)
typedef struct CAPS_TIER_CASE
{
	char *Name;
	UINT ProductType;
	UINT Product;
	UINT Machine;
	bool Rras;
	bool HyperV;
	bool WinNat;
	bool NetNat;
	UINT Tier;
} CAPS_TIER_CASE;

// The hosts: the product type and the product, the architecture, RRAS as a LAN router, Hyper-V, WinNAT and a NAT network of
// WinNAT of another program
static const CAPS_TIER_CASE caps_tier_cases[] =
{
	{"Windows Server 2025 whose RRAS runs as a LAN router", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true, false, false, false, CONTROL_EGRESS_RRAS},
	{"Windows Server 2022 with RRAS, Hyper-V and WinNAT: RRAS NAT comes first", VER_NT_SERVER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true, true, true, false, CONTROL_EGRESS_RRAS},
	{"Windows Server 2025 with Hyper-V and WinNAT, no RRAS and no NAT network", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false, true, true, false, CONTROL_EGRESS_WINNAT},
	{"Windows Server 2025 with Hyper-V, WinNAT and the NAT network of another program", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false, true, true, true, CONTROL_EGRESS_PROXY},
	{"Windows 11 Pro with Hyper-V and WinNAT and no NAT network", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, false, true, true, false, CONTROL_EGRESS_WINNAT},
	{"Windows 11 Pro with Hyper-V, WinNAT and the NAT network of Docker", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, false, true, true, true, CONTROL_EGRESS_PROXY},
	{"Windows 11 Pro whose RRAS runs: RRAS NAT is for Windows Server", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, true, false, false, false, CONTROL_EGRESS_PROXY},
	{"Windows 11 Home", VER_NT_WORKSTATION, PRODUCT_CORE, PROCESSOR_ARCHITECTURE_AMD64, false, false, false, false, CONTROL_EGRESS_PROXY},
	{"Windows 11 Pro on arm64 without Hyper-V", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_ARM64, false, false, false, false, CONTROL_EGRESS_PROXY},
	{"Windows 11 Enterprise on arm64 with Hyper-V and WinNAT", VER_NT_WORKSTATION, PRODUCT_ENTERPRISE, PROCESSOR_ARCHITECTURE_ARM64, false, true, true, false, CONTROL_EGRESS_WINNAT},
	{"a Windows Server with WinNAT and without Hyper-V", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false, false, true, false, CONTROL_EGRESS_PROXY},
	{"Windows 11 Pro with Hyper-V and without WinNAT", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, false, true, false, false, CONTROL_EGRESS_PROXY},
	{"a host with RRAS whose version cannot be read", 0, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true, false, false, false, CONTROL_EGRESS_PROXY},
};

// caps: the Capabilities of a node for the hosts that ranz install leaves, and for this host
RANZ_TEST("caps", caps_test, "Node Capabilities: the architecture, SeLow and the XDP runtime that a node reports in its Hello, for each host that ranz install leaves and for this host, and the BGP peering when its sidecar is there.");
void caps_test(UINT num, char **arg)
{
	NODE_CAPS_HOST host;
	CONTROL_CAPS caps;
	CONTROL_CAPS reported;
	UINT expected;
	UINT failed = 0;

	Print("Capabilities test (NodeCapsDecide, NodeCapsReadHost, NodeCapsProc)\n");

	for (UINT i = 0; i < sizeof(caps_cases) / sizeof(caps_cases[0]); i++)
	{
		const CAPS_CASE *c = &caps_cases[i];

		// A Capabilities that holds something already: the decision is of the host alone, and leaves nothing of it
		caps.Architecture = 99;
		caps.SeLow = true;
		caps.Xdp = true;
		NodeCapsDecide(&c->Host, &caps);

		if (caps.Architecture != c->Architecture || caps.SeLow != c->SeLow || caps.Xdp != c->Xdp)
		{
			Print("  [FAIL] %s: architecture %u, SeLow %u, XDP %u; expected %u, %u, %u\n", c->Name, caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp,
				c->Architecture, (UINT)c->SeLow, (UINT)c->Xdp);
			failed++;
		}
		else
		{
			Print("  [OK] %s: architecture %u, SeLow %u, XDP %u\n", c->Name, caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp);
		}
	}

	// The Windows edition, Hyper-V and the Egress tier (SDN-12, #188): with neither RRAS nor WinNAT, every host takes the proxy
	for (UINT i = 0; i < sizeof(caps_sku_cases) / sizeof(caps_sku_cases[0]); i++)
	{
		const CAPS_SKU_CASE *c = &caps_sku_cases[i];

		Zero(&host, sizeof(host));
		host.Machine = c->Machine;
		host.ProductType = c->ProductType;
		host.Product = c->Product;
		host.HyperV = c->HyperV;
		caps.Sku = 99;
		caps.HyperV = (c->HyperV == false);
		caps.EgressTier = 99;
		NodeCapsDecide(&host, &caps);

		if (caps.Sku != c->Sku || caps.HyperV != c->HyperV || caps.EgressTier != CONTROL_EGRESS_PROXY)
		{
			Print("  [FAIL] %s: SKU %u, Hyper-V %u, Egress tier %u; expected %u, %u, %u (the proxy)\n", c->Name, caps.Sku, (UINT)caps.HyperV, caps.EgressTier,
				c->Sku, (UINT)c->HyperV, (UINT)CONTROL_EGRESS_PROXY);
			failed++;
		}
		else
		{
			Print("  [OK] %s: SKU %u, Hyper-V %u, Egress tier %u (the proxy)\n", c->Name, caps.Sku, (UINT)caps.HyperV, caps.EgressTier);
		}
	}

	// The Egress tier, the first that the host supports (SDN-12, #188)
	for (UINT i = 0; i < sizeof(caps_tier_cases) / sizeof(caps_tier_cases[0]); i++)
	{
		const CAPS_TIER_CASE *c = &caps_tier_cases[i];

		Zero(&host, sizeof(host));
		host.Machine = c->Machine;
		host.ProductType = c->ProductType;
		host.Product = c->Product;
		host.Rras = c->Rras;
		host.HyperV = c->HyperV;
		host.WinNat = c->WinNat;
		host.NetNat = c->NetNat;
		caps.EgressTier = 99;
		NodeCapsDecide(&host, &caps);

		if (caps.EgressTier != c->Tier)
		{
			Print("  [FAIL] %s: Egress tier %u; expected %u\n", c->Name, caps.EgressTier, c->Tier);
			failed++;
		}
		else
		{
			Print("  [OK] %s: Egress tier %u\n", c->Name, caps.EgressTier);
		}
	}

	// A decision for no host and for no Capabilities does nothing but return
	NodeCapsDecide(NULL, &caps);
	if (caps.Architecture != CONTROL_ARCHITECTURE_UNSPECIFIED || caps.SeLow || caps.Xdp || caps.Sku != CONTROL_SKU_UNSPECIFIED || caps.HyperV ||
		caps.EgressTier != CONTROL_EGRESS_NONE)
	{
		Print("  [FAIL] No host: architecture %u, SeLow %u, XDP %u, SKU %u, Hyper-V %u, Egress tier %u; expected a Capabilities that holds none\n",
			caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp, caps.Sku, (UINT)caps.HyperV, caps.EgressTier);
		failed++;
	}
	NodeCapsDecide(&caps_cases[0].Host, NULL);

	// This host
	NodeCapsReadHost(&host);
	NodeCapsDecide(&host, &caps);
	Print("  This host: machine %u, SeLow service %u and driver %u, XDP service %u, driver %u and API library %u: architecture %u, SeLow %u, XDP %u\n",
		host.Machine, (UINT)host.SeLowService, (UINT)host.SeLowDriver, (UINT)host.XdpService, (UINT)host.XdpDriver, (UINT)host.XdpApi,
		caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp);
	Print("  This host: product type %u, product 0x%X, Hyper-V %u, RRAS as a LAN router %u, WinNAT %u, a NAT network of WinNAT of another program %u: SKU %u, Egress tier %u\n",
		host.ProductType, host.Product, (UINT)host.HyperV, (UINT)host.Rras, (UINT)host.WinNat, (UINT)host.NetNat, caps.Sku, caps.EgressTier);

	// The version of a host that runs this build can be read, and the host gives a tier: the proxy, unless it has RRAS on a
	// Windows Server or Hyper-V with WinNAT
	if (host.ProductType != VER_NT_WORKSTATION && host.ProductType != VER_NT_SERVER && host.ProductType != VER_NT_DOMAIN_CONTROLLER)
	{
		Print("  [FAIL] The product type of this host is %u, which is neither a workstation's nor a server's\n", host.ProductType);
		failed++;
	}
	if (caps.EgressTier < CONTROL_EGRESS_RRAS || caps.EgressTier > CONTROL_EGRESS_PROXY ||
		((caps.Sku != CONTROL_SKU_SERVER || host.Rras == false) && (host.HyperV == false || host.WinNat == false) && caps.EgressTier != CONTROL_EGRESS_PROXY))
	{
		Print("  [FAIL] The Egress tier of this host is %u, which its facts do not give\n", caps.EgressTier);
		failed++;
	}

	// An x64 build runs natively on x64 and under emulation on arm64, where Windows shows it an x64 host
#if defined(_M_ARM64)
	expected = CONTROL_ARCHITECTURE_ARM64;
#else
	expected = CONTROL_ARCHITECTURE_X64;
#endif
	if (caps.Architecture != expected)
	{
		Print("  [FAIL] The architecture of this host is %u, not %u, that of this build\n", caps.Architecture, expected);
		failed++;
	}

	if (caps.Architecture == CONTROL_ARCHITECTURE_ARM64 && (caps.SeLow || caps.Xdp))
	{
		Print("  [FAIL] An arm64 host has no SeLow and no XDP runtime: SeLow %u, XDP %u\n", (UINT)caps.SeLow, (UINT)caps.Xdp);
		failed++;
	}

	// What the control client asks for with each Hello
	reported.Architecture = 99;
	reported.SeLow = true;
	reported.Xdp = true;
	NodeCapsProc(NULL, &reported);
	if (reported.Architecture != caps.Architecture || reported.SeLow != caps.SeLow || reported.Xdp != caps.Xdp)
	{
		Print("  [FAIL] NodeCapsProc: architecture %u, SeLow %u, XDP %u; the decision on this host is %u, %u, %u\n", reported.Architecture,
			(UINT)reported.SeLow, (UINT)reported.Xdp, caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp);
		failed++;
	}
	if (reported.Sku != caps.Sku || reported.HyperV != caps.HyperV || reported.EgressTier != caps.EgressTier)
	{
		Print("  [FAIL] NodeCapsProc: SKU %u, Hyper-V %u, Egress tier %u; the decision on this host is %u, %u, %u\n", reported.Sku, (UINT)reported.HyperV,
			reported.EgressTier, caps.Sku, (UINT)caps.HyperV, caps.EgressTier);
		failed++;
	}

	// The BGP peering (SDN-77-R2, #532): a node reports it when its sidecar is where it looks for it, NODE.BgpSidecar. This
	// executable stands for that file, and the same name with a suffix for a file that is not there
	NODE *node = ZeroMalloc(sizeof(NODE));

	GetExeNameW(node->BgpSidecar, sizeof(node->BgpSidecar));
	caps.BgpPeering = false;
	caps.BgpReflection = false;
	NodeCapsPeering(node, &caps);
	if (caps.BgpPeering == false || caps.BgpReflection == false)
	{
		Print("  [FAIL] A node whose sidecar is there does not report the BGP peering (%u) or its route reflectors (%u)\n", (UINT)caps.BgpPeering,
			(UINT)caps.BgpReflection);
		failed++;
	}
	else
	{
		Print("  [OK] A node whose sidecar is there reports the BGP peering and its route reflectors\n");
	}

	UniStrCat(node->BgpSidecar, sizeof(node->BgpSidecar), L".missing");
	caps.BgpPeering = true;
	caps.BgpReflection = true;
	NodeCapsPeering(node, &caps);
	if (caps.BgpPeering || caps.BgpReflection)
	{
		Print("  [FAIL] A node whose sidecar is not there reports the BGP peering (%u) or its route reflectors (%u)\n", (UINT)caps.BgpPeering,
			(UINT)caps.BgpReflection);
		failed++;
	}
	else
	{
		Print("  [OK] A node whose sidecar is not there reports no BGP peering and no route reflectors\n");
	}

	// A node that names no sidecar at all, and no node
	Zero(node->BgpSidecar, sizeof(node->BgpSidecar));
	caps.BgpPeering = true;
	caps.BgpReflection = true;
	NodeCapsPeering(node, &caps);
	if (caps.BgpPeering || caps.BgpReflection)
	{
		Print("  [FAIL] A node that names no sidecar reports the BGP peering or its route reflectors\n");
		failed++;
	}

	caps.BgpPeering = true;
	caps.BgpReflection = true;
	NodeCapsPeering(NULL, &caps);
	if (caps.BgpPeering || caps.BgpReflection)
	{
		Print("  [FAIL] No node reports the BGP peering or its route reflectors\n");
		failed++;
	}

	// No Capabilities to fill does nothing but return
	NodeCapsPeering(node, NULL);
	Free(node);

	if (failed == 0)
	{
		Print("CAPS TEST OK\n");
	}
	else
	{
		Print("CAPS TEST FAILED (%u checks failed)\n", failed);
	}
}
