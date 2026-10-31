// evpncapstest.c
// Named Capability evpn test of vpntest ("evpncaps" command, SDN-63, #290)
//
// The Capability evpn that a node reports to the controller in the Hello of its control stream (NodeCaps.c; ADR-0032 amendment
// of 2026-10-22): the node can be the gateway of a Stretch of an L2 Network when its host is a Windows Server and its VXLAN
// module runs, which it does on every host that runs the node (the Capability plainLinks says so too). The licence that has EVPN
// and BGP is not the node's to tell: only the controller holds the key, and it gives no Stretch to a node while the licence in
// force lacks it. The test gives NodeCapsDecide the editions that a node runs on, Windows Server and its domain controllers and
// the editions of Windows 11, on x64 and on arm64: only a Server has the Capability, and neither a workstation of a product that
// the protocol does not count nor a host whose version cannot be read has it. It gives it no host, which holds no Capability.
// Then it reads the host it runs on: NodeCapsProc, which the control client calls for each Hello, tells the Capability that
// NodeCapsDecide decides on what NodeCapsReadHost found, with the VXLAN module that it needs. The SDN tracer of windows.yml reads
// the same Capability from the controller that the Hello of a node on the runner reached (the API).
// Prints "EVPNCAPS TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/NodeCaps.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

// An edition of a host, and whether a node on it reports the Capability evpn
typedef struct EVPN_CASE
{
	char *Name;
	UINT ProductType;
	UINT Product;
	UINT Machine;
	bool Evpn;
} EVPN_CASE;

// The editions: the product type of the version, the product of GetProductInfo and the architecture
static const EVPN_CASE evpn_cases[] =
{
	{"Windows Server 2025 Datacenter", VER_NT_SERVER, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true},
	{"Windows Server 2022 Standard", VER_NT_SERVER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true},
	{"Windows Server on arm64", VER_NT_SERVER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_ARM64, true},
	{"a domain controller", VER_NT_DOMAIN_CONTROLLER, PRODUCT_STANDARD_SERVER, PROCESSOR_ARCHITECTURE_AMD64, true},
	{"Windows 11 Home", VER_NT_WORKSTATION, PRODUCT_CORE, PROCESSOR_ARCHITECTURE_AMD64, false},
	{"Windows 11 Pro", VER_NT_WORKSTATION, PRODUCT_PROFESSIONAL, PROCESSOR_ARCHITECTURE_AMD64, false},
	{"Windows 11 Pro for Workstations", VER_NT_WORKSTATION, PRODUCT_PRO_WORKSTATION, PROCESSOR_ARCHITECTURE_AMD64, false},
	{"Windows 11 Enterprise on arm64", VER_NT_WORKSTATION, PRODUCT_ENTERPRISE, PROCESSOR_ARCHITECTURE_ARM64, false},
	{"Windows 11 Enterprise multi-session", VER_NT_WORKSTATION, PRODUCT_SERVERRDSH, PROCESSOR_ARCHITECTURE_AMD64, false},
	{"a workstation of a product that the protocol does not count", VER_NT_WORKSTATION, PRODUCT_HOME_PREMIUM, PROCESSOR_ARCHITECTURE_AMD64, false},
	{"a host whose version cannot be read", 0, PRODUCT_DATACENTER_SERVER, PROCESSOR_ARCHITECTURE_AMD64, false},
};

// evpncaps: the Capability evpn of a node, for each edition of Windows that it runs on and for this host
RANZ_TEST("evpncaps", evpncaps_test, "Node Capability evpn: a Windows Server can be the gateway of a Stretch of an L2 Network, a workstation cannot, for each edition and for this host.");
void evpncaps_test(UINT num, char **arg)
{
	NODE_CAPS_HOST host;
	CONTROL_CAPS caps;
	CONTROL_CAPS reported;
	UINT failed = 0;

	Print("Capability evpn test (NodeCapsDecide, NodeCapsReadHost, NodeCapsProc)\n");

	for (UINT i = 0; i < sizeof(evpn_cases) / sizeof(evpn_cases[0]); i++)
	{
		const EVPN_CASE *c = &evpn_cases[i];

		Zero(&host, sizeof(host));
		host.Machine = c->Machine;
		host.ProductType = c->ProductType;
		host.Product = c->Product;

		// A Capabilities that holds the opposite already: the decision is of the host alone, and leaves nothing of it
		caps.Evpn = (c->Evpn == false);
		NodeCapsDecide(&host, &caps);

		if (caps.Evpn != c->Evpn)
		{
			Print("  [FAIL] %s: evpn %u; expected %u\n", c->Name, (UINT)caps.Evpn, (UINT)c->Evpn);
			failed++;
		}
		else
		{
			Print("  [OK] %s: evpn %u\n", c->Name, (UINT)caps.Evpn);
		}
	}

	// A Windows Server has the Capability whatever else its host holds: with no driver, and with SeLow and the XDP runtime
	Zero(&host, sizeof(host));
	host.Machine = PROCESSOR_ARCHITECTURE_AMD64;
	host.ProductType = VER_NT_SERVER;
	host.Product = PRODUCT_STANDARD_SERVER;
	host.SeLowService = true;
	host.SeLowDriver = true;
	host.XdpService = true;
	host.XdpDriver = true;
	host.XdpApi = true;
	host.HyperV = true;
	host.Rras = true;
	caps.Evpn = false;
	NodeCapsDecide(&host, &caps);
	if (caps.Evpn == false)
	{
		Print("  [FAIL] A Windows Server with SeLow, the XDP runtime, Hyper-V and RRAS reports no evpn\n");
		failed++;
	}

	// A decision for no host holds no Capability
	caps.Evpn = true;
	NodeCapsDecide(NULL, &caps);
	if (caps.Evpn)
	{
		Print("  [FAIL] No host: evpn %u; expected a Capabilities that holds none\n", (UINT)caps.Evpn);
		failed++;
	}

	// This host
	NodeCapsReadHost(&host);
	NodeCapsDecide(&host, &caps);
	Print("  This host: product type %u, product 0x%X: SKU %u, evpn %u\n", host.ProductType, host.Product, caps.Sku, (UINT)caps.Evpn);
	if (caps.Evpn != (caps.Sku == CONTROL_SKU_SERVER))
	{
		Print("  [FAIL] The SKU of this host is %u, and it gives evpn %u: only a Windows Server does\n", caps.Sku, (UINT)caps.Evpn);
		failed++;
	}

	// What the control client asks for with each Hello: the decision on this host, with the VXLAN module that the Capability
	// needs
	reported.Evpn = (caps.Evpn == false);
	reported.PlainLinks = false;
	NodeCapsProc(NULL, &reported);
	if (reported.Evpn != caps.Evpn)
	{
		Print("  [FAIL] NodeCapsProc: evpn %u; the decision on this host is %u\n", (UINT)reported.Evpn, (UINT)caps.Evpn);
		failed++;
	}
	if (reported.Evpn && reported.PlainLinks == false)
	{
		Print("  [FAIL] NodeCapsProc: evpn without plainLinks, the VXLAN module that evpn needs\n");
		failed++;
	}

	if (failed == 0)
	{
		Print("EVPNCAPS TEST OK\n");
	}
	else
	{
		Print("EVPNCAPS TEST FAILED (%u checks failed)\n", failed);
	}
}
