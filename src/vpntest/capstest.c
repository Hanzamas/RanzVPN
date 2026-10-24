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
// node log) and from the controller that its Hello reached (the API). Prints "CAPS TEST OK" only when every check
// passes.

#include "testlist.h"

#include "Cedar/NodeCaps.h"

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

// caps: the Capabilities of a node for the hosts that ranz install leaves, and for this host
RANZ_TEST("caps", caps_test, "Node Capabilities: the architecture, SeLow and the XDP runtime that a node reports in its Hello, for each host that ranz install leaves and for this host.");
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

	// A decision for no host and for no Capabilities does nothing but return
	NodeCapsDecide(NULL, &caps);
	if (caps.Architecture != CONTROL_ARCHITECTURE_UNSPECIFIED || caps.SeLow || caps.Xdp)
	{
		Print("  [FAIL] No host: architecture %u, SeLow %u, XDP %u; expected a Capabilities that holds none\n", caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp);
		failed++;
	}
	NodeCapsDecide(&caps_cases[0].Host, NULL);

	// This host
	NodeCapsReadHost(&host);
	NodeCapsDecide(&host, &caps);
	Print("  This host: machine %u, SeLow service %u and driver %u, XDP service %u, driver %u and API library %u: architecture %u, SeLow %u, XDP %u\n",
		host.Machine, (UINT)host.SeLowService, (UINT)host.SeLowDriver, (UINT)host.XdpService, (UINT)host.XdpDriver, (UINT)host.XdpApi,
		caps.Architecture, (UINT)caps.SeLow, (UINT)caps.Xdp);

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

	if (failed == 0)
	{
		Print("CAPS TEST OK\n");
	}
	else
	{
		Print("CAPS TEST FAILED (%u checks failed)\n", failed);
	}
}
