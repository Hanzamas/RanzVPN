// NodeCaps.c
// The Capabilities of a node (ADR-0033; ONE-3, #312): the facts about its host that the node tells the controller in
// the Hello of its control stream (NodeCapsProc, which the control client calls for each Hello) and writes to its node
// log at each start (NodeLogCaps), where what ranz install put on the machine can be read from outside. The node finds
// them by looking at the host, with the calls that Windows gives for it and that any account may make: the
// architecture from GetNativeSystemInfo, and a driver from the service that its package registers and the files that
// the package copies into System32. SeLow and the XDP runtime exist for x64 only (ADR-0013, ADR-0022), so a host of
// another architecture has neither, whatever it holds under those names. A fact that cannot be found counts as
// missing, which the controller reads as a Capability that the node lacks (ADR-0033).

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"

#include "NodeCaps.h"
#include "NodeInternal.h"

// The key of the services of Windows in the registry: the key of a service is named after it
#define NODE_CAPS_SERVICES L"SYSTEM\\CurrentControlSet\\Services\\"

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
}

// The architecture of the Capabilities as the node log names it
static const char *NodeCapsArchitecture(UINT architecture) {
	if (architecture == CONTROL_ARCHITECTURE_X64)
		return "x64";
	if (architecture == CONTROL_ARCHITECTURE_ARM64)
		return "arm64";

	return "unknown";
}

void NodeLogCaps(NODE *n) {
	CONTROL_CAPS caps;

	NodeCapsProc(NULL, &caps);

	NodeLog(n, "Capabilities: architecture %s, SeLow %s, XDP %s", NodeCapsArchitecture(caps.Architecture), caps.SeLow ? "yes" : "no", caps.Xdp ? "yes" : "no");
}
