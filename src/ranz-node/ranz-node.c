// ranz-node.c
// The node of the new core as the ranzvpnserver Windows service (ADR-0011; ADR-0020 decision 4)

#include "Cedar/Cedar.h"
#include "Cedar/Node.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"

static NODE *node = NULL;

static void StartProcess() {
	// The self-integrity check at start (SEC-3 #281, ADR-0036). A changed or patched binary degrades
	// later and far from the check; an unsigned development build runs clean. It never crashes here.
	MsStartSelfIntegrity();

	InitCedar();

	node = NewNode(NULL);
	NodeStart(node);
}

static void StopProcess() {
	FreeNode(node);
	node = NULL;

	FreeCedar();
}

// The GUI-subsystem entry point: CmdLine holds the arguments without the program name
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow) {
	InitProcessCallOnce();

	// The process mitigations and the System32-only DLL search of ADR-0039, before anything starts (NodeHarden.c)
	NodeHarden();

	// The service runs as its virtual account NT SERVICE\ranzvpnserver, not LocalSystem (ADR-0039 decision 3);
	// /install adds no firewall rule for it
	return MsServiceEx(GC_SVC_NAME_NODE, StartProcess, StopProcess, CmdLine, NULL, true);
}
