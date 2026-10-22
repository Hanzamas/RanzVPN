// NodeHarden.c
// The process mitigations of the node (ADR-0039 decision 2; SEC-1, #279): ranz-node sets them through
// SetProcessMitigationPolicy first thing, before it starts anything, and keeps the DLL search to System32 (FIX-4).
// A mitigation that a feature of the node cannot run under stays off; node_mitigations records why, and the node
// log says it at each start. vpntest runs nodes in its own process without them; nodesvc checks them on the
// ranzvpnserver service.

#include "Node.h"

#include "NodeInternal.h"

// The mitigations in the order the node sets them; Flags are the bits of each policy structure:
// - dynamic-code (ACG): PROCESS_MITIGATION_DYNAMIC_CODE_POLICY ProhibitDynamicCode. No executable memory is
//   allocated or made writable: the node has no JIT and no code generation.
// - signed-images: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY MicrosoftSignedOnly. Only images that Microsoft
//   signed load once the process runs: the node loads the DLLs of Windows only (winsqlite3, CNG, Winsock).
// - strict-handles: PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY RaiseExceptionOnInvalidHandleReference and
//   HandleExceptionsPermanentlyEnabled. A handle that is not valid raises an exception instead of an error code.
// - image-load: PROCESS_MITIGATION_IMAGE_LOAD_POLICY NoRemoteImages, NoLowMandatoryLabelImages and
//   PreferSystem32Images. No image from a remote share or with a low mandatory label, and System32 first.
static NODE_MITIGATION node_mitigations[] =
    {
        {"dynamic-code", ProcessDynamicCodePolicy, 0x1, NULL},
        {"signed-images", ProcessSignaturePolicy, 0x1, NULL},
        {"strict-handles", ProcessStrictHandleCheckPolicy, 0x3, NULL},
        {"image-load", ProcessImageLoadPolicy, 0x7, NULL},
};

#define NODE_NUM_MITIGATIONS ((UINT)(sizeof(node_mitigations) / sizeof(node_mitigations[0])))

// What NodeHarden did: whether it ran, and the error of each SetProcessMitigationPolicy that failed (0 when it took)
static bool node_hardened = false;
static UINT node_harden_errors[NODE_NUM_MITIGATIONS];

// Keep the DLL search to System32 and set the mitigations of node_mitigations that are not off. ranz-node calls it
// before InitMayaqua, so it uses plain Win32 calls only.
void NodeHarden() {
	// A DLL loaded by name comes from System32 only, never from the directory of the executable, which the default
	// directories of MsInitProcessCallOnce still search for the programs of the fork
	SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

	for (UINT i = 0; i < NODE_NUM_MITIGATIONS; i++) {
		NODE_MITIGATION *m = &node_mitigations[i];
		DWORD flags = m->Flags;

		if (m->Off != NULL)
			continue;

		if (SetProcessMitigationPolicy((PROCESS_MITIGATION_POLICY)m->Policy, &flags, sizeof(flags)) == FALSE)
			node_harden_errors[i] = GetLastError();
	}

	node_hardened = true;
}

// The mitigations of the node, for the tests; num receives the number of entries
const NODE_MITIGATION *NodeGetMitigations(UINT *num) {
	if (num != NULL)
		*num = NODE_NUM_MITIGATIONS;

	return node_mitigations;
}

// Write what NodeHarden did to the node log: each mitigation on, off with its reason, or not set with its error.
// Nothing in a process that did not call it.
void NodeLogMitigations(NODE *n) {
	if (node_hardened == false)
		return;

	for (UINT i = 0; i < NODE_NUM_MITIGATIONS; i++) {
		NODE_MITIGATION *m = &node_mitigations[i];

		if (m->Off != NULL)
			NodeLog(n, "Mitigation %s off: %s", m->Name, m->Off);
		else if (node_harden_errors[i] != 0)
			NodeLog(n, "Mitigation %s not set: error %u", m->Name, node_harden_errors[i]);
		else
			NodeLog(n, "Mitigation %s on", m->Name);
	}

	NodeLog(n, "DLLs load from System32 only");
}
