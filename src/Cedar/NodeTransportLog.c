// NodeTransportLog.c
// The log of the transport module in the node log (CORE-H5-R, #443): a line of Core/Transport.h's log, as that of a QUIC
// side whose msquic gives no exporter, goes into the log of the running node. The log of the transport module is one
// per process, so the node that started last takes it, and a node that stops gives it back to the debugger; the nodes
// that the vpntest harness runs in one process share it that way.

#include "Node.h"

#include "NodeInternal.h"

// A line of the transport log, on any thread, a callback of msquic too
static void NodeTransportLogLine(void *param, const char *line) {
	NodeLog((NODE *)param, "Transport: %s", line);
}

// The lines of the transport log go into the log of n
void NodeTransportLogStart(NODE *n) {
	TransportSetLog(NodeTransportLogLine, n);
}

// ... and no more, once it returns
void NodeTransportLogStop(NODE *n) {
	UNREFERENCED_PARAMETER(n);

	TransportSetLog(NULL, NULL);
}
