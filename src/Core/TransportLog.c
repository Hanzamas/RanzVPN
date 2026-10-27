// TransportLog.c
// The log of the transport module (CORE-H5-R, #443): a line that tells why a transport runs with less than it should goes
// to the procedure that its owner, a node, gave, or without one to the debugger. The module has no log of its own, so a
// QUIC side without an exporter, whose sessions with a bound peer fail, says so here.

#include "Core/Transport.h"

#include <stdarg.h>
#include <stdio.h>

static SRWLOCK g_transport_log_lock = SRWLOCK_INIT; // The procedure: shared while a line goes out, exclusive to set it
static TRANSPORT_LOG_PROC *g_transport_log = NULL;  // The procedure, NULL for the debugger
static void *g_transport_log_param = NULL;          // ... and its parameter

void TransportSetLog(TRANSPORT_LOG_PROC *proc, void *param) {
	AcquireSRWLockExclusive(&g_transport_log_lock);
	g_transport_log = proc;
	g_transport_log_param = (proc != NULL ? param : NULL);
	ReleaseSRWLockExclusive(&g_transport_log_lock);
}

void TransportLog(const char *format, ...) {
	char line[TRANSPORT_LOG_SIZE];
	va_list args;

	if (format == NULL)
		return;

	va_start(args, format);
	int n = vsnprintf(line, sizeof(line), format, args);
	va_end(args);
	if (n < 0)
		return;

	AcquireSRWLockShared(&g_transport_log_lock);
	if (g_transport_log != NULL) {
		g_transport_log(g_transport_log_param, line);
	} else {
		OutputDebugStringA(line);
		OutputDebugStringA("\n");
	}
	ReleaseSRWLockShared(&g_transport_log_lock);
}
