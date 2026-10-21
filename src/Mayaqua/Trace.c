// Trace.c
// Debug() tracing on an ETW TraceLogging provider
//
// Debug() (Str.c) hands its messages to the "Ranz.VPN" provider. The provider is off unless an ETW
// trace session enables it: until then IsTraceEnabled() is false and Debug() prints, or does not,
// exactly as before. While a session listens, each message becomes one "Debug" event (level
// verbose, field "Message"), with debug output on or off.
//
// TraceLoggingProvider.h and evntprov.h select their declarations by the Windows API level, which the
// build sets for every file (Windows 10, cmake/RanzOptions.cmake).

#include "Trace.h"

#include "Internat.h"
#include "Memory.h"
#include "Str.h"

#include <TraceLoggingProvider.h>
#include <winmeta.h>

// The GUID {75b1770a-b78d-5167-6ab6-c837a52a76a2} is the EventSource hash of the name, the
// convention for TraceLogging providers, so that a tool given the name can derive it
TRACELOGGING_DEFINE_PROVIDER(trace_provider, "Ranz.VPN",
                             (0x75b1770a, 0xb78d, 0x5167, 0x6a, 0xb6, 0xc8, 0x37, 0xa5, 0x2a, 0x76, 0xa2));

static bool trace_registered = false;

// Register the provider (InitMayaqua)
void InitTrace() {
	if (trace_registered) {
		return;
	}

	// A provider that fails to register stays off, as it is without a session
	trace_registered = (TraceLoggingRegister(trace_provider) == S_OK);
}

// Unregister the provider (FreeMayaqua)
void FreeTrace() {
	if (trace_registered == false) {
		return;
	}

	TraceLoggingUnregister(trace_provider);
	trace_registered = false;
}

// Whether a trace session listens for the Debug() events
bool IsTraceEnabled() {
	return TraceLoggingProviderEnabled(trace_provider, WINEVENT_LEVEL_VERBOSE, 0) ? true : false;
}

// Write a Debug() message as one "Debug" event, formatted as PrintArgs() (Str.c) formats it
void TraceDebugArgs(const char *fmt, va_list args) {
	if (fmt == NULL || IsTraceEnabled() == false) {
		return;
	}

	wchar_t *msg = CopyFormatArgsToUni(fmt, args);
	if (msg == NULL) {
		return;
	}

	TraceLoggingWrite(trace_provider, "Debug",
	                  TraceLoggingLevel(WINEVENT_LEVEL_VERBOSE),
	                  TraceLoggingWideString(msg, "Message"));

	Free(msg);
}
