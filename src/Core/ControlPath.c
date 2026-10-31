// ControlPath.c
// The Paths of the peer agent of a node on the control stream (CORE-S5-6, #412; Core/Control.h; ADR-0030 decision 3): the
// Upgrades of its Paths since the node started, each a move from the Relay to the direct path that ICE validated, and their
// Fallbacks, each a direct path whose consent freshness failed, so that its pair went back to the Relay. The owner sets the
// counts (ControlSetPaths), and the client sends them in one Telemetry message after each Hello once they were set, so a
// controller that the node reaches anew has them, and whenever they changed, at most every CONTROL_PATH_REPORT ms. The
// controller exports them, and drops a counter that its node did not report for a while (telemetry.DefaultStale, 5 minutes),
// as a counter that the node no longer has: so the client sends the counts again every CONTROL_PATH_REFRESH ms while they
// stay the same, as they do for hours on a node whose pairs keep their paths. The same message holds the punches of the
// node (CORE-S5-7, #413): its attempts at a direct path to a peer behind a symmetric NAT, the ones that met and the ones
// whose prediction failed (ControlSetPunches).

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#define CONTROL_PATHS_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The counts that a client reports
struct CONTROL_PATHS {
	SRWLOCK Lock;                       // Everything below but Message
	bool Set;                           // The owner set the counts: the client sends them after each Hello
	UINT64 Upgrades;                    // The counts that the owner set last
	UINT64 Fallbacks;                   // ...
	UINT64 PunchAttempts;               // ...
	UINT64 PunchSuccesses;              // ...
	UINT64 PunchFailures;               // ...
	bool Changed;                       // They changed since the client sent them
	UINT64 Sent;                        // When the client sent them last, 0 for never on the stream that runs
	ranz_control_v1_Telemetry *Message; // The message that the thread of the client writes
};

static void *ControlPathAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlPathFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

CONTROL_PATHS *ControlNewPaths() {
	CONTROL_PATHS *p = ControlPathAlloc(sizeof(CONTROL_PATHS));

	if (p == NULL)
		return NULL;

	InitializeSRWLock(&p->Lock);
	p->Message = ControlPathAlloc(sizeof(ranz_control_v1_Telemetry));
	if (p->Message == NULL) {
		ControlPathFree(p);
		return NULL;
	}

	return p;
}

void ControlFreePaths(CONTROL_PATHS *p) {
	if (p == NULL)
		return;

	ControlPathFree(p->Message);
	ControlPathFree(p);
}

// Put the counts of the Paths in place of the ones before: the client sends them when they differ from the ones it sent
void ControlSetPaths(CONTROL_PATHS *p, UINT64 upgrades, UINT64 fallbacks) {
	if (p == NULL)
		return;

	AcquireSRWLockExclusive(&p->Lock);
	if (p->Set == false || p->Upgrades != upgrades || p->Fallbacks != fallbacks) {
		p->Set = true;
		p->Upgrades = upgrades;
		p->Fallbacks = fallbacks;
		p->Changed = true;
	}
	ReleaseSRWLockExclusive(&p->Lock);
}

// Put the counts of the punches in place of the ones before: they go in the message of the Paths, which the client sends
// when they differ from the ones it sent
void ControlSetPunches(CONTROL_PATHS *p, UINT64 attempts, UINT64 successes, UINT64 failures) {
	if (p == NULL)
		return;

	AcquireSRWLockExclusive(&p->Lock);
	if (p->Set == false || p->PunchAttempts != attempts || p->PunchSuccesses != successes || p->PunchFailures != failures) {
		p->Set = true;
		p->PunchAttempts = attempts;
		p->PunchSuccesses = successes;
		p->PunchFailures = failures;
		p->Changed = true;
	}
	ReleaseSRWLockExclusive(&p->Lock);
}

// A new stream has none of the counts
void ControlPathsResend(CONTROL_PATHS *p) {
	if (p == NULL)
		return;

	AcquireSRWLockExclusive(&p->Lock);
	p->Changed = p->Set;
	p->Sent = 0;
	ReleaseSRWLockExclusive(&p->Lock);
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlPathsSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlPathAlloc(CONTROL_PATHS_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_PATHS_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_PATHS_HEADER + size);
	}

	ControlPathFree(frame);
	return ok;
}

// Write the counts as one Telemetry message, on the thread of the client, once they were set: on a stream that has none of
// them yet, when they changed since the client sent them and CONTROL_PATH_REPORT ms passed since then, and when they stayed
// the same for CONTROL_PATH_REFRESH ms. False when the write failed, which ends the stream.
bool ControlWritePaths(CONTROL_PATHS *p, TRANSPORT_STREAM *s) {
	bool due = false;
	UINT64 now = GetTickCount64();

	if (p == NULL)
		return true;

	AcquireSRWLockExclusive(&p->Lock);
	if (p->Set && (p->Sent == 0 || now - p->Sent >= (p->Changed ? CONTROL_PATH_REPORT : CONTROL_PATH_REFRESH))) {
		ranz_control_v1_Telemetry *m = p->Message;

		ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
		m->has_paths = true;
		m->paths.upgrades = p->Upgrades;
		m->paths.fallbacks = p->Fallbacks;
		m->paths.punch_attempts = p->PunchAttempts;
		m->paths.punch_successes = p->PunchSuccesses;
		m->paths.punch_failures = p->PunchFailures;
		p->Changed = false;
		p->Sent = now;
		due = true;
	}
	ReleaseSRWLockExclusive(&p->Lock);

	return (due == false || ControlPathsSend(p->Message, s));
}
