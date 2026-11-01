// ControlEvpn.c
// The EVPN of a gateway on the control stream (SDN-25-R3, #571; Core/Control.h; ADR-0030 decision 3): the counters of the
// frames of the gateway with the fabric since its sidecar started (CONTROL_EVPN_COUNTERS, NODE_EVPN_STATUS of
// Cedar/NodeEvpn.h), so that an operator sees in the metrics of the controller what the gateway dropped, the frames of an
// unknown VTEP among them. The owner sets the counters while its EVPN runs and takes them away when it stops
// (ControlSetEvpn), and the client sends them in one Telemetry message after each Hello while they are set, so a controller
// that the node reaches anew has them, and whenever they changed, at most every CONTROL_EVPN_REPORT ms. The controller drops a
// counter that its node did not report for a while (telemetry.DefaultStale, 5 minutes), so the client sends the counters again
// every CONTROL_EVPN_REFRESH ms while they stay the same, as it sends the Paths of the node (ControlPath.c).

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#define CONTROL_EVPN_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The counters that a client reports
struct CONTROL_EVPN {
	SRWLOCK Lock;                       // Everything below but Message
	bool Set;                           // The owner set the counters: the client sends them after each Hello
	CONTROL_EVPN_COUNTERS Counters;     // The counters that the owner set last
	bool Changed;                       // They changed since the client sent them
	UINT64 Sent;                        // When the client sent them last, 0 for never on the stream that runs
	ranz_control_v1_Telemetry *Message; // The message that the thread of the client writes
};

static void *ControlEvpnAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlEvpnFree(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

CONTROL_EVPN *ControlNewEvpn() {
	CONTROL_EVPN *e = ControlEvpnAlloc(sizeof(CONTROL_EVPN));

	if (e == NULL)
		return NULL;

	InitializeSRWLock(&e->Lock);
	e->Message = ControlEvpnAlloc(sizeof(ranz_control_v1_Telemetry));
	if (e->Message == NULL) {
		ControlEvpnFree(e);
		return NULL;
	}

	return e;
}

void ControlFreeEvpn(CONTROL_EVPN *e) {
	if (e == NULL)
		return;

	ControlEvpnFree(e->Message);
	ControlEvpnFree(e);
}

// Put the counters c in place of the ones before, or none for NULL: the client sends them when they differ from the ones it
// sent, and sends none while none are set
void ControlSetEvpn(CONTROL_EVPN *e, const CONTROL_EVPN_COUNTERS *c) {
	if (e == NULL)
		return;

	AcquireSRWLockExclusive(&e->Lock);
	if (c == NULL) {
		e->Set = false;
		e->Changed = false;
		ZeroMemory(&e->Counters, sizeof(e->Counters));
	} else if (e->Set == false || memcmp(&e->Counters, c, sizeof(e->Counters)) != 0) {
		e->Set = true;
		e->Counters = *c;
		e->Changed = true;
	}
	ReleaseSRWLockExclusive(&e->Lock);
}

// The counters that the owner set last into c: false, with c zero, while none are set
bool ControlGetEvpn(CONTROL_EVPN *e, CONTROL_EVPN_COUNTERS *c) {
	bool set = false;

	if (c == NULL)
		return false;

	ZeroMemory(c, sizeof(CONTROL_EVPN_COUNTERS));
	if (e == NULL)
		return false;

	AcquireSRWLockShared(&e->Lock);
	set = e->Set;
	if (set)
		*c = e->Counters;
	ReleaseSRWLockShared(&e->Lock);

	return set;
}

// A new stream has none of the counters
void ControlEvpnResend(CONTROL_EVPN *e) {
	if (e == NULL)
		return;

	AcquireSRWLockExclusive(&e->Lock);
	e->Changed = e->Set;
	e->Sent = 0;
	ReleaseSRWLockExclusive(&e->Lock);
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlEvpnSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlEvpnAlloc(CONTROL_EVPN_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_EVPN_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_EVPN_HEADER + size);
	}

	ControlEvpnFree(frame);
	return ok;
}

// Write the counters as one Telemetry message, on the thread of the client, while they are set: on a stream that has none of
// them yet, when they changed since the client sent them and CONTROL_EVPN_REPORT ms passed since then, and when they stayed the
// same for CONTROL_EVPN_REFRESH ms. False when the write failed, which ends the stream.
bool ControlWriteEvpn(CONTROL_EVPN *e, TRANSPORT_STREAM *s) {
	bool due = false;
	UINT64 now = GetTickCount64();

	if (e == NULL)
		return true;

	AcquireSRWLockExclusive(&e->Lock);
	if (e->Set && (e->Sent == 0 || now - e->Sent >= (e->Changed ? CONTROL_EVPN_REPORT : CONTROL_EVPN_REFRESH))) {
		ranz_control_v1_Telemetry *m = e->Message;
		const CONTROL_EVPN_COUNTERS *c = &e->Counters;

		ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
		m->has_evpn = true;
		m->evpn.sent = c->Sent;
		m->evpn.failed = c->Failed;
		m->evpn.delivered = c->Delivered;
		m->evpn.undelivered = c->Undelivered;
		m->evpn.unknown_vtep = c->UnknownVtep;
		m->evpn.strangers = c->Strangers;
		m->evpn.not_ours = c->NotOurs;
		m->evpn.unknown_vni = c->UnknownVni;
		m->evpn.malformed = c->Malformed;
		e->Changed = false;
		e->Sent = now;
		due = true;
	}
	ReleaseSRWLockExclusive(&e->Lock);

	return (due == false || ControlEvpnSend(e->Message, s));
}
