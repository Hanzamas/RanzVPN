// ControlTrace.c
// The trace of a packet on the control stream (SDN-89, #388; Core/Control.h). The Network objects of a state say whether
// the trace of each Network is on (Network.trace): the state holds the pools of those Networks, each with the VRF of its
// Network (CONTROL_STATE.Traced), by which a node tells the packets of its host that it traces as their ingress node. A
// node records each traced packet that it handles (ControlAddTrace), and the record waits in a queue until the client
// writes it as one of the records of a Telemetry message (TraceRecord of the control protocol): at once while its stream
// is open, and after the Hello of the next stream when it is not. A record leaves the queue only once its write
// succeeded, so a stream that ended while it was written has it written again on the next. The queue is a ring of
// CONTROL_TRACE_QUEUE records, and a new one above that takes the place of the oldest, so that a record costs the same
// whether the stream drains the queue or not.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_TRACES_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// A message holds the records that CONTROL_MAX_TRACES says, and each names the ingress node by CONTROL_TRACE_INGRESS bytes
_Static_assert(CONTROL_MAX_TRACES <= sizeof(((ranz_control_v1_Telemetry *)0)->traces) / sizeof(((ranz_control_v1_Telemetry *)0)->traces[0]), "a Telemetry message holds CONTROL_MAX_TRACES records");
_Static_assert(CONTROL_TRACE_INGRESS == sizeof(((ranz_control_v1_TraceRecord *)0)->ingress.bytes), "a record names the ingress node by CONTROL_TRACE_INGRESS bytes");

// The records that a client reports
struct CONTROL_TRACES {
	// The queue and its state
	SRWLOCK Lock;
	// The records that wait, oldest first from First, in a ring
	UINT First;
	UINT Num;
	CONTROL_TRACE Queue[CONTROL_TRACE_QUEUE];
	// The records that the queue dropped, oldest first, because it was full
	UINT64 Dropped;
	// The message that the thread of the client writes
	ranz_control_v1_Telemetry *Message;
};

static void *ControlTraceAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlTraceRelease(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

//
// The Networks that trace
//

// The pool p of a Network of the VRF vrf_id whose trace is on into the state, as long as CONTROL_MAX_TRACED pools fit: a
// pool that is neither IPv4 nor IPv6, or longer than its address, is left out
static void ControlTracedPool(CONTROL_STATE *st, UINT vrf_id, const ranz_control_v1_Prefix *p) {
	if (p == NULL || st->NumTraced >= CONTROL_MAX_TRACED || (p->address.size != 4 && p->address.size != 16) || p->length > (uint32_t)p->address.size * 8)
		return;

	CONTROL_TRACED *t = &st->Traced[st->NumTraced++];

	ZeroMemory(t, sizeof(CONTROL_TRACED));
	t->VrfId = vrf_id;
	CopyMemory(t->Pool.Address, p->address.bytes, p->address.size);
	t->Pool.AddressSize = p->address.size;
	t->Pool.Length = p->length;
}

// The IPv4 and the IPv6 pool of each Network whose trace is on, among num objects, into the state
void ControlCopyTraced(CONTROL_STATE *st, const ranz_control_v1_Object *objects, UINT num) {
	st->NumTraced = 0;

	for (UINT i = 0; i < num; i++) {
		if (objects[i].which_kind != ranz_control_v1_Object_network_tag || objects[i].kind.network.trace == false)
			continue;

		const ranz_control_v1_Network *nw = &objects[i].kind.network;

		ControlTracedPool(st, nw->vrf_id, nw->has_ipv4_pool ? &nw->ipv4_pool : NULL);
		ControlTracedPool(st, nw->vrf_id, nw->has_ipv6_pool ? &nw->ipv6_pool : NULL);
	}
}

//
// The records
//

CONTROL_TRACES *ControlNewTraces() {
	CONTROL_TRACES *q = ControlTraceAlloc(sizeof(CONTROL_TRACES));

	if (q == NULL)
		return NULL;

	InitializeSRWLock(&q->Lock);
	q->Message = ControlTraceAlloc(sizeof(ranz_control_v1_Telemetry));
	if (q->Message == NULL) {
		ControlTraceRelease(q);
		return NULL;
	}

	return q;
}

void ControlFreeTraces(CONTROL_TRACES *q) {
	if (q == NULL)
		return;

	ControlTraceRelease(q->Message);
	ControlTraceRelease(q);
}

bool ControlAddTrace(CONTROL_TRACES *q, const CONTROL_TRACE *record) {
	if (q == NULL || record == NULL || record->Id == 0)
		return false;

	AcquireSRWLockExclusive(&q->Lock);
	// The queue is full: the oldest record goes
	if (q->Num == CONTROL_TRACE_QUEUE) {
		q->First = (q->First + 1) % CONTROL_TRACE_QUEUE;
		q->Num--;
		q->Dropped++;
	}
	CopyMemory(&q->Queue[(q->First + q->Num) % CONTROL_TRACE_QUEUE], record, sizeof(CONTROL_TRACE));
	q->Num++;
	ReleaseSRWLockExclusive(&q->Lock);

	return true;
}

UINT ControlGetTraces(CONTROL_TRACES *q, CONTROL_TRACE *list, UINT max) {
	UINT num = 0;

	if (q == NULL || list == NULL)
		return 0;

	AcquireSRWLockShared(&q->Lock);
	num = (q->Num < max ? q->Num : max);
	for (UINT i = 0; i < num; i++)
		CopyMemory(&list[i], &q->Queue[(q->First + i) % CONTROL_TRACE_QUEUE], sizeof(CONTROL_TRACE));
	ReleaseSRWLockShared(&q->Lock);

	return num;
}

// Fill the message with the first records that wait, CONTROL_MAX_TRACES at most: their number. The caller holds the lock.
static UINT ControlTracesFill(CONTROL_TRACES *q) {
	ranz_control_v1_Telemetry *m = q->Message;
	UINT num = (q->Num < CONTROL_MAX_TRACES ? q->Num : CONTROL_MAX_TRACES);

	if (num == 0)
		return 0;

	ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
	for (UINT i = 0; i < num; i++) {
		const CONTROL_TRACE *t = &q->Queue[(q->First + i) % CONTROL_TRACE_QUEUE];
		ranz_control_v1_TraceRecord *r = &m->traces[m->traces_count++];

		r->trace = t->Id;
		r->ingress.size = CONTROL_TRACE_INGRESS;
		CopyMemory(r->ingress.bytes, t->Ingress, CONTROL_TRACE_INGRESS);
		r->vrf_id = t->VrfId;
		r->group = t->Group;
		r->allowed = t->Allowed;
	}

	return num;
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlTracesSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlTraceAlloc(CONTROL_TRACES_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_TRACES_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_TRACES_HEADER + size);
	}

	ControlTraceRelease(frame);
	return ok;
}

bool ControlWriteTraces(CONTROL_TRACES *q, TRANSPORT_STREAM *s) {
	UINT num = 0;
	UINT64 dropped = 0;

	if (q == NULL)
		return true;

	AcquireSRWLockExclusive(&q->Lock);
	num = ControlTracesFill(q);
	dropped = q->Dropped;
	ReleaseSRWLockExclusive(&q->Lock);

	if (num == 0)
		return true;

	// The write is outside the lock, so that the node records its traced packets while it waits for the stream; only the
	// thread of the client uses the message
	if (ControlTracesSend(q->Message, s) == false)
		return false;

	// What was written leaves the queue. A record that the queue dropped meanwhile was one of them, the oldest.
	AcquireSRWLockExclusive(&q->Lock);
	UINT64 gone = q->Dropped - dropped;
	if (gone < num) {
		UINT sent = num - (UINT)gone;

		q->First = (q->First + sent) % CONTROL_TRACE_QUEUE;
		q->Num -= sent;
	}
	ReleaseSRWLockExclusive(&q->Lock);

	return true;
}
