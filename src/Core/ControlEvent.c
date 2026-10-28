// ControlEvent.c
// The events of the node itself on the control stream (AUD1-DT-11, #459; Core/Control.h; ADR-0030 decision 5). The owner of
// a client raises an event (ControlRaiseEvent), which waits in a queue until the client writes it as one of the events of a
// Telemetry message (NodeEvent of the control protocol): at once while its stream is open, and after the Hello of the next
// stream when it is not, so a node that was cut off from its controller reports what it saw once it is back. An event
// leaves the queue only once its write succeeded, so a stream that ended while it was written has it written again on the
// next. The queue holds CONTROL_EVENT_QUEUE events, and a new one above that takes the place of the oldest.

#include "Core/ControlInternal.h"

#include <pb_encode.h>

#include <string.h>

#define CONTROL_EVENTS_HEADER 4 // The size of a frame, big-endian, before its message (as Control.c writes them)

// The types are the values of the schema, and a message holds the events that CONTROL_MAX_EVENTS says
_Static_assert(CONTROL_EVENT_SESSION_FLAP == (UINT)ranz_control_v1_NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP, "CONTROL_EVENT_SESSION_FLAP is NODE_EVENT_TYPE_SESSION_FLAP of the control protocol");
_Static_assert(CONTROL_MAX_EVENTS <= sizeof(((ranz_control_v1_Telemetry *)0)->events) / sizeof(((ranz_control_v1_Telemetry *)0)->events[0]), "a Telemetry message holds CONTROL_MAX_EVENTS events");

// The events that a client reports
struct CONTROL_EVENTS {
	// The queue and its state
	SRWLOCK Lock;
	// The events that wait, oldest first
	UINT Num;
	CONTROL_EVENT Queue[CONTROL_EVENT_QUEUE];
	// The events that the queue dropped, oldest first, because it was full
	UINT64 Dropped;
	// The message that the thread of the client writes
	ranz_control_v1_Telemetry *Message;
};

static void *ControlEventAlloc(SIZE_T size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static void ControlEventRelease(void *p) {
	if (p != NULL)
		HeapFree(GetProcessHeap(), 0, p);
}

CONTROL_EVENTS *ControlNewEvents() {
	CONTROL_EVENTS *e = ControlEventAlloc(sizeof(CONTROL_EVENTS));

	if (e == NULL)
		return NULL;

	InitializeSRWLock(&e->Lock);
	e->Message = ControlEventAlloc(sizeof(ranz_control_v1_Telemetry));
	if (e->Message == NULL) {
		ControlEventRelease(e);
		return NULL;
	}

	return e;
}

void ControlFreeEvents(CONTROL_EVENTS *e) {
	if (e == NULL)
		return;

	ControlEventRelease(e->Message);
	ControlEventRelease(e);
}

bool ControlRaiseEvent(CONTROL_EVENTS *e, UINT type, const char *subject, const char *message) {
	if (e == NULL || type == 0)
		return false;

	AcquireSRWLockExclusive(&e->Lock);
	// The queue is full: the oldest event goes
	if (e->Num == CONTROL_EVENT_QUEUE) {
		MoveMemory(&e->Queue[0], &e->Queue[1], sizeof(CONTROL_EVENT) * (CONTROL_EVENT_QUEUE - 1));
		e->Num--;
		e->Dropped++;
	}

	CONTROL_EVENT *ev = &e->Queue[e->Num++];

	ZeroMemory(ev, sizeof(CONTROL_EVENT));
	ev->Type = type;
	strncpy_s(ev->Subject, sizeof(ev->Subject), (subject != NULL ? subject : ""), _TRUNCATE);
	strncpy_s(ev->Message, sizeof(ev->Message), (message != NULL ? message : ""), _TRUNCATE);
	ReleaseSRWLockExclusive(&e->Lock);

	return true;
}

UINT ControlGetEvents(CONTROL_EVENTS *e, CONTROL_EVENT *list, UINT max) {
	UINT num = 0;

	if (e == NULL || list == NULL)
		return 0;

	AcquireSRWLockShared(&e->Lock);
	num = (e->Num < max ? e->Num : max);
	if (num != 0)
		CopyMemory(list, e->Queue, sizeof(CONTROL_EVENT) * num);
	ReleaseSRWLockShared(&e->Lock);

	return num;
}

// Fill the message with the first events that wait, CONTROL_MAX_EVENTS at most: their number. The caller holds the lock.
static UINT ControlEventsFill(CONTROL_EVENTS *e) {
	ranz_control_v1_Telemetry *m = e->Message;
	UINT num = (e->Num < CONTROL_MAX_EVENTS ? e->Num : CONTROL_MAX_EVENTS);

	if (num == 0)
		return 0;

	ZeroMemory(m, sizeof(ranz_control_v1_Telemetry));
	for (UINT i = 0; i < num; i++) {
		ranz_control_v1_NodeEvent *ne = &m->events[m->events_count++];

		ne->type = (ranz_control_v1_NodeEventType)e->Queue[i].Type;
		strncpy_s(ne->subject, sizeof(ne->subject), e->Queue[i].Subject, _TRUNCATE);
		strncpy_s(ne->message, sizeof(ne->message), e->Queue[i].Message, _TRUNCATE);
	}

	return num;
}

// Write m as the body Telemetry of a ControlMessage, in one frame
static bool ControlEventsSend(const ranz_control_v1_Telemetry *m, TRANSPORT_STREAM *s) {
	pb_ostream_t sizing = PB_OSTREAM_SIZING;

	if (pb_encode_tag(&sizing, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) == false || pb_encode_submessage(&sizing, ranz_control_v1_Telemetry_fields, m) == false)
		return false;

	UINT size = (UINT)sizing.bytes_written;
	UCHAR *frame = ControlEventAlloc(CONTROL_EVENTS_HEADER + (SIZE_T)size);
	if (frame == NULL)
		return false;

	pb_ostream_t os = pb_ostream_from_buffer(frame + CONTROL_EVENTS_HEADER, size);
	bool ok = pb_encode_tag(&os, PB_WT_STRING, ranz_control_v1_ControlMessage_telemetry_tag) && pb_encode_submessage(&os, ranz_control_v1_Telemetry_fields, m) && os.bytes_written == size;
	if (ok) {
		frame[0] = (UCHAR)(size >> 24);
		frame[1] = (UCHAR)(size >> 16);
		frame[2] = (UCHAR)(size >> 8);
		frame[3] = (UCHAR)size;
		ok = TransportWrite(s, frame, CONTROL_EVENTS_HEADER + size);
	}

	ControlEventRelease(frame);
	return ok;
}

bool ControlWriteEvents(CONTROL_EVENTS *e, TRANSPORT_STREAM *s) {
	UINT num = 0;
	UINT64 dropped = 0;

	if (e == NULL)
		return true;

	AcquireSRWLockExclusive(&e->Lock);
	num = ControlEventsFill(e);
	dropped = e->Dropped;
	ReleaseSRWLockExclusive(&e->Lock);

	if (num == 0)
		return true;

	// The write is outside the lock, so that the owner raises its events while it waits for the stream; only the thread of
	// the client uses the message
	if (ControlEventsSend(e->Message, s) == false)
		return false;

	// What was written leaves the queue. An event that the queue dropped meanwhile was one of them, the oldest.
	AcquireSRWLockExclusive(&e->Lock);
	UINT64 gone = e->Dropped - dropped;
	if (gone < num) {
		UINT sent = num - (UINT)gone;

		MoveMemory(&e->Queue[0], &e->Queue[sent], sizeof(CONTROL_EVENT) * (e->Num - sent));
		e->Num -= sent;
	}
	ReleaseSRWLockExclusive(&e->Lock);

	return true;
}
