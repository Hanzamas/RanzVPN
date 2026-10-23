// TransportQueue.c
// The ingress queue of the session layer (CORE-S2-1 #69; ADR-0022, amendment of 2026-10-15 on the
// TCP-over-TCP meltdown): the data records of a Noise session over a transport on TCP wait here for
// the stream (TransportNoise.c). The queue is CoDel, after the pseudocode of RFC 8289 and the Linux
// codel.h it gives: when a record leaves, the queue measures how long it waited (its sojourn time);
// once the sojourn time stayed above the target for an interval while more than one largest record
// waited, it drops the record at the head and enters the dropping state, in which it drops the next
// one an interval over the square root of the drops later, until a record leaves below the target.
// A queue without CoDel drops only at its limit, at the tail, as a full buffer does.

#include "Core/Transport.h"

#include <math.h>

// One record that waits: the next one, when it came and its bytes
struct TRANSPORT_QUEUE_ITEM {
	TRANSPORT_QUEUE_ITEM *Next; // The record that came after it
	UINT64 Time;                // When it was pushed (us)
	UINT Size;                  // Its size ...
	UCHAR *Data;                // ... and its bytes, NULL for none
};

// Wipe and free a record, which may be NULL
static void TransportQueueFreeItem(TRANSPORT_QUEUE_ITEM *item) {
	if (item == NULL)
		return;

	if (item->Data != NULL) {
		SecureZeroMemory(item->Data, item->Size);
		HeapFree(GetProcessHeap(), 0, item->Data);
	}
	HeapFree(GetProcessHeap(), 0, item);
}

void TransportQueueInit(TRANSPORT_QUEUE *q, UINT mode) {
	if (q == NULL)
		return;

	ZeroMemory(q, sizeof(TRANSPORT_QUEUE));
	q->Mode = (mode == TRANSPORT_QUEUE_CODEL ? TRANSPORT_QUEUE_CODEL : TRANSPORT_QUEUE_FIFO);
	q->Limit = TRANSPORT_QUEUE_LIMIT;
	q->Target = TRANSPORT_QUEUE_TARGET;
	q->Interval = TRANSPORT_QUEUE_INTERVAL;
}

bool TransportQueuePush(TRANSPORT_QUEUE *q, UINT64 now, const void *data, UINT size) {
	if (q == NULL || (data == NULL && size != 0))
		return false;

	q->NumPushed++;
	if (q->NumRecords >= q->Limit) {
		q->NumOverflow++;
		return false;
	}

	// A record that finds no memory is dropped as one above the limit is
	TRANSPORT_QUEUE_ITEM *item = (TRANSPORT_QUEUE_ITEM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_QUEUE_ITEM));
	UCHAR *copy = (size != 0 ? (UCHAR *)HeapAlloc(GetProcessHeap(), 0, size) : NULL);
	if (item == NULL || (size != 0 && copy == NULL)) {
		if (copy != NULL)
			HeapFree(GetProcessHeap(), 0, copy);
		TransportQueueFreeItem(item);
		q->NumOverflow++;
		return false;
	}

	if (copy != NULL && data != NULL)
		CopyMemory(copy, data, size);
	item->Time = now;
	item->Size = size;
	item->Data = copy;

	if (q->Tail != NULL)
		q->Tail->Next = item;
	else
		q->Head = item;
	q->Tail = item;
	q->NumRecords++;
	q->Bytes += size;
	if (size > q->MaxRecord)
		q->MaxRecord = size;

	return true;
}

// The record at the head leaves the queue (dodequeue of RFC 8289): NULL when none waits. *ok_to_drop: the sojourn time
// has been above the target for an interval, and more than one largest record still waits.
static TRANSPORT_QUEUE_ITEM *TransportQueueTake(TRANSPORT_QUEUE *q, UINT64 now, bool *ok_to_drop) {
	TRANSPORT_QUEUE_ITEM *item = q->Head;

	*ok_to_drop = false;
	if (item == NULL) {
		// Nothing waits, so nothing waits above the target
		q->FirstAbove = 0;
		return NULL;
	}

	q->Head = item->Next;
	if (q->Head == NULL)
		q->Tail = NULL;
	q->NumRecords--;
	q->Bytes -= item->Size;

	UINT64 sojourn = (now > item->Time ? now - item->Time : 0);
	if (sojourn < q->Target || q->Bytes <= q->MaxRecord) {
		// Below the target, or too little waits to keep the stream busy: it must stay above for a whole interval again
		q->FirstAbove = 0;
	} else if (q->FirstAbove == 0) {
		q->FirstAbove = now + q->Interval;
	} else if (now >= q->FirstAbove) {
		*ok_to_drop = true;
	}

	return item;
}

// The control law: the time of the next drop, an interval over the square root of the drops after t
static UINT64 TransportQueueControlLaw(const TRANSPORT_QUEUE *q, UINT64 t, UINT count) {
	return t + (UINT64)((double)q->Interval / sqrt((double)(count != 0 ? count : 1)));
}

// Drop a record that CoDel took
static void TransportQueueDrop(TRANSPORT_QUEUE *q, TRANSPORT_QUEUE_ITEM *item) {
	if (item == NULL)
		return;

	q->NumDropped++;
	TransportQueueFreeItem(item);
}

bool TransportQueuePop(TRANSPORT_QUEUE *q, UINT64 now, void *data, UINT max, UINT *size) {
	bool ok_to_drop = false;

	if (size != NULL)
		*size = 0;
	if (q == NULL || size == NULL || (data == NULL && max != 0))
		return false;

	TRANSPORT_QUEUE_ITEM *item = TransportQueueTake(q, now, &ok_to_drop);

	if (q->Mode == TRANSPORT_QUEUE_CODEL && q->Dropping) {
		// The sojourn time went below the target: the dropping state ends. Otherwise drop at the times of the control
		// law, several records when the time of several came, while the records still wait too long.
		if (ok_to_drop == false)
			q->Dropping = false;
		while (q->Dropping && now >= q->DropNext) {
			TransportQueueDrop(q, item);
			q->Count++;
			item = TransportQueueTake(q, now, &ok_to_drop);
			if (ok_to_drop == false)
				q->Dropping = false;
			else
				q->DropNext = TransportQueueControlLaw(q, q->DropNext, q->Count);
		}
	} else if (q->Mode == TRANSPORT_QUEUE_CODEL && ok_to_drop) {
		// Above the target for an interval: drop one and enter the dropping state. When it last left that state not
		// long ago, the drop rate that controlled the queue then is the start (the Linux variant that RFC 8289 gives).
		TransportQueueDrop(q, item);
		item = TransportQueueTake(q, now, &ok_to_drop);
		q->Dropping = true;

		UINT delta = q->Count - q->LastCount;
		q->Count = 1;
		if (delta > 1 && (now < q->DropNext || now - q->DropNext < 16 * q->Interval))
			q->Count = delta;
		q->DropNext = TransportQueueControlLaw(q, now, q->Count);
		q->LastCount = q->Count;
	}

	// A record that does not fit the caller's buffer cannot go out: it is dropped as well, and the next one leaves
	while (item != NULL && item->Size > max) {
		TransportQueueDrop(q, item);
		item = TransportQueueTake(q, now, &ok_to_drop);
	}
	if (item == NULL)
		return false;

	if (data != NULL && item->Data != NULL)
		CopyMemory(data, item->Data, item->Size);
	*size = item->Size;
	q->NumPopped++;
	TransportQueueFreeItem(item);

	return true;
}

void TransportQueueFree(TRANSPORT_QUEUE *q) {
	if (q == NULL)
		return;

	while (q->Head != NULL) {
		TRANSPORT_QUEUE_ITEM *item = q->Head;

		q->Head = item->Next;
		TransportQueueFreeItem(item);
	}
	q->Tail = NULL;
	q->NumRecords = 0;
	q->Bytes = 0;
}

UINT64 TransportQueueNow() {
	LARGE_INTEGER frequency, count;

	// Neither fails on Windows XP and later, and the frequency is fixed at boot; the tick count of the system stands in
	// should one fail
	if (QueryPerformanceFrequency(&frequency) == FALSE || frequency.QuadPart <= 0 || QueryPerformanceCounter(&count) == FALSE || count.QuadPart < 0)
		return GetTickCount64() * 1000;

	// Whole seconds, then the rest, so that the product does not overflow
	return (UINT64)(count.QuadPart / frequency.QuadPart) * 1000000 + (UINT64)(count.QuadPart % frequency.QuadPart) * 1000000 / (UINT64)frequency.QuadPart;
}
