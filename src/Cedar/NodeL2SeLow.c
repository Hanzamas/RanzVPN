// NodeL2SeLow.c
// The SeLow backend of the L2 adapter (NodeL2.h; CORE-S3-2, #72): the fallback where XDP is not installed or cannot bind
// (ADR-0022 amendment of 2026-10-15, ADR-0002 amendment of 2026-10-21). SeLow is the NDIS protocol driver of the Local
// Bridge (ADR-0013), which ranz install puts on an x64 machine (ONE-3, #312) and which binds to every Ethernet adapter, the
// KM-TEST ones among them. The backend opens the device of the adapter (\\.\SELOW_A_{GUID}) through SeLowUser and moves
// the frames through its exchange buffers, up to SL_MAX_PACKET_EXCHANGE frames a call each way: the drain thread reads
// what the host sends once the driver signals its event, straight from the buffer into the capture ring of the adapter
// without allocating, and the injector writes the frames for the host. The SeLow-vs-XDP benchmark measured about 70 kpps
// of RX inject on this path (ADR-0022 amendment of 2026-10-15), which is why XDP comes first.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "NodeL2.h"
#include "SeLowUser.h"

// ms that the drain thread waits for the event of the driver at a time, so that it sees its halt
#define NODE_L2_SELOW_WAIT 100

// The state of the backend on one adapter (NODE_L2.BackendState)
typedef struct NODE_L2_SELOW {
	NODE_L2 *Adapter;
	SU_ADAPTER *Su;
	HANDLE StopEvent;
	HANDLE Thread;
} NODE_L2_SELOW;

// The drain thread: once the driver signals its event, read its queue until it is empty, each frame straight from the
// exchange buffer into the capture ring of the adapter
static DWORD WINAPI NodeL2SeLowDrain(void *param) {
	NODE_L2_SELOW *s = (NODE_L2_SELOW *)param;
	HANDLE events[2];

	events[0] = s->StopEvent;
	events[1] = s->Su->hEvent;

	while (true) {
		while (true) {
			if (SuGetPacketsFromDriver(s->Su) == false)
				return 0;

			UCHAR *buf = s->Su->GetBuffer;
			UINT num = SL_NUM_PACKET(buf);
			if (num > SL_MAX_PACKET_EXCHANGE)
				num = SL_MAX_PACKET_EXCHANGE;

			for (UINT i = 0; i < num; i++)
				NodeL2Capture(s->Adapter, (const UCHAR *)SL_ADDR_OF_PACKET(buf, i), SL_SIZE_OF_PACKET(buf, i));

			if (num != 0)
				NodeL2CaptureDone(s->Adapter);

			// An empty read: the driver's queue is empty, and it signals the event for the next frame
			if (num == 0 && SL_LEFT_FLAG(buf) == 0)
				break;
		}

		if (WaitForMultipleObjects(2, events, FALSE, NODE_L2_SELOW_WAIT) == WAIT_OBJECT_0)
			return 0;
	}
}

// Hand a batch to the host, on the injector thread: the frames into the exchange buffer, written to the driver whenever
// it holds SL_MAX_PACKET_EXCHANGE of them and once at the end. Returns how many the driver took.
static UINT NodeL2SeLowInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num) {
	NODE_L2_SELOW *s = (NODE_L2_SELOW *)a->BackendState;
	UINT count = 0;
	UINT taken = 0;

	if (s == NULL || s->Su->Halt)
		return 0;

	UCHAR *buf = s->Su->PutBuffer;

	for (UINT i = 0; i < num; i++) {
		if (sizes[i] < SL_MIN_PACKET_SIZE || sizes[i] > SL_MAX_PACKET_SIZE)
			continue;

		SL_SIZE_OF_PACKET(buf, count) = sizes[i];
		Copy(SL_ADDR_OF_PACKET(buf, count), frames[i], sizes[i]);
		count++;

		if (count == SL_MAX_PACKET_EXCHANGE) {
			SL_NUM_PACKET(buf) = count;
			if (SuPutPacketsToDriver(s->Su) == false)
				return taken;
			taken += count;
			count = 0;
		}
	}

	if (count != 0) {
		SL_NUM_PACKET(buf) = count;
		if (SuPutPacketsToDriver(s->Su))
			taken += count;
	}

	return taken;
}

// Whether the device of the adapter still answers: a read or write that failed halts it
static bool NodeL2SeLowHealthy(NODE_L2 *a) {
	NODE_L2_SELOW *s = (NODE_L2_SELOW *)a->BackendState;

	return (s != NULL && s->Su->Halt == false);
}

// Free the state of the backend once no thread runs on it
static void NodeL2SeLowRelease(NODE_L2_SELOW *s) {
	if (s->Su != NULL)
		SuCloseAdapter(s->Su);
	if (s->StopEvent != NULL)
		CloseHandle(s->StopEvent);

	Free(s);
}

// Stop: the drain thread ends within timeout ms, then the device of the adapter closes. SeLow writes synchronously, so
// nothing that was injected is outstanding. A drain thread that does not end in time keeps the state.
static bool NodeL2SeLowDetach(NODE_L2 *a, UINT timeout) {
	NODE_L2_SELOW *s = (NODE_L2_SELOW *)a->BackendState;

	if (s == NULL)
		return true;

	a->BackendState = NULL;

	SetEvent(s->StopEvent);
	if (WaitForSingleObject(s->Thread, timeout) != WAIT_OBJECT_0)
		return false;
	CloseHandle(s->Thread);

	NodeL2SeLowRelease(s);

	return true;
}

// Bind to the adapter: open its SeLow device, which exists while the SeLow protocol is bound to it, and start the drain
// thread
static bool NodeL2SeLowAttach(NODE_L2 *a, char *error, UINT error_size) {
	char id[MAX_SIZE];
	const GUID *g = &a->Guid;

	if (SuIsSupportedOs() == false) {
		StrCpy(error, error_size, "SeLow is not supported on this host");
		return false;
	}

	Format(id, sizeof(id), SL_ADAPTER_ID_PREFIX "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0], (UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);

	NODE_L2_SELOW *s = ZeroMalloc(sizeof(NODE_L2_SELOW));
	s->Adapter = a;
	s->Su = SuOpenAdapter(id);
	if (s->Su == NULL) {
		Format(error, error_size, "the SeLow device %s of the adapter cannot be opened (error %u): SeLow is not installed or not bound to it", id, (UINT)GetLastError());
		NodeL2SeLowRelease(s);
		return false;
	}

	s->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->Thread = (s->StopEvent != NULL ? CreateThread(NULL, 0, NodeL2SeLowDrain, s, 0, NULL) : NULL);
	if (s->Thread == NULL) {
		Format(error, error_size, "the drain thread could not start (error %u)", (UINT)GetLastError());
		NodeL2SeLowRelease(s);
		return false;
	}

	SetThreadPriority(s->Thread, THREAD_PRIORITY_HIGHEST);

	// SeLow hands over the frames of the adapter on one device, whatever queue they came in on
	InterlockedExchange(&a->DriverQueues, 1);
	a->BackendState = s;

	return true;
}

static const NODE_L2_BACKEND node_l2_selow = {"selow", NodeL2SeLowAttach, NodeL2SeLowInject, NodeL2SeLowHealthy, NodeL2SeLowDetach};

// The SeLow backend
const NODE_L2_BACKEND *NodeL2SeLowBackend() {
	return &node_l2_selow;
}
