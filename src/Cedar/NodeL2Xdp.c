// NodeL2Xdp.c
// The XDP backend of the L2 adapter (NodeL2.h; CORE-S3-2, #72): XDP for Windows 1.4, in generic mode, on a KM-TEST
// adapter (ADR-0018). Both directions go through the rule API and AF_XDP sockets, no eBPF (ADR-0018 amendment of
// 2026-10-13, ADR-0022):
// - TX inspect: XDP hands each frame that the host sends out of the adapter to a queue of the hook {L2, TX, INSPECT},
//   chosen by the RSS hash of the frame, and a KM-TEST adapter reports receive queues for RSS. XDP passes the frames of a
//   queue without a program on to the adapter, where nothing captures them, so the backend binds every queue that the
//   adapter has (NodeL2XdpQueues, up to NODE_L2_XDP_MAX_QUEUES). Each queue has an AF_XDP socket bound for RX, a program
//   that redirects every frame of the queue to it, and a drain thread of its own, which takes the frames of the RX ring
//   in batches, copies each into the capture ring of the adapter (NodeL2Capture) and gives the UMEM chunks back to the
//   fill ring in one go. A drain thread waits for nothing but its ring (XskNotifySocket), takes no lock, allocates
//   nothing and does no other I/O, so no socket backs up into the senders of the host (#72, risk R1).
// - RX inject: one more socket, bound for TX on {L2, RX, INJECT} of queue 0, needs no program. The injector of the
//   adapter hands it batches: free UMEM chunks are filled, the descriptors reserved and submitted in bulk, the socket
//   poked once per batch when XDP asks for it, and the completions recycled in bulk (ADR-0022 amendment of 2026-10-19).
// - The health check reads the statistics of the sockets of TX inspect, the frames that XDP dropped or cut short before
//   a drain thread took them, into the counters of the adapter.
// The API is the header-only one of XDP_API_VERSION 3 from the pinned SDK package (src/Cedar/CMakeLists.txt): it opens
// the XDP driver with NtCreateFile of ntdll, so nothing of the package ships, and the runtime is the one that ranz
// install puts on the machine (ONE-3, #312). Where the runtime is missing or cannot bind, XskCreate, XskBind or
// XdpCreateProgram fails and the adapter takes the next backend, SeLow. The code follows the xskfwd sample of
// microsoft/xdp-for-windows (release/1.4) and the spike of ADR-0018.

// The XDP headers come first: they include windows.h without the NTSTATUS codes of winnt.h, which ntstatus.h defines
#include <xdpapi.h>
#include <afxdp_helper.h>

#include "NodeL2.h"

#include <stdio.h>

// The XDP headers define their functions inline, and C gives an inline function no external definition of its own.
// Declaring the ones that this file reaches extern makes this file hold the one external definition of each (C17
// 6.7.4), so that a build without inlining (Debug) links them too. No other file includes the XDP headers.
extern XDP_STATUS _XdpCloseHandle(HANDLE Handle);
extern XDP_STATUS _XdpConvertNtStatusToXdpStatus(NTSTATUS Status);
extern XDP_STATUS _XdpCreateEvent(HANDLE *EventHandle);
extern XDP_STATUS _XdpWaitInfinite(HANDLE *EventHandle);
extern XDP_STATUS _XdpSetFileCompletionModes(HANDLE Handle, UCHAR Flags);
extern VOID *_XdpInitializeEaVersion(XDP_OBJECT_TYPE ObjectType, UINT32 ApiVersion, VOID *EaBuffer, ULONG EaLength);
extern VOID *_XdpInitializeEa(XDP_OBJECT_TYPE ObjectType, VOID *EaBuffer, ULONG EaLength);
extern XDP_STATUS _XdpOpenDevice(HANDLE *Handle, ULONG Disposition, VOID *EaBuffer, ULONG EaLength, const WCHAR *DeviceNameStr);
extern XDP_STATUS _XdpOpenObjectType(HANDLE *Handle, ULONG Disposition, VOID *EaBuffer, ULONG EaLength, XDP_OBJECT_TYPE ObjectType);
extern XDP_STATUS _XdpIoctl(HANDLE XdpHandle, ULONG Operation, VOID *InBuffer, ULONG InBufferSize, VOID *OutBuffer, ULONG OutputBufferSize, ULONG *BytesReturned, XDP_OVERLAPPED *Overlapped, BOOLEAN MayPend);
extern const WCHAR *_XdpObjectTypeDeviceName(XDP_OBJECT_TYPE ObjectType);
extern XDP_STATUS _XskCreateVersion(HANDLE *Socket, UINT32 ApiVersion);
extern VOID XskRingInitialize(XSK_RING *Ring, const XSK_RING_INFO *RingInfo);
extern VOID *XskRingGetElement(const XSK_RING *Ring, UINT32 Index);
extern UINT32 XskRingGetFlags(const XSK_RING *Ring);
extern UINT32 XskRingConsumerReserve(XSK_RING *Ring, UINT32 MaxCount, UINT32 *Index);
extern VOID XskRingConsumerRelease(XSK_RING *Ring, UINT32 Count);
extern UINT32 XskRingProducerReserve(XSK_RING *Ring, UINT32 MaxCount, UINT32 *Index);
extern VOID XskRingProducerSubmit(XSK_RING *Ring, UINT32 Count);
extern BOOLEAN XskRingError(const XSK_RING *Ring);
extern BOOLEAN XskRingProducerNeedPoke(const XSK_RING *Ring);

// Bytes of a UMEM chunk: one frame of NODE_L2_MAX_FRAME bytes at most
#define NODE_L2_XDP_CHUNK 2048
// Entries of each AF_XDP ring, and chunks of each UMEM, without NODE_L2_CONFIG.BackendRing: the socket of RX inject has
// NODE_L2_XDP_RING, and the sockets of TX inspect share NODE_L2_XDP_CHUNKS, from NODE_L2_XDP_MIN_RING to
// NODE_L2_XDP_RING each
#define NODE_L2_XDP_RING     2048
#define NODE_L2_XDP_CHUNKS   8192
#define NODE_L2_XDP_MIN_RING 256
// Entries of the rings of a socket that NodeL2XdpQueues opens to see whether a queue binds
#define NODE_L2_XDP_PROBE_RING 64
// Frames that a drain thread takes from its RX ring at once
#define NODE_L2_XDP_BATCH 256
// ms that a drain thread waits on its RX ring at a time, so that it sees its halt
#define NODE_L2_XDP_WAIT 50
// ms that an injection waits at most for completions when no chunk is free
#define NODE_L2_XDP_FREE_WAIT 1

typedef struct NODE_L2_XDP NODE_L2_XDP;

// One AF_XDP socket with its UMEM and its two rings: RX and fill, or TX and completion
typedef struct NODE_L2_XSK {
	HANDLE Socket;
	UCHAR *Umem;
	UINT NumChunks;
	XSK_RING Ring;
	XSK_RING Other;
} NODE_L2_XSK;

// One queue of TX inspect: its socket, the program that redirects the frames of the queue to it, and its drain thread
typedef struct NODE_L2_XDP_QUEUE {
	NODE_L2_XDP *Xdp;
	NODE_L2_XSK Rx;
	HANDLE Program;
	HANDLE Thread;
	// Written by the drain thread only: the frames that it took, and the waits on its ring that XDP refused, with the
	// error of the last
	volatile LONG64 Frames;
	volatile LONG64 WaitFailures;
	volatile LONG WaitError;
} NODE_L2_XDP_QUEUE;

// The state of the backend on one adapter (NODE_L2.BackendState)
struct NODE_L2_XDP {
	NODE_L2 *Adapter;
	// TX inspect: one entry for each queue of the hook, and the halt of their drain threads
	NODE_L2_XDP_QUEUE *Queues;
	UINT NumQueues;
	volatile LONG Halt;
	// What the health check put into the counters of the adapter so far, on the injector thread
	UINT64 ReportedDrops;
	UINT64 ReportedWaitFailures;
	// RX inject, on the injector thread only: the socket, the chunks of its UMEM that no descriptor holds (a stack), the
	// descriptors submitted and completed so far, and when the completions last moved
	UINT RingSize;
	NODE_L2_XSK Tx;
	UINT64 *Free;
	UINT NumFree;
	UINT64 Submitted;
	UINT64 Completed;
	UINT64 LastProgress;
};

// Open an AF_XDP socket on the hook of queue queue of the interface if_index, for RX (rx) or for TX, with a UMEM of ring
// chunks and rings of ring entries, and activate it. step names what failed.
static HRESULT NodeL2XdpOpen(NODE_L2_XSK *s, UINT if_index, UINT queue, const XDP_HOOK_ID *hook, bool rx, UINT ring, const char **step) {
	XSK_UMEM_REG reg;
	XSK_RING_INFO_SET info;
	UINT32 size = ring;
	UINT32 len = sizeof(info);
	HRESULT hr;

	s->NumChunks = ring;
	s->Umem = VirtualAlloc(NULL, (SIZE_T)ring * NODE_L2_XDP_CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	*step = "the UMEM";
	if (s->Umem == NULL)
		return E_OUTOFMEMORY;

	*step = "XskCreate";
	hr = XskCreate(&s->Socket);
	if (FAILED(hr))
		return hr;

	ZeroMemory(&reg, sizeof(reg));
	reg.TotalSize = (UINT64)ring * NODE_L2_XDP_CHUNK;
	reg.ChunkSize = NODE_L2_XDP_CHUNK;
	reg.Address = s->Umem;
	*step = "the UMEM registration";
	hr = XskSetSockopt(s->Socket, XSK_SOCKOPT_UMEM_REG, &reg, sizeof(reg));
	if (FAILED(hr))
		return hr;

	*step = "the hook";
	hr = XskSetSockopt(s->Socket, rx ? XSK_SOCKOPT_RX_HOOK_ID : XSK_SOCKOPT_TX_HOOK_ID, hook, sizeof(*hook));
	if (FAILED(hr))
		return hr;

	*step = "XskBind";
	hr = XskBind(s->Socket, if_index, queue, (XSK_BIND_FLAGS)((rx ? XSK_BIND_FLAG_RX : XSK_BIND_FLAG_TX) | XSK_BIND_FLAG_GENERIC));
	if (FAILED(hr))
		return hr;

	*step = "the ring sizes";
	hr = XskSetSockopt(s->Socket, rx ? XSK_SOCKOPT_RX_RING_SIZE : XSK_SOCKOPT_TX_RING_SIZE, &size, sizeof(size));
	if (SUCCEEDED(hr))
		hr = XskSetSockopt(s->Socket, rx ? XSK_SOCKOPT_RX_FILL_RING_SIZE : XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &size, sizeof(size));
	if (FAILED(hr))
		return hr;

	*step = "XskActivate";
	hr = XskActivate(s->Socket, XSK_ACTIVATE_FLAG_NONE);
	if (FAILED(hr))
		return hr;

	*step = "the ring information";
	ZeroMemory(&info, sizeof(info));
	hr = XskGetSockopt(s->Socket, XSK_SOCKOPT_RING_INFO, &info, &len);
	if (FAILED(hr))
		return hr;

	XskRingInitialize(&s->Ring, rx ? &info.Rx : &info.Tx);
	XskRingInitialize(&s->Other, rx ? &info.Fill : &info.Completion);

	return S_OK;
}

// Close a socket and free its UMEM
static void NodeL2XdpClose(NODE_L2_XSK *s) {
	if (s->Socket != NULL)
		CloseHandle(s->Socket);
	if (s->Umem != NULL)
		VirtualFree(s->Umem, 0, MEM_RELEASE);

	s->Socket = NULL;
	s->Umem = NULL;
}

// Free the state of the backend once no thread runs on it
static void NodeL2XdpRelease(NODE_L2_XDP *x) {
	for (UINT i = 0; x->Queues != NULL && i < x->NumQueues; i++) {
		if (x->Queues[i].Program != NULL)
			CloseHandle(x->Queues[i].Program);
		NodeL2XdpClose(&x->Queues[i].Rx);
	}

	NodeL2XdpClose(&x->Tx);

	if (x->Queues != NULL)
		HeapFree(GetProcessHeap(), 0, x->Queues);
	if (x->Free != NULL)
		HeapFree(GetProcessHeap(), 0, x->Free);

	HeapFree(GetProcessHeap(), 0, x);
}

// Halt the drain threads and join them, within timeout ms for all of them; false when one did not end in time
static bool NodeL2XdpJoin(NODE_L2_XDP *x, UINT timeout) {
	UINT64 end = GetTickCount64() + timeout;

	InterlockedExchange(&x->Halt, 1);
	for (UINT i = 0; i < x->NumQueues; i++) {
		NODE_L2_XDP_QUEUE *q = &x->Queues[i];
		UINT64 now = GetTickCount64();

		if (q->Thread == NULL)
			continue;
		if (WaitForSingleObject(q->Thread, (DWORD)(now < end ? end - now : 0)) != WAIT_OBJECT_0)
			return false;
		CloseHandle(q->Thread);
		q->Thread = NULL;
	}

	return true;
}

// The drain thread of a queue of TX inspect: the frames of its RX ring, NODE_L2_XDP_BATCH at a time, into the capture
// ring of the adapter, and their chunks back to the fill ring in one go. Between batches it waits on the RX ring, and
// pokes the fill ring when XDP asks for it.
static DWORD WINAPI NodeL2XdpDrain(void *param) {
	NODE_L2_XDP_QUEUE *q = (NODE_L2_XDP_QUEUE *)param;
	NODE_L2_XDP *x = q->Xdp;
	UINT64 bases[NODE_L2_XDP_BATCH];

	while (ReadAcquire(&x->Halt) == 0) {
		XSK_NOTIFY_RESULT_FLAGS result = XSK_NOTIFY_RESULT_FLAG_NONE;
		UINT32 index = 0;
		UINT32 num = XskRingConsumerReserve(&q->Rx.Ring, NODE_L2_XDP_BATCH, &index);

		if (num == 0) {
			XSK_NOTIFY_FLAGS flags = XSK_NOTIFY_FLAG_WAIT_RX;

			if (XskRingProducerNeedPoke(&q->Rx.Other))
				flags = (XSK_NOTIFY_FLAGS)(flags | XSK_NOTIFY_FLAG_POKE_RX);

			HRESULT hr = XskNotifySocket(q->Rx.Socket, flags, NODE_L2_XDP_WAIT, &result);
			// A wait that XDP refuses is counted, and the ring is polled once a millisecond instead. A socket that XDP took
			// away (the interface went) flags its rings with an error, which the health check sees.
			if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_TIMEOUT) && hr != HRESULT_FROM_WIN32(WAIT_TIMEOUT)) {
				InterlockedExchange(&q->WaitError, (LONG)hr);
				InterlockedIncrement64(&q->WaitFailures);
				Sleep(1);
			}
			continue;
		}

		for (UINT32 i = 0; i < num; i++) {
			XSK_BUFFER_DESCRIPTOR *d = (XSK_BUFFER_DESCRIPTOR *)XskRingGetElement(&q->Rx.Ring, index + i);

			NodeL2Capture(x->Adapter, q->Rx.Umem + d->Address.BaseAddress + d->Address.Offset, d->Length);
			bases[i] = d->Address.BaseAddress;
		}
		XskRingConsumerRelease(&q->Rx.Ring, num);

		UINT32 fill = 0;
		UINT32 got = XskRingProducerReserve(&q->Rx.Other, num, &fill);
		for (UINT32 i = 0; i < got; i++)
			*(UINT64 *)XskRingGetElement(&q->Rx.Other, fill + i) = bases[i];
		XskRingProducerSubmit(&q->Rx.Other, got);
		if (XskRingProducerNeedPoke(&q->Rx.Other))
			XskNotifySocket(q->Rx.Socket, XSK_NOTIFY_FLAG_POKE_RX, 0, &result);

		InterlockedAdd64(&q->Frames, (LONG64)num);
		NodeL2CaptureDone(x->Adapter);
	}

	return 0;
}

// What the queues of TX inspect tell, on the injector thread, into the counters of the adapter: the queues that frames
// came in on, the frames that XDP dropped or cut short before a drain thread took them (the statistics of the sockets),
// and the waits that XDP refused, with the error of the last
static void NodeL2XdpReport(NODE_L2_XDP *x) {
	NODE_L2 *a = x->Adapter;
	UINT64 drops = 0;
	UINT64 failures = 0;
	UINT busy = 0;

	for (UINT i = 0; i < x->NumQueues; i++) {
		NODE_L2_XDP_QUEUE *q = &x->Queues[i];
		XSK_STATISTICS stats;
		UINT32 len = sizeof(stats);

		ZeroMemory(&stats, sizeof(stats));
		if (SUCCEEDED(XskGetSockopt(q->Rx.Socket, XSK_SOCKOPT_STATISTICS, &stats, &len)))
			drops += stats.RxDropped + stats.RxTruncated;

		if (ReadAcquire64(&q->WaitFailures) != 0) {
			failures += (UINT64)ReadAcquire64(&q->WaitFailures);
			InterlockedExchange(&a->DriverWaitError, ReadAcquire(&q->WaitError));
		}
		if (ReadAcquire64(&q->Frames) != 0)
			busy++;
	}

	InterlockedExchange(&a->DriverBusyQueues, (LONG)busy);
	if (drops > x->ReportedDrops) {
		InterlockedAdd64(&a->DriverDrops, (LONG64)(drops - x->ReportedDrops));
		x->ReportedDrops = drops;
	}
	if (failures > x->ReportedWaitFailures) {
		InterlockedAdd64(&a->DriverWaitFailures, (LONG64)(failures - x->ReportedWaitFailures));
		x->ReportedWaitFailures = failures;
	}
}

// The completions of the TX ring, in one go: their chunks are free again
static void NodeL2XdpComplete(NODE_L2_XDP *x) {
	UINT32 index = 0;
	UINT32 num = XskRingConsumerReserve(&x->Tx.Other, x->RingSize, &index);

	if (num == 0)
		return;

	for (UINT32 i = 0; i < num; i++)
		x->Free[x->NumFree++] = *(UINT64 *)XskRingGetElement(&x->Tx.Other, index + i);
	XskRingConsumerRelease(&x->Tx.Other, num);

	x->Completed += num;
	x->LastProgress = GetTickCount64();
}

// RX inject of a batch, on the injector thread: the frames into free chunks, their descriptors reserved and submitted at
// once, and one poke when XDP asks for it. When the chunks run short, it waits NODE_L2_XDP_FREE_WAIT ms at most for
// completions; the frames that find no chunk then are refused. Returns how many it took.
static UINT NodeL2XdpInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num) {
	NODE_L2_XDP *x = (NODE_L2_XDP *)a->BackendState;
	XSK_NOTIFY_RESULT_FLAGS result = XSK_NOTIFY_RESULT_FLAG_NONE;
	UINT32 index = 0;

	if (x == NULL || num == 0)
		return 0;

	NodeL2XdpComplete(x);
	if (x->NumFree < num) {
		XskNotifySocket(x->Tx.Socket, (XSK_NOTIFY_FLAGS)(XSK_NOTIFY_FLAG_POKE_TX | XSK_NOTIFY_FLAG_WAIT_TX), NODE_L2_XDP_FREE_WAIT, &result);
		NodeL2XdpComplete(x);
	}

	UINT32 want = (num < x->NumFree ? num : x->NumFree);
	UINT32 got = (want != 0 ? XskRingProducerReserve(&x->Tx.Ring, want, &index) : 0);

	for (UINT32 i = 0; i < got; i++) {
		XSK_BUFFER_DESCRIPTOR *d = (XSK_BUFFER_DESCRIPTOR *)XskRingGetElement(&x->Tx.Ring, index + i);
		UINT64 chunk = x->Free[--x->NumFree];

		CopyMemory(x->Tx.Umem + chunk, frames[i], sizes[i]);
		d->Address.AddressAndOffset = chunk;
		d->Length = sizes[i];
		d->Reserved = 0;
	}

	if (got != 0) {
		if (x->Submitted == x->Completed)
			x->LastProgress = GetTickCount64();
		XskRingProducerSubmit(&x->Tx.Ring, got);
		x->Submitted += got;
		if (XskRingProducerNeedPoke(&x->Tx.Ring))
			XskNotifySocket(x->Tx.Socket, XSK_NOTIFY_FLAG_POKE_TX, 0, &result);
	}

	return got;
}

// Whether the binding works, on the injector thread: no ring of any socket has an error (XDP sets one when the interface
// goes or XDP lets go of it), and injected frames do not wait longer than NODE_L2_STALL ms for their completion. It
// reports what the queues of TX inspect tell first.
static bool NodeL2XdpHealthy(NODE_L2 *a) {
	NODE_L2_XDP *x = (NODE_L2_XDP *)a->BackendState;

	if (x == NULL)
		return false;

	NodeL2XdpReport(x);

	for (UINT i = 0; i < x->NumQueues; i++)
		if (XskRingError(&x->Queues[i].Rx.Ring) || XskRingError(&x->Queues[i].Rx.Other))
			return false;

	if (XskRingError(&x->Tx.Ring) || XskRingError(&x->Tx.Other))
		return false;

	NodeL2XdpComplete(x);

	return (x->Submitted == x->Completed || GetTickCount64() - x->LastProgress <= NODE_L2_STALL);
}

// Stop, within timeout ms for each step (#72, risk R2): what was injected completes first, then the programs go, so no
// frame is redirected any more, then the drain threads end and the sockets close. A drain thread that does not end in
// time keeps the state, which is then left to it.
static bool NodeL2XdpDetach(NODE_L2 *a, UINT timeout) {
	NODE_L2_XDP *x = (NODE_L2_XDP *)a->BackendState;
	XSK_NOTIFY_RESULT_FLAGS result = XSK_NOTIFY_RESULT_FLAG_NONE;
	bool ok = true;

	if (x == NULL)
		return true;

	a->BackendState = NULL;

	UINT64 end = GetTickCount64() + timeout;
	while (true) {
		NodeL2XdpComplete(x);
		if (x->Submitted == x->Completed)
			break;
		if (GetTickCount64() >= end) {
			ok = false;
			break;
		}
		XskNotifySocket(x->Tx.Socket, (XSK_NOTIFY_FLAGS)(XSK_NOTIFY_FLAG_POKE_TX | XSK_NOTIFY_FLAG_WAIT_TX), NODE_L2_XDP_WAIT, &result);
	}

	for (UINT i = 0; i < x->NumQueues; i++) {
		if (x->Queues[i].Program != NULL) {
			CloseHandle(x->Queues[i].Program);
			x->Queues[i].Program = NULL;
		}
	}

	if (NodeL2XdpJoin(x, timeout) == false)
		return false;

	NodeL2XdpReport(x);
	NodeL2XdpRelease(x);

	return ok;
}

// Bind to the adapter: on each queue of TX inspect a socket with its fill ring full and the program that redirects every
// frame of the queue to it, then the socket of RX inject, and last the drain threads
static bool NodeL2XdpAttach(NODE_L2 *a, char *error, UINT error_size) {
	XDP_HOOK_ID inspect = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
	XDP_HOOK_ID inject = {XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INJECT};
	char why[256];
	const char *step = "";
	UINT32 index = 0;
	HRESULT hr;

	UINT queues = NodeL2XdpQueues(a->IfIndex, NODE_L2_XDP_MAX_QUEUES, why, sizeof(why));
	if (queues == 0) {
		snprintf(error, error_size, "TX inspect: %s", why);
		return false;
	}

	NODE_L2_XDP *x = (NODE_L2_XDP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NODE_L2_XDP));
	if (x == NULL) {
		snprintf(error, error_size, "no memory");
		return false;
	}
	x->Adapter = a;
	x->RingSize = (a->BackendRing != 0 ? a->BackendRing : NODE_L2_XDP_RING);
	x->Queues = (NODE_L2_XDP_QUEUE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NODE_L2_XDP_QUEUE) * queues);
	if (x->Queues == NULL) {
		snprintf(error, error_size, "no memory");
		NodeL2XdpRelease(x);
		return false;
	}
	x->NumQueues = queues;

	// The rings of TX inspect: NODE_L2_CONFIG.BackendRing each, or a share of NODE_L2_XDP_CHUNKS
	UINT ring = a->BackendRing;
	if (ring == 0) {
		ring = NODE_L2_XDP_RING;
		while (ring > NODE_L2_XDP_MIN_RING && ring * queues > NODE_L2_XDP_CHUNKS)
			ring /= 2;
	}

	for (UINT i = 0; i < queues; i++) {
		NODE_L2_XDP_QUEUE *q = &x->Queues[i];
		XDP_RULE rule;

		q->Xdp = x;
		hr = NodeL2XdpOpen(&q->Rx, a->IfIndex, i, &inspect, true, ring, &step);
		if (FAILED(hr)) {
			snprintf(error, error_size, "TX inspect, queue %u: %s failed (0x%08X)", i, step, (UINT)hr);
			NodeL2XdpRelease(x);
			return false;
		}

		// Every chunk of the UMEM in the fill ring, for the frames to come
		UINT32 got = XskRingProducerReserve(&q->Rx.Other, q->Rx.NumChunks, &index);
		for (UINT32 j = 0; j < got; j++)
			*(UINT64 *)XskRingGetElement(&q->Rx.Other, index + j) = (UINT64)j * NODE_L2_XDP_CHUNK;
		XskRingProducerSubmit(&q->Rx.Other, got);

		ZeroMemory(&rule, sizeof(rule));
		rule.Match = XDP_MATCH_ALL;
		rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
		rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
		rule.Redirect.Target = q->Rx.Socket;
		hr = XdpCreateProgram(a->IfIndex, &inspect, i, XDP_CREATE_PROGRAM_FLAG_GENERIC, &rule, 1, &q->Program);
		if (FAILED(hr)) {
			snprintf(error, error_size, "TX inspect, queue %u: XdpCreateProgram failed (0x%08X)", i, (UINT)hr);
			q->Program = NULL;
			NodeL2XdpRelease(x);
			return false;
		}
	}

	hr = NodeL2XdpOpen(&x->Tx, a->IfIndex, 0, &inject, false, x->RingSize, &step);
	if (FAILED(hr)) {
		snprintf(error, error_size, "RX inject: %s failed (0x%08X)", step, (UINT)hr);
		NodeL2XdpRelease(x);
		return false;
	}

	x->Free = (UINT64 *)HeapAlloc(GetProcessHeap(), 0, sizeof(UINT64) * x->Tx.NumChunks);
	if (x->Free == NULL) {
		snprintf(error, error_size, "no memory");
		NodeL2XdpRelease(x);
		return false;
	}
	for (UINT i = 0; i < x->Tx.NumChunks; i++)
		x->Free[x->NumFree++] = (UINT64)i * NODE_L2_XDP_CHUNK;
	x->LastProgress = GetTickCount64();

	// The drain threads run ahead of the injector, as the senders of the host do
	for (UINT i = 0; i < queues; i++) {
		NODE_L2_XDP_QUEUE *q = &x->Queues[i];

		q->Thread = CreateThread(NULL, 0, NodeL2XdpDrain, q, 0, NULL);
		if (q->Thread == NULL) {
			snprintf(error, error_size, "the drain thread of queue %u could not start (error %u)", i, (UINT)GetLastError());
			if (NodeL2XdpJoin(x, NODE_L2_STOP_WAIT))
				NodeL2XdpRelease(x);
			return false;
		}
		SetThreadPriority(q->Thread, THREAD_PRIORITY_HIGHEST);
	}

	InterlockedExchange(&a->DriverQueues, (LONG)queues);
	InterlockedExchange(&a->DriverBusyQueues, 0);
	a->BackendState = x;

	return true;
}

static const NODE_L2_BACKEND node_l2_xdp = {"xdp", NodeL2XdpAttach, NodeL2XdpInject, NodeL2XdpHealthy, NodeL2XdpDetach};

// The XDP backend
const NODE_L2_BACKEND *NodeL2XdpBackend() {
	return &node_l2_xdp;
}

// How many queues of the TX inspect hook of the interface if_index an AF_XDP socket binds to, from queue 0 on, up to max:
// XDP has one for each receive queue that the adapter reports for RSS, and one for an adapter without RSS (#72,
// multi-queue). error gets why the first queue that did not bind failed.
UINT NodeL2XdpQueues(UINT if_index, UINT max, char *error, UINT error_size) {
	XDP_HOOK_ID inspect = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
	UINT num = 0;

	if (error != NULL && error_size != 0)
		error[0] = 0;

	for (; num < max; num++) {
		NODE_L2_XSK s;
		const char *step = "";

		ZeroMemory(&s, sizeof(s));
		HRESULT hr = NodeL2XdpOpen(&s, if_index, num, &inspect, true, NODE_L2_XDP_PROBE_RING, &step);
		NodeL2XdpClose(&s);

		if (FAILED(hr)) {
			if (error != NULL)
				snprintf(error, error_size, "queue %u: %s failed (0x%08X)", num, step, (UINT)hr);
			break;
		}
	}

	return num;
}
