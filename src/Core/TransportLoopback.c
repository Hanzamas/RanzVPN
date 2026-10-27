// TransportLoopback.c
// The loopback transport: streams in memory between a dialler and a listener of the same process,
// for the vpntest harness and the nodes it runs in one process (CORE-F4, #64). Each loopback
// transport is a network of its own, whose listeners its dials find by their address. A stream is
// a pair of byte rings, one per direction, which its two ends share; the last end to close frees
// it. A dial waits the dial delay of its transport first, and a cancel ends that wait. A bound
// transport gives each stream a random channel binding, which both ends of the stream give.

#include "Core/Transport.h"

#include <string.h>

#define TRANSPORT_LOOPBACK_RING    262144 // Bytes that one direction of a stream holds before a write waits
#define TRANSPORT_LOOPBACK_BACKLOG 16     // Dialled streams that a listener holds before a dial fails

// One direction of a stream: a ring of bytes
typedef struct LOOPBACK_RING {
	UCHAR *Buf;  // TRANSPORT_LOOPBACK_RING bytes
	UINT Start;  // The first byte not read yet
	UINT Used;   // The bytes not read yet
	bool Closed; // The writer closed its end: the reader takes the bytes left, then the end
	bool Gone;   // The reader closed its end: what the writer writes goes nowhere, as on TCP before the reset
} LOOPBACK_RING;

// A stream, which its two ends share
typedef struct LOOPBACK_LINK {
	SRWLOCK Lock;                       // The rings
	CONDITION_VARIABLE Changed;         // Bytes came or went, or the stream closed
	LOOPBACK_RING Ring[2];              // Ring[0] from the dialler to the listener's end, Ring[1] back
	volatile LONG NumEnds;              // The ends not closed yet: the last one frees the link
	UINT BindingSize;                   // A bound transport: the size of the binding of the stream ...
	UCHAR Binding[NOISE_EXPORTER_SIZE]; // ... and the random binding
	// What the two ends tell of the other (TransportRemote; AUD1-DT-11, #459): the dialler's end the address that it
	// dialled, the listener's end the source that the dial came from, "" for none
	char Remote[2][TRANSPORT_LOOPBACK_REMOTE];
} LOOPBACK_LINK;

// One end of a stream: the stream object of the transport
typedef struct LOOPBACK_END {
	LOOPBACK_LINK *Link; // The stream
	UINT Side;           // 0: the dialler's end, which writes Ring[0] and reads Ring[1]; 1: the listener's end
} LOOPBACK_END;

typedef struct LOOPBACK_NET LOOPBACK_NET;

// A listener: the listener object of the transport
typedef struct LOOPBACK_LISTENER {
	LOOPBACK_NET *Net;                               // Its transport
	char Address[TRANSPORT_ADDRESS_SIZE];            // The address it listens on
	LOOPBACK_END *Queue[TRANSPORT_LOOPBACK_BACKLOG]; // The listener's ends of the streams dialled and not accepted, oldest first
	UINT NumQueued;                                  // ... their number
	bool Closed;                                     // CloseListener runs: an Accept returns, a dial finds no listener
	UINT NumWaiting;                                 // The Accept calls that wait
	struct LOOPBACK_LISTENER *Next;                  // The next listener of the transport
} LOOPBACK_LISTENER;

// The state of a loopback transport, its Param
struct LOOPBACK_NET {
	SRWLOCK Lock;                           // The listeners and their queues
	CONDITION_VARIABLE Changed;             // A stream was dialled, an Accept returned, or a listener closed
	LOOPBACK_LISTENER *Listeners;           // The listeners
	UINT DialDelay;                         // ms that a dial waits first
	bool Bound;                             // Each stream has a random channel binding
	char Source[TRANSPORT_LOOPBACK_REMOTE]; // The source of the streams dialled from now on (TransportLoopbackSetSource)
};

static void *TransportLoopbackAlloc(UINT size) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

// Wipe and free size bytes at p, which may be NULL
static void TransportLoopbackRelease(void *p, UINT size) {
	if (p == NULL)
		return;

	SecureZeroMemory(p, size);
	HeapFree(GetProcessHeap(), 0, p);
}

static void TransportLoopbackFreeLink(LOOPBACK_LINK *k) {
	if (k == NULL)
		return;

	TransportLoopbackRelease(k->Ring[0].Buf, TRANSPORT_LOOPBACK_RING);
	TransportLoopbackRelease(k->Ring[1].Buf, TRANSPORT_LOOPBACK_RING);
	TransportLoopbackRelease(k, sizeof(LOOPBACK_LINK));
}

// A new stream and its two ends: ends[0] the dialler's, ends[1] the listener's
static bool TransportLoopbackNewLink(LOOPBACK_NET *net, LOOPBACK_END **ends) {
	LOOPBACK_LINK *k = (LOOPBACK_LINK *)TransportLoopbackAlloc(sizeof(LOOPBACK_LINK));

	ends[0] = (LOOPBACK_END *)TransportLoopbackAlloc(sizeof(LOOPBACK_END));
	ends[1] = (LOOPBACK_END *)TransportLoopbackAlloc(sizeof(LOOPBACK_END));
	if (k != NULL) {
		k->Ring[0].Buf = (UCHAR *)TransportLoopbackAlloc(TRANSPORT_LOOPBACK_RING);
		k->Ring[1].Buf = (UCHAR *)TransportLoopbackAlloc(TRANSPORT_LOOPBACK_RING);
	}

	bool ok = (k != NULL && ends[0] != NULL && ends[1] != NULL && k->Ring[0].Buf != NULL && k->Ring[1].Buf != NULL);
	if (ok && net->Bound) {
		ok = CryptoRandom(k->Binding, NOISE_EXPORTER_SIZE);
		k->BindingSize = NOISE_EXPORTER_SIZE;
	}
	if (ok == false) {
		TransportLoopbackFreeLink(k);
		TransportLoopbackRelease(ends[0], sizeof(LOOPBACK_END));
		TransportLoopbackRelease(ends[1], sizeof(LOOPBACK_END));
		ends[0] = NULL;
		ends[1] = NULL;
		return false;
	}

	InitializeSRWLock(&k->Lock);
	InitializeConditionVariable(&k->Changed);
	k->NumEnds = 2;
	ends[0]->Link = k;
	ends[0]->Side = 0;
	ends[1]->Link = k;
	ends[1]->Side = 1;

	return true;
}

// Take size bytes out of a ring that holds them
static void TransportLoopbackTake(LOOPBACK_RING *r, UCHAR *dst, UINT size) {
	UINT first = TRANSPORT_LOOPBACK_RING - r->Start;

	if (first > size)
		first = size;
	CopyMemory(dst, r->Buf + r->Start, first);
	CopyMemory(dst + first, r->Buf, size - first);
	SecureZeroMemory(r->Buf + r->Start, first);
	SecureZeroMemory(r->Buf, size - first);

	r->Start = (r->Start + size) % TRANSPORT_LOOPBACK_RING;
	r->Used -= size;
}

// Put size bytes into a ring that has the room for them
static void TransportLoopbackPut(LOOPBACK_RING *r, const UCHAR *src, UINT size) {
	UINT pos = (r->Start + r->Used) % TRANSPORT_LOOPBACK_RING;
	UINT first = TRANSPORT_LOOPBACK_RING - pos;

	if (first > size)
		first = size;
	CopyMemory(r->Buf + pos, src, first);
	CopyMemory(r->Buf, src + first, size - first);

	r->Used += size;
}

//
// The streams
//

static UINT TransportLoopbackRead(void *stream, void *buf, UINT size, UINT timeout) {
	LOOPBACK_END *e = (LOOPBACK_END *)stream;
	LOOPBACK_LINK *k = e->Link;
	LOOPBACK_RING *r = &k->Ring[1 - e->Side];
	UINT64 end = GetTickCount64() + timeout;
	UINT ret = TRANSPORT_LATER;

	AcquireSRWLockExclusive(&k->Lock);
	while (r->Used == 0 && r->Closed == false) {
		DWORD wait = INFINITE;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			if (now >= end)
				break;
			wait = (DWORD)(end - now);
		}
		SleepConditionVariableSRW(&k->Changed, &k->Lock, wait, 0);
	}

	if (r->Used != 0) {
		ret = (size < r->Used ? size : r->Used);
		TransportLoopbackTake(r, (UCHAR *)buf, ret);
		// Room for the writer
		WakeAllConditionVariable(&k->Changed);
	} else if (r->Closed) {
		ret = 0;
	}
	ReleaseSRWLockExclusive(&k->Lock);

	return ret;
}

static bool TransportLoopbackWrite(void *stream, const void *buf, UINT size) {
	LOOPBACK_END *e = (LOOPBACK_END *)stream;
	LOOPBACK_LINK *k = e->Link;
	LOOPBACK_RING *r = &k->Ring[e->Side];
	const UCHAR *p = (const UCHAR *)buf;

	AcquireSRWLockExclusive(&k->Lock);
	while (size != 0 && r->Gone == false) {
		// A full ring waits for the reader
		UINT room = TRANSPORT_LOOPBACK_RING - r->Used;
		if (room == 0) {
			SleepConditionVariableSRW(&k->Changed, &k->Lock, INFINITE, 0);
			continue;
		}

		UINT n = (size < room ? size : room);
		TransportLoopbackPut(r, p, n);
		p += n;
		size -= n;
		WakeAllConditionVariable(&k->Changed);
	}
	ReleaseSRWLockExclusive(&k->Lock);

	return true;
}

// Close an end: the other end reads the bytes left and then the end, and what it writes from now
// on goes nowhere, so a record that it sends while the close is under way does not hide the
// records before the close from it
static void TransportLoopbackClose(void *stream) {
	LOOPBACK_END *e = (LOOPBACK_END *)stream;

	if (e == NULL)
		return;

	LOOPBACK_LINK *k = e->Link;
	AcquireSRWLockExclusive(&k->Lock);
	k->Ring[e->Side].Closed = true;
	k->Ring[1 - e->Side].Gone = true;
	WakeAllConditionVariable(&k->Changed);
	ReleaseSRWLockExclusive(&k->Lock);

	// The last end frees the stream, once the other end's calls are over
	if (InterlockedDecrement(&k->NumEnds) == 0)
		TransportLoopbackFreeLink(k);
	TransportLoopbackRelease(e, sizeof(LOOPBACK_END));
}

// The address that the other end of a stream tells (AUD1-DT-11, #459): the address that the dialler dialled, the source that
// the dial came from; false when there is none
static bool TransportLoopbackRemote(void *stream, char *address, UINT size) {
	LOOPBACK_END *e = (LOOPBACK_END *)stream;
	const char *remote = e->Link->Remote[e->Side];
	size_t len = strnlen(remote, TRANSPORT_LOOPBACK_REMOTE);

	if (len == 0 || len >= size)
		return false;

	CopyMemory(address, remote, len + 1);
	return true;
}

static UINT TransportLoopbackBinding(void *stream, UCHAR *binding, UINT max, UINT *size) {
	LOOPBACK_LINK *k = ((LOOPBACK_END *)stream)->Link;

	*size = 0;
	if (k->BindingSize == 0 || k->BindingSize > max)
		return NOISE_BINDING_NONE;

	CopyMemory(binding, k->Binding, k->BindingSize);
	*size = k->BindingSize;

	return NOISE_BINDING_EXPORTER;
}

//
// The listeners
//

// The open listener on an address, under the lock of the transport
static LOOPBACK_LISTENER *TransportLoopbackFind(LOOPBACK_NET *net, const char *address) {
	for (LOOPBACK_LISTENER *l = net->Listeners; l != NULL; l = l->Next)
		if (l->Closed == false && strcmp(l->Address, address) == 0)
			return l;

	return NULL;
}

// Copy text into a remote field of TRANSPORT_LOOPBACK_REMOTE bytes, cut where it does not fit
static void TransportLoopbackSetText(char *dst, const char *text) {
	size_t len = strnlen(text, TRANSPORT_LOOPBACK_REMOTE - 1);

	CopyMemory(dst, text, len);
	dst[len] = 0;
}

static bool TransportLoopbackDial(void *param, const char *address, HANDLE cancel, void **stream) {
	LOOPBACK_NET *net = (LOOPBACK_NET *)param;
	LOOPBACK_END *ends[2];

	*stream = NULL;

	// The round trips of a real transport; a cancel ends the dial
	if (cancel != NULL) {
		if (WaitForSingleObject(cancel, net->DialDelay) != WAIT_TIMEOUT)
			return false;
	} else if (net->DialDelay != 0) {
		Sleep(net->DialDelay);
	}

	if (TransportLoopbackNewLink(net, ends) == false)
		return false;

	AcquireSRWLockExclusive(&net->Lock);
	LOOPBACK_LISTENER *l = TransportLoopbackFind(net, address);
	bool queued = (l != NULL && l->NumQueued < TRANSPORT_LOOPBACK_BACKLOG);
	if (queued) {
		// What each end tells of the other, before the listener's end can be accepted (AUD1-DT-11, #459)
		TransportLoopbackSetText(ends[0]->Link->Remote[0], address);
		TransportLoopbackSetText(ends[0]->Link->Remote[1], net->Source);
		l->Queue[l->NumQueued++] = ends[1];
		WakeAllConditionVariable(&net->Changed);
	}
	ReleaseSRWLockExclusive(&net->Lock);

	// No listener on the address, or one whose queue is full: nothing answers
	if (queued == false) {
		TransportLoopbackClose(ends[0]);
		TransportLoopbackClose(ends[1]);
		return false;
	}

	*stream = ends[0];
	return true;
}

static bool TransportLoopbackListen(void *param, const char *address, void **listener) {
	LOOPBACK_NET *net = (LOOPBACK_NET *)param;
	size_t size = strnlen(address, TRANSPORT_ADDRESS_SIZE);

	*listener = NULL;
	if (size == 0 || size >= TRANSPORT_ADDRESS_SIZE)
		return false;

	LOOPBACK_LISTENER *l = (LOOPBACK_LISTENER *)TransportLoopbackAlloc(sizeof(LOOPBACK_LISTENER));
	if (l == NULL)
		return false;
	l->Net = net;
	CopyMemory(l->Address, address, size);

	// One listener per address
	AcquireSRWLockExclusive(&net->Lock);
	bool taken = (TransportLoopbackFind(net, address) != NULL);
	if (taken == false) {
		l->Next = net->Listeners;
		net->Listeners = l;
	}
	ReleaseSRWLockExclusive(&net->Lock);

	if (taken) {
		TransportLoopbackRelease(l, sizeof(LOOPBACK_LISTENER));
		return false;
	}

	*listener = l;
	return true;
}

static bool TransportLoopbackAccept(void *listener, UINT timeout, void **stream) {
	LOOPBACK_LISTENER *l = (LOOPBACK_LISTENER *)listener;
	LOOPBACK_NET *net = l->Net;
	UINT64 end = GetTickCount64() + timeout;

	*stream = NULL;

	AcquireSRWLockExclusive(&net->Lock);
	l->NumWaiting++;
	while (l->NumQueued == 0 && l->Closed == false) {
		DWORD wait = INFINITE;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			if (now >= end)
				break;
			wait = (DWORD)(end - now);
		}
		SleepConditionVariableSRW(&net->Changed, &net->Lock, wait, 0);
	}

	if (l->NumQueued != 0 && l->Closed == false) {
		*stream = l->Queue[0];
		l->NumQueued--;
		MoveMemory(l->Queue, l->Queue + 1, sizeof(LOOPBACK_END *) * l->NumQueued);
	}

	// A CloseListener waits for the last Accept
	l->NumWaiting--;
	WakeAllConditionVariable(&net->Changed);
	ReleaseSRWLockExclusive(&net->Lock);

	return (*stream != NULL);
}

static void TransportLoopbackCloseListener(void *listener) {
	LOOPBACK_LISTENER *l = (LOOPBACK_LISTENER *)listener;
	LOOPBACK_NET *net = l->Net;

	AcquireSRWLockExclusive(&net->Lock);
	l->Closed = true;
	WakeAllConditionVariable(&net->Changed);
	while (l->NumWaiting != 0)
		SleepConditionVariableSRW(&net->Changed, &net->Lock, INFINITE, 0);

	for (LOOPBACK_LISTENER **p = &net->Listeners; *p != NULL; p = &(*p)->Next) {
		if (*p == l) {
			*p = l->Next;
			break;
		}
	}
	ReleaseSRWLockExclusive(&net->Lock);

	// The streams that nobody accepted: their diallers read the end
	for (UINT i = 0; i < l->NumQueued; i++)
		TransportLoopbackClose(l->Queue[i]);
	TransportLoopbackRelease(l, sizeof(LOOPBACK_LISTENER));
}

//
// The transport
//

TRANSPORT *TransportLoopbackNew(const char *name, UINT dial_delay, bool bound) {
	if (name == NULL)
		return NULL;

	size_t size = strnlen(name, TRANSPORT_NAME_SIZE);
	if (size == 0 || size >= TRANSPORT_NAME_SIZE)
		return NULL;

	TRANSPORT *t = (TRANSPORT *)TransportLoopbackAlloc(sizeof(TRANSPORT));
	LOOPBACK_NET *net = (LOOPBACK_NET *)TransportLoopbackAlloc(sizeof(LOOPBACK_NET));
	if (t == NULL || net == NULL) {
		TransportLoopbackRelease(t, sizeof(TRANSPORT));
		TransportLoopbackRelease(net, sizeof(LOOPBACK_NET));
		return NULL;
	}

	InitializeSRWLock(&net->Lock);
	InitializeConditionVariable(&net->Changed);
	net->DialDelay = dial_delay;
	net->Bound = bound;

	CopyMemory(t->Name, name, size);
	t->Param = net;
	t->Dial = TransportLoopbackDial;
	t->Listen = TransportLoopbackListen;
	t->Accept = TransportLoopbackAccept;
	t->CloseListener = TransportLoopbackCloseListener;
	t->Read = TransportLoopbackRead;
	t->Write = TransportLoopbackWrite;
	t->Close = TransportLoopbackClose;
	t->Binding = TransportLoopbackBinding;
	t->Rekey = NULL;
	t->Remote = TransportLoopbackRemote;

	return t;
}

void TransportLoopbackSetSource(TRANSPORT *t, const char *source) {
	if (t == NULL || t->Param == NULL)
		return;

	LOOPBACK_NET *net = (LOOPBACK_NET *)t->Param;

	AcquireSRWLockExclusive(&net->Lock);
	TransportLoopbackSetText(net->Source, (source != NULL ? source : ""));
	ReleaseSRWLockExclusive(&net->Lock);
}

void TransportLoopbackFree(TRANSPORT *t) {
	if (t == NULL)
		return;

	// The streams do not need the transport: each frees itself with its last end
	TransportLoopbackRelease(t->Param, sizeof(LOOPBACK_NET));
	TransportLoopbackRelease(t, sizeof(TRANSPORT));
}
