// NodeHandshake.c
// The handshakes of the streams that the overlay of a node accepts (AUD1-DT-1, #449; NS-9 of docs/threat-model.md). A
// stream that a stranger dialled has proved no key until its Noise handshake finished, and the handshake waits for the
// first frame of the initiator for up to NODE_OVERLAY_HANDSHAKE. The one thread of the overlay also reads the sessions
// of every peer and dials every peer, so it never runs one: it hands each stream that it accepts to this pool and takes
// only the sessions whose handshake finished (NodeOverlayAccept).
//
// The pool is a private pool of the Windows thread pool with at most NODE_OVERLAY_HANDSHAKE_WORKERS threads, each of
// which runs one handshake at a time. At most MaxHandshakes of the overlay's configuration are in flight, waiting for a
// thread or running on one: the stream after them is refused at the accept, closed at once and counted. The time of a
// handshake runs from its accept, so one that waited for a thread has the rest of it: a handshake that does not finish
// in its time is closed and counted, as is one that failed. A session whose handshake finished waits for the thread of
// the overlay in a list.

#include "Node.h"

#include "Mayaqua/Memory.h"

#include "NodeInternal.h"

// One stream that the overlay accepted, while its handshake waits or runs, and then its session while it waits for the
// thread of the overlay
typedef struct NODE_HANDSHAKE {
	NODE_HANDSHAKES *Pool;
	TRANSPORT_STREAM *Stream;    // The stream
	UINT64 Deadline;             // The GetTickCount64 by which its handshake finishes: NODE_OVERLAY_HANDSHAKE after its accept
	TRANSPORT_NOISE *Session;    // Its session, once the handshake finished
	struct NODE_HANDSHAKE *Next; // The next session of the list of the finished ones
} NODE_HANDSHAKE;

// The pool of the handshakes of an overlay
struct NODE_HANDSHAKES {
	NOISE_SESSION_CONFIG Config; // The configuration of a responder, whose keys outlive the pool
	UINT Max;                    // Handshakes in flight at most
	PTP_POOL Pool;               // The private pool of the Windows thread pool ...
	TP_CALLBACK_ENVIRON Env;     // ... the environment of its callbacks ...
	PTP_CLEANUP_GROUP Group;     // ... and their cleanup group, which waits for every callback
	volatile bool Halt;          // The pool stops: a handshake that did not start closes its stream
	bool Stopped;                // NodeHandshakeStop ran
	volatile LONG InFlight;      // Handshakes that wait for a thread or run on one
	SRWLOCK Lock;                // First and Last
	NODE_HANDSHAKE *First;       // The sessions whose handshake finished, oldest first ...
	NODE_HANDSHAKE *Last;        // ... and the newest
	volatile LONG64 TimedOut;    // Handshakes that did not finish in their time
	volatile LONG64 Failed;      // Handshakes that failed within it
	volatile LONG64 Refused;     // Streams refused at the accept: the handshakes in flight were at Max
};

// Run the handshake of one stream on a thread of the pool, in the time left of it, and put the session of one that
// finished on the list of the finished ones
static void CALLBACK NodeHandshakeRun(PTP_CALLBACK_INSTANCE instance, void *param) {
	NODE_HANDSHAKE *h = (NODE_HANDSHAKE *)param;
	NODE_HANDSHAKES *p = h->Pool;
	UINT64 now = GetTickCount64();

	UNREFERENCED_PARAMETER(instance);

	if (p->Halt || now >= h->Deadline) {
		// The pool stops, or the handshake waited for a thread for all of its time
		TransportClose(h->Stream);
		if (p->Halt == false)
			InterlockedIncrement64(&p->TimedOut);
		Free(h);
		InterlockedDecrement(&p->InFlight);
		return;
	}

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	if (TransportNoiseAccept(s, h->Stream, &p->Config, (UINT)(h->Deadline - now)) == false) {
		// The accept closed the stream
		Free(s);
		InterlockedIncrement64(GetTickCount64() >= h->Deadline ? &p->TimedOut : &p->Failed);
		Free(h);
		InterlockedDecrement(&p->InFlight);
		return;
	}

	h->Stream = NULL;
	h->Session = s;
	AcquireSRWLockExclusive(&p->Lock);
	if (p->Last != NULL)
		p->Last->Next = h;
	else
		p->First = h;
	p->Last = h;
	ReleaseSRWLockExclusive(&p->Lock);

	InterlockedDecrement(&p->InFlight);
}

// Start the pool of the handshakes of an overlay: cfg is the configuration of a responder, whose keys outlive the pool,
// and max the handshakes in flight at most, 0 for NODE_OVERLAY_HANDSHAKES. NULL when the pool cannot start.
NODE_HANDSHAKES *NodeHandshakeStart(const NOISE_SESSION_CONFIG *cfg, UINT max) {
	if (cfg == NULL)
		return NULL;

	NODE_HANDSHAKES *p = ZeroMalloc(sizeof(NODE_HANDSHAKES));
	Copy(&p->Config, cfg, sizeof(NOISE_SESSION_CONFIG));
	p->Max = (max != 0 ? max : NODE_OVERLAY_HANDSHAKES);
	InitializeSRWLock(&p->Lock);
	InitializeThreadpoolEnvironment(&p->Env);

	p->Pool = CreateThreadpool(NULL);
	p->Group = CreateThreadpoolCleanupGroup();
	if (p->Pool == NULL || p->Group == NULL) {
		if (p->Group != NULL)
			CloseThreadpoolCleanupGroup(p->Group);
		if (p->Pool != NULL)
			CloseThreadpool(p->Pool);
		DestroyThreadpoolEnvironment(&p->Env);
		Free(p);
		return NULL;
	}

	SetThreadpoolThreadMaximum(p->Pool, NODE_OVERLAY_HANDSHAKE_WORKERS);
	SetThreadpoolCallbackPool(&p->Env, p->Pool);
	SetThreadpoolCallbackCleanupGroup(&p->Env, p->Group, NULL);

	return p;
}

// Run the handshake of a stream that the overlay accepted, in the pool: false when the handshakes in flight are at
// their limit, or the pool cannot take it, and the stream is closed and counted as refused
bool NodeHandshakeSubmit(NODE_HANDSHAKES *p, TRANSPORT_STREAM *stream) {
	if (stream == NULL)
		return false;

	if (p != NULL && p->Halt == false) {
		if (InterlockedIncrement(&p->InFlight) <= (LONG)p->Max) {
			NODE_HANDSHAKE *h = ZeroMalloc(sizeof(NODE_HANDSHAKE));

			h->Pool = p;
			h->Stream = stream;
			h->Deadline = GetTickCount64() + NODE_OVERLAY_HANDSHAKE;
			if (TrySubmitThreadpoolCallback(NodeHandshakeRun, h, &p->Env))
				return true;
			Free(h);
		}
		InterlockedDecrement(&p->InFlight);
	}

	TransportClose(stream);
	if (p != NULL)
		InterlockedIncrement64(&p->Refused);

	return false;
}

// The oldest session whose handshake finished, which the caller takes: NULL for none
TRANSPORT_NOISE *NodeHandshakeTake(NODE_HANDSHAKES *p) {
	if (p == NULL)
		return NULL;

	AcquireSRWLockExclusive(&p->Lock);
	NODE_HANDSHAKE *h = p->First;
	if (h != NULL) {
		p->First = h->Next;
		if (p->First == NULL)
			p->Last = NULL;
	}
	ReleaseSRWLockExclusive(&p->Lock);

	if (h == NULL)
		return NULL;

	TRANSPORT_NOISE *s = h->Session;
	Free(h);

	return s;
}

// Stop the pool: a handshake that did not start closes its stream, the ones that run end in their time, and the
// sessions that the overlay did not take are closed. The counters stay for NodeHandshakeGetStatus until the pool is
// freed.
void NodeHandshakeStop(NODE_HANDSHAKES *p) {
	TRANSPORT_NOISE *s;

	if (p == NULL || p->Stopped)
		return;

	p->Halt = true;
	CloseThreadpoolCleanupGroupMembers(p->Group, FALSE, NULL);
	CloseThreadpoolCleanupGroup(p->Group);
	CloseThreadpool(p->Pool);
	DestroyThreadpoolEnvironment(&p->Env);
	p->Stopped = true;

	while ((s = NodeHandshakeTake(p)) != NULL) {
		TransportNoiseClose(s);
		Free(s);
	}
}

// Stop the pool, and free it
void NodeHandshakeFree(NODE_HANDSHAKES *p) {
	if (p == NULL)
		return;

	NodeHandshakeStop(p);
	Free(p);
}

// The handshakes of the pool into the status of the overlay
void NodeHandshakeGetStatus(NODE_HANDSHAKES *p, NODE_OVERLAY_STATUS *st) {
	if (p == NULL || st == NULL)
		return;

	st->MaxHandshakes = p->Max;
	st->HandshakesInFlight = (UINT)MAX(ReadAcquire(&p->InFlight), 0);
	st->HandshakesTimedOut = (UINT64)ReadAcquire64(&p->TimedOut);
	st->HandshakesFailed = (UINT64)ReadAcquire64(&p->Failed);
	st->HandshakesRefused = (UINT64)ReadAcquire64(&p->Refused);
}
