// Transport.c
// The transport interface of the new core: the calls on a stream and a listener, which go to the
// procedures of their transport; the fallback list of a client, and its race happy-eyeballs style
// (RFC 8305) on the Windows thread pool.

#include "Core/Transport.h"

#include <string.h>

struct TRANSPORT_STREAM {
	TRANSPORT *Transport; // The transport that carries the stream
	void *Stream;         // Its own stream object
};

struct TRANSPORT_LISTENER {
	TRANSPORT *Transport; // The transport that listens
	void *Listener;       // Its own listener object
};

typedef struct TRANSPORT_RACE_STATE TRANSPORT_RACE_STATE;

// One attempt of a race: one entry of the list, dialled on a thread of the thread pool
typedef struct TRANSPORT_ATTEMPT {
	TRANSPORT_RACE_STATE *Race; // The race
	UINT Index;                 // The entry it dials
	PTP_WORK Work;              // Its work item, NULL when it could not start
} TRANSPORT_ATTEMPT;

// A race in progress
struct TRANSPORT_RACE_STATE {
	const TRANSPORT_TARGET *Targets;                   // The fallback list
	HANDLE Cancel;                                     // Set once the race is over: the attempts still dialling return
	SRWLOCK Lock;                                      // The fields below
	CONDITION_VARIABLE Changed;                        // An attempt returned
	bool Over;                                         // The race is over: a stream now is a late one, a failure a cancelled attempt
	UINT NumEnded;                                     // The attempts that returned
	UINT NumFailed;                                    // ... of them, the ones that failed before the race was over
	UINT Winner;                                       // The first attempt that connected, INFINITE before
	void *Stream;                                      // ... its stream object
	UINT64 WonAt;                                      // ... and when it connected
	TRANSPORT_ATTEMPT Attempts[TRANSPORT_MAX_TARGETS]; // The attempts, in the order of the list
};

//
// The interface
//

// A stream object of t in a TRANSPORT_STREAM; NULL, with the object closed, when there is no memory
static TRANSPORT_STREAM *TransportWrap(TRANSPORT *t, void *stream) {
	TRANSPORT_STREAM *s = (TRANSPORT_STREAM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_STREAM));

	if (s == NULL) {
		t->Close(stream);
		return NULL;
	}

	s->Transport = t;
	s->Stream = stream;

	return s;
}

TRANSPORT_STREAM *TransportDial(TRANSPORT *t, const char *address, HANDLE cancel) {
	void *stream = NULL;

	if (t == NULL || t->Dial == NULL || address == NULL)
		return NULL;
	if (t->Dial(t->Param, address, cancel, &stream) == false)
		return NULL;

	return TransportWrap(t, stream);
}

TRANSPORT_LISTENER *TransportListen(TRANSPORT *t, const char *address) {
	void *listener = NULL;

	if (t == NULL || t->Listen == NULL || address == NULL)
		return NULL;
	if (t->Listen(t->Param, address, &listener) == false)
		return NULL;

	TRANSPORT_LISTENER *l = (TRANSPORT_LISTENER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_LISTENER));
	if (l == NULL) {
		t->CloseListener(listener);
		return NULL;
	}

	l->Transport = t;
	l->Listener = listener;

	return l;
}

TRANSPORT_STREAM *TransportAccept(TRANSPORT_LISTENER *l, UINT timeout) {
	void *stream = NULL;

	if (l == NULL)
		return NULL;

	// The transport first: a CloseListener on another thread frees l once this Accept returned
	TRANSPORT *t = l->Transport;
	if (t->Accept(l->Listener, timeout, &stream) == false)
		return NULL;

	return TransportWrap(t, stream);
}

bool TransportTake(TRANSPORT_LISTENER *l, UINT_PTR socket) {
	if (l == NULL || l->Transport->Take == NULL)
		return false;

	return l->Transport->Take(l->Listener, socket);
}

void TransportCloseListener(TRANSPORT_LISTENER *l) {
	if (l == NULL)
		return;

	l->Transport->CloseListener(l->Listener);
	HeapFree(GetProcessHeap(), 0, l);
}

UINT TransportRead(TRANSPORT_STREAM *s, void *buf, UINT size, UINT timeout) {
	if (s == NULL || buf == NULL || size == 0)
		return 0;

	return s->Transport->Read(s->Stream, buf, size, timeout);
}

bool TransportWrite(TRANSPORT_STREAM *s, const void *buf, UINT size) {
	if (s == NULL || (buf == NULL && size != 0))
		return false;
	if (size == 0)
		return true;

	return s->Transport->Write(s->Stream, buf, size);
}

void TransportClose(TRANSPORT_STREAM *s) {
	if (s == NULL)
		return;

	s->Transport->Close(s->Stream);
	HeapFree(GetProcessHeap(), 0, s);
}

UINT TransportBinding(TRANSPORT_STREAM *s, UCHAR *binding, UINT max, UINT *size) {
	if (size != NULL)
		*size = 0;
	if (s == NULL || binding == NULL || size == NULL || s->Transport->Binding == NULL)
		return NOISE_BINDING_NONE;

	return s->Transport->Binding(s->Stream, binding, max, size);
}

bool TransportRekey(TRANSPORT_STREAM *s) {
	if (s == NULL)
		return false;

	// A transport without keys of its own has nothing to update
	if (s->Transport->Rekey == NULL)
		return true;

	return s->Transport->Rekey(s->Stream);
}

TRANSPORT *TransportOf(TRANSPORT_STREAM *s) {
	return (s != NULL ? s->Transport : NULL);
}

//
// The fallback list
//

// The known transport of a name of size bytes, or NULL
static TRANSPORT *TransportFind(TRANSPORT **transports, UINT num, const char *name, UINT size) {
	for (UINT i = 0; i < num; i++) {
		TRANSPORT *t = transports[i];

		if (t != NULL && strlen(t->Name) == size && memcmp(t->Name, name, size) == 0)
			return t;
	}

	return NULL;
}

UINT TransportParseList(const char *list, TRANSPORT **transports, UINT num_transports, TRANSPORT_TARGET *targets, UINT max) {
	UINT num = 0;

	if (targets != NULL && max != 0)
		ZeroMemory(targets, sizeof(TRANSPORT_TARGET) * max);
	if (list == NULL || transports == NULL || targets == NULL)
		return 0;

	// Every entry up to the next comma, so that an empty one, also after the last comma, is malformed
	const char *p = list;
	while (true) {
		// One entry: up to the next comma, without the spaces around it
		const char *end = strchr(p, ',');
		if (end == NULL)
			end = p + strlen(p);
		const char *b = p;
		const char *e = end;
		while (b < e && (*b == ' ' || *b == '\t'))
			b++;
		while (e > b && (e[-1] == ' ' || e[-1] == '\t'))
			e--;

		// The name of a known transport, a colon, and an address that fits
		const char *colon = (const char *)memchr(b, ':', (size_t)(e - b));
		if (num >= max || colon == NULL || colon == b || colon + 1 == e || (size_t)(e - colon - 1) >= TRANSPORT_ADDRESS_SIZE)
			goto FAIL;
		TRANSPORT *t = TransportFind(transports, num_transports, b, (UINT)(colon - b));
		if (t == NULL)
			goto FAIL;

		targets[num].Transport = t;
		CopyMemory(targets[num].Address, colon + 1, (size_t)(e - colon - 1));
		num++;

		if (*end == 0)
			break;
		p = end + 1;
	}

	return num;

FAIL:
	ZeroMemory(targets, sizeof(TRANSPORT_TARGET) * max);
	return 0;
}

//
// The race
//

// An attempt, on a thread of the thread pool: dial its entry. The first stream wins; a stream that
// connects after the winner's, or after the race is over, is closed.
static void CALLBACK TransportAttempt(PTP_CALLBACK_INSTANCE instance, void *param, PTP_WORK work) {
	TRANSPORT_ATTEMPT *a = (TRANSPORT_ATTEMPT *)param;
	TRANSPORT_RACE_STATE *r = a->Race;
	const TRANSPORT_TARGET *target = &r->Targets[a->Index];
	TRANSPORT *t = target->Transport;
	void *stream = NULL;

	bool ok = t->Dial(t->Param, target->Address, r->Cancel, &stream);

	AcquireSRWLockExclusive(&r->Lock);
	if (ok && r->Over == false && r->Winner == INFINITE) {
		r->Winner = a->Index;
		r->Stream = stream;
		r->WonAt = GetTickCount64();
		stream = NULL;
	} else if (ok == false && r->Over == false) {
		r->NumFailed++;
	}
	r->NumEnded++;
	WakeAllConditionVariable(&r->Changed);
	ReleaseSRWLockExclusive(&r->Lock);

	if (stream != NULL)
		t->Close(stream);
}

// Start attempt i of a race, under its lock. An attempt that cannot start has failed.
static void TransportStartAttempt(TRANSPORT_RACE_STATE *r, UINT i) {
	TRANSPORT_ATTEMPT *a = &r->Attempts[i];

	a->Race = r;
	a->Index = i;
	a->Work = CreateThreadpoolWork(TransportAttempt, a, NULL);
	if (a->Work == NULL) {
		r->NumEnded++;
		r->NumFailed++;
		return;
	}

	SubmitThreadpoolWork(a->Work);
}

TRANSPORT_STREAM *TransportRace(const TRANSPORT_TARGET *targets, UINT num, UINT delay, UINT timeout, TRANSPORT_RACE *race) {
	TRANSPORT_RACE_STATE r;
	UINT started = 0;

	if (race != NULL) {
		ZeroMemory(race, sizeof(TRANSPORT_RACE));
		race->Winner = INFINITE;
	}
	if (targets == NULL || num == 0 || num > TRANSPORT_MAX_TARGETS)
		return NULL;
	for (UINT i = 0; i < num; i++)
		if (targets[i].Transport == NULL || targets[i].Transport->Dial == NULL || targets[i].Transport->Close == NULL)
			return NULL;

	ZeroMemory(&r, sizeof(r));
	r.Targets = targets;
	r.Winner = INFINITE;
	InitializeSRWLock(&r.Lock);
	InitializeConditionVariable(&r.Changed);
	r.Cancel = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (r.Cancel == NULL)
		return NULL;

	UINT64 start = GetTickCount64();
	UINT64 next = start;

	AcquireSRWLockExclusive(&r.Lock);
	while (r.Winner == INFINITE) {
		UINT64 now = GetTickCount64();

		// The next attempt starts the attempt delay after the one before it, or at once when every
		// attempt so far failed (RFC 8305 section 5)
		if (started < num && (now >= next || r.NumEnded == started)) {
			TransportStartAttempt(&r, started);
			started++;
			next = now + delay;
			continue;
		}

		// Every attempt failed, or the time is up
		if (r.NumEnded == started)
			break;
		if (timeout != INFINITE && now >= start + timeout)
			break;

		// Until an attempt returns, the next one is due, or the time is up
		UINT64 until = (started < num ? next : MAXUINT64);
		if (timeout != INFINITE && start + timeout < until)
			until = start + timeout;
		SleepConditionVariableSRW(&r.Changed, &r.Lock, (until == MAXUINT64 ? INFINITE : (DWORD)(until - now)), 0);
	}
	r.Over = true;
	ReleaseSRWLockExclusive(&r.Lock);

	// The attempts still dialling are not needed: cancel them, and wait until each returned
	SetEvent(r.Cancel);
	for (UINT i = 0; i < started; i++) {
		if (r.Attempts[i].Work != NULL) {
			WaitForThreadpoolWorkCallbacks(r.Attempts[i].Work, FALSE);
			CloseThreadpoolWork(r.Attempts[i].Work);
		}
	}
	CloseHandle(r.Cancel);

	if (race != NULL) {
		race->Winner = r.Winner;
		race->NumStarted = started;
		race->NumFailed = r.NumFailed;
		race->Elapsed = (r.Winner != INFINITE ? r.WonAt : GetTickCount64()) - start;
	}

	if (r.Winner == INFINITE)
		return NULL;

	return TransportWrap(targets[r.Winner].Transport, r.Stream);
}
