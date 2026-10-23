// TransportNoise.c
// The session layer on the transport interface: a Noise session (Core/Noise.h) over a stream of any
// transport, through the calls of Transport.c alone. Each record goes as one frame, its size in 4
// bytes (big-endian) and the record. The channel binding of the stream goes into the handshake,
// and a stream that nothing binds gets an encrypted session. While Receive waits for a record, it
// runs the timers of the session: a keepalive when this side was quiet, the next keys of an
// encrypted session or the update of the outer keys of a bound stream, and the dead-peer timeout.
// On a transport over TCP the data records wait in the ingress queue of the session
// (TransportQueue.c), and a writer on the Windows thread pool writes the records it lets out.

#include "Core/Transport.h"

// What a read of a frame gave
#define TRANSPORT_FRAME_DONE  0 // A whole frame is in In
#define TRANSPORT_FRAME_LATER 1 // Not within the timeout: the bytes read so far stay in In
#define TRANSPORT_FRAME_END   2 // The stream ended, or its next frame holds no record

// Wipe and free a frame buffer, which may be NULL
static void TransportNoiseFreeFrame(UCHAR *frame) {
	if (frame == NULL)
		return;

	SecureZeroMemory(frame, TRANSPORT_MAX_FRAME);
	HeapFree(GetProcessHeap(), 0, frame);
}

static void CALLBACK TransportNoiseWriter(PTP_CALLBACK_INSTANCE instance, void *param, PTP_WORK work);

// Take the stream and allocate the frames, and the ingress queue and its writer where the
// transport has one; then the configuration of the session: cfg with the channel binding of the
// stream, in binding, and an encrypted session where there is none
static bool TransportNoiseStart(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, NOISE_SESSION_CONFIG *c, UCHAR *binding) {
	UINT binding_size = 0;

	ZeroMemory(n, sizeof(TRANSPORT_NOISE));
	InitializeSRWLock(&n->Lock);
	InitializeSRWLock(&n->QueueLock);
	InitializeConditionVariable(&n->Written);
	n->Stream = s;
	if (s == NULL || cfg == NULL)
		return false;

	n->In = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TRANSPORT_MAX_FRAME);
	n->Out = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TRANSPORT_MAX_FRAME);
	if (n->In == NULL || n->Out == NULL)
		return false;

	UINT mode = TransportOf(s)->Queue;
	if (mode != TRANSPORT_QUEUE_NONE) {
		n->Queue = (TRANSPORT_QUEUE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_QUEUE));
		n->Pending = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NOISE_MAX_PAYLOAD);
		n->Writer = CreateThreadpoolWork(TransportNoiseWriter, n, NULL);
		if (n->Queue == NULL || n->Pending == NULL || n->Writer == NULL)
			return false;
		TransportQueueInit(n->Queue, mode);
	}

	CopyMemory(c, cfg, sizeof(NOISE_SESSION_CONFIG));
	c->BindingType = TransportBinding(s, binding, NOISE_MAX_BINDING, &binding_size);
	c->Binding = binding;
	c->BindingSize = binding_size;
	if (c->BindingType == NOISE_BINDING_NONE)
		c->Flags |= NOISE_SESSION_ENCRYPT;
	else
		c->Flags &= ~NOISE_SESSION_ENCRYPT;

	return true;
}

// Write the record that Out holds after the frame header, size bytes, as one frame. A stream that
// fails ends the session.
static bool TransportNoiseWrite(TRANSPORT_NOISE *n, UINT size) {
	n->Out[0] = (UCHAR)(size >> 24);
	n->Out[1] = (UCHAR)(size >> 16);
	n->Out[2] = (UCHAR)(size >> 8);
	n->Out[3] = (UCHAR)size;

	if (TransportWrite(n->Stream, n->Out, TRANSPORT_FRAME_HEADER + size) == false) {
		NoiseSessionFree(&n->Session);
		return false;
	}

	n->NumSent++;
	return true;
}

// The writer of the ingress queue, on the Windows thread pool: it writes the records that the queue
// lets out, each as Send writes one, until none waits. Once the session is not open any more (it
// closed, or a write failed), the queue takes no record, and the records that wait go nowhere.
static void CALLBACK TransportNoiseWriter(PTP_CALLBACK_INSTANCE instance, void *param, PTP_WORK work) {
	TRANSPORT_NOISE *n = (TRANSPORT_NOISE *)param;

	UNREFERENCED_PARAMETER(work);

	// A write waits for the stream: the pool starts another thread for its other callbacks
	(void)CallbackMayRunLong(instance);

	while (true) {
		UINT size = 0, record_size = 0;

		AcquireSRWLockExclusive(&n->QueueLock);
		bool more = (n->Failed == false && TransportQueuePop(n->Queue, TransportQueueNow(), n->Pending, NOISE_MAX_PAYLOAD, &size));
		if (more == false) {
			n->Writing = false;
			WakeAllConditionVariable(&n->Written);
		}
		ReleaseSRWLockExclusive(&n->QueueLock);
		if (more == false)
			return;

		AcquireSRWLockExclusive(&n->Lock);
		if (NoiseSessionSend(&n->Session, GetTickCount64(), NOISE_RECORD_DATA, n->Pending, size, n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &record_size))
			TransportNoiseWrite(n, record_size);
		bool open = (n->Session.State == NOISE_STATE_OPEN);
		ReleaseSRWLockExclusive(&n->Lock);
		SecureZeroMemory(n->Pending, size);

		if (open == false) {
			AcquireSRWLockExclusive(&n->QueueLock);
			n->Failed = true;
			ReleaseSRWLockExclusive(&n->QueueLock);
		}
	}
}

// Queue a data record for the writer, and start the writer when it does not run: false when the
// session takes no record any more, or the queue dropped the record at its limit
static bool TransportNoiseQueue(TRANSPORT_NOISE *n, const void *data, UINT size) {
	bool ok = false;

	if ((data == NULL && size != 0) || size > NOISE_MAX_PAYLOAD)
		return false;

	AcquireSRWLockExclusive(&n->QueueLock);
	if (n->Closing == false && n->Failed == false && TransportQueuePush(n->Queue, TransportQueueNow(), data, size)) {
		ok = true;
		if (n->Writing == false) {
			n->Writing = true;
			SubmitThreadpoolWork(n->Writer);
		}
	}
	ReleaseSRWLockExclusive(&n->QueueLock);

	return ok;
}

// Read one frame into In within timeout. A frame that the timeout cut short stays in In for the
// next read; the caller empties In (InSize = 0) once it took a whole frame.
static UINT TransportNoiseRead(TRANSPORT_NOISE *n, UINT timeout) {
	UINT64 end = GetTickCount64() + timeout;

	while (true) {
		UINT need = TRANSPORT_FRAME_HEADER;

		if (n->InSize >= TRANSPORT_FRAME_HEADER) {
			UINT size = ((UINT)n->In[0] << 24) | ((UINT)n->In[1] << 16) | ((UINT)n->In[2] << 8) | n->In[3];
			if (size == 0 || size > NOISE_MAX_RECORD)
				return TRANSPORT_FRAME_END;
			need += size;
			if (n->InSize == need)
				return TRANSPORT_FRAME_DONE;
		}

		UINT wait = INFINITE;
		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			wait = (now >= end ? 0 : (UINT)(end - now));
		}

		UINT got = TransportRead(n->Stream, n->In + n->InSize, need - n->InSize, wait);
		if (got == TRANSPORT_LATER)
			return TRANSPORT_FRAME_LATER;
		if (got == 0 || got > need - n->InSize)
			return TRANSPORT_FRAME_END;
		n->InSize += got;
	}
}

// Run the timers of the session: write the keepalives it asks for, update the outer keys of a
// bound stream when it asks. *next is when the next timer is due. false once the session is not
// open: closed, dead, or on a stream that failed.
static bool TransportNoisePoll(TRANSPORT_NOISE *n, UINT64 *next) {
	NOISE_SESSION *s = &n->Session;
	bool ok = true;

	AcquireSRWLockExclusive(&n->Lock);
	while (ok) {
		UINT size = 0;
		UINT poll = NoiseSessionPoll(s, GetTickCount64(), n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &size);

		if (poll == NOISE_POLL_SEND)
			ok = TransportNoiseWrite(n, size);
		else if (poll == NOISE_POLL_REKEY)
			ok = TransportRekey(n->Stream);
		else
			break;
	}
	if (ok == false)
		NoiseSessionFree(s);

	// The keepalive, the dead timeout or the rekey, whichever comes first
	*next = s->LastSent + s->KeepaliveInterval;
	if (s->LastReceived + s->DeadTimeout < *next)
		*next = s->LastReceived + s->DeadTimeout;
	if (s->LastRekey + s->RekeyInterval < *next)
		*next = s->LastRekey + s->RekeyInterval;

	ok = (s->State == NOISE_STATE_OPEN);
	ReleaseSRWLockExclusive(&n->Lock);

	return ok;
}

bool TransportNoiseConnect(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout) {
	NOISE_SESSION_CONFIG c;
	UCHAR binding[NOISE_MAX_BINDING];
	UINT size = 0;

	if (n == NULL) {
		TransportClose(s);
		return false;
	}

	// The first handshake record out, the second back
	bool ok = TransportNoiseStart(n, s, cfg, &c, binding);
	if (ok)
		ok = NoiseSessionConnect(&n->Session, &c, GetTickCount64(), n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &size);
	if (ok)
		ok = TransportNoiseWrite(n, size);
	if (ok)
		ok = (TransportNoiseRead(n, timeout) == TRANSPORT_FRAME_DONE);
	if (ok)
		ok = NoiseSessionFinish(&n->Session, GetTickCount64(), n->In + TRANSPORT_FRAME_HEADER, n->InSize - TRANSPORT_FRAME_HEADER);
	SecureZeroMemory(binding, sizeof(binding));

	if (ok == false) {
		TransportNoiseClose(n);
		return false;
	}

	n->InSize = 0;
	return true;
}

bool TransportNoiseAccept(TRANSPORT_NOISE *n, TRANSPORT_STREAM *s, const NOISE_SESSION_CONFIG *cfg, UINT timeout) {
	NOISE_SESSION_CONFIG c;
	UCHAR binding[NOISE_MAX_BINDING];
	UINT size = 0;

	if (n == NULL) {
		TransportClose(s);
		return false;
	}

	// The first handshake record in, the second out
	bool ok = TransportNoiseStart(n, s, cfg, &c, binding);
	if (ok)
		ok = (TransportNoiseRead(n, timeout) == TRANSPORT_FRAME_DONE);
	if (ok)
		ok = NoiseSessionAccept(&n->Session, &c, GetTickCount64(), n->In + TRANSPORT_FRAME_HEADER, n->InSize - TRANSPORT_FRAME_HEADER, n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &size);
	if (ok)
		ok = TransportNoiseWrite(n, size);
	SecureZeroMemory(binding, sizeof(binding));

	if (ok == false) {
		TransportNoiseClose(n);
		return false;
	}

	n->InSize = 0;
	return true;
}

bool TransportNoiseSend(TRANSPORT_NOISE *n, UINT type, const void *data, UINT size) {
	UINT record_size = 0;
	bool ok = false;

	if (n == NULL || n->Stream == NULL)
		return false;

	// A data record of a session with an ingress queue waits there for the writer
	if (type == NOISE_RECORD_DATA && n->Queue != NULL)
		return TransportNoiseQueue(n, data, size);

	AcquireSRWLockExclusive(&n->Lock);
	if (NoiseSessionSend(&n->Session, GetTickCount64(), type, data, size, n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &record_size))
		ok = TransportNoiseWrite(n, record_size);
	ReleaseSRWLockExclusive(&n->Lock);

	return ok;
}

UINT TransportNoiseReceive(TRANSPORT_NOISE *n, void *data, UINT max, UINT *size, UINT timeout) {
	UINT64 end = GetTickCount64() + timeout;
	UINT64 next = 0;

	if (size != NULL)
		*size = 0;
	if (n == NULL || n->Stream == NULL || size == NULL)
		return NOISE_RECEIVE_ERROR;

	while (TransportNoisePoll(n, &next)) {
		// A frame, until the next timer is due or the timeout ends
		UINT64 now = GetTickCount64();
		if (timeout != INFINITE && end < next)
			next = end;

		UINT got = TransportNoiseRead(n, (next > now ? (UINT)(next - now) : 0));
		if (got == TRANSPORT_FRAME_END)
			break;

		if (got == TRANSPORT_FRAME_DONE) {
			AcquireSRWLockExclusive(&n->Lock);
			UINT ret = NoiseSessionReceive(&n->Session, GetTickCount64(), n->In + TRANSPORT_FRAME_HEADER, n->InSize - TRANSPORT_FRAME_HEADER, data, max, size);
			ReleaseSRWLockExclusive(&n->Lock);
			n->InSize = 0;
			n->NumReceived++;

			// A keepalive has nothing for the owner
			if (ret != NOISE_RECEIVE_NONE)
				return ret;
		}

		if (timeout != INFINITE && GetTickCount64() >= end)
			return NOISE_RECEIVE_NONE;
	}

	// The stream ended, or the session is closed or dead
	AcquireSRWLockExclusive(&n->Lock);
	NoiseSessionFree(&n->Session);
	ReleaseSRWLockExclusive(&n->Lock);

	return NOISE_RECEIVE_ERROR;
}

void TransportNoiseAcceptLogin(TRANSPORT_NOISE *n) {
	if (n == NULL)
		return;

	AcquireSRWLockExclusive(&n->Lock);
	NoiseSessionAcceptLogin(&n->Session);
	ReleaseSRWLockExclusive(&n->Lock);
}

void TransportNoiseClose(TRANSPORT_NOISE *n) {
	UINT size = 0;

	if (n == NULL)
		return;

	// The data records that wait go out before the close record: the queue takes none any more, and
	// the writer empties it
	if (n->Writer != NULL) {
		AcquireSRWLockExclusive(&n->QueueLock);
		n->Closing = true;
		while (n->Writing)
			SleepConditionVariableSRW(&n->Written, &n->QueueLock, INFINITE, 0);
		ReleaseSRWLockExclusive(&n->QueueLock);
		WaitForThreadpoolWorkCallbacks(n->Writer, FALSE);
		CloseThreadpoolWork(n->Writer);
		n->Writer = NULL;
	}

	// The close record, while the session is open
	if (n->Stream != NULL && n->Out != NULL) {
		AcquireSRWLockExclusive(&n->Lock);
		if (NoiseSessionSend(&n->Session, GetTickCount64(), NOISE_RECORD_CLOSE, NULL, 0, n->Out + TRANSPORT_FRAME_HEADER, NOISE_MAX_RECORD, &size))
			TransportNoiseWrite(n, size);
		ReleaseSRWLockExclusive(&n->Lock);
	}

	TransportClose(n->Stream);
	NoiseSessionFree(&n->Session);
	TransportNoiseFreeFrame(n->In);
	TransportNoiseFreeFrame(n->Out);
	if (n->Queue != NULL) {
		TransportQueueFree(n->Queue);
		HeapFree(GetProcessHeap(), 0, n->Queue);
	}
	if (n->Pending != NULL) {
		SecureZeroMemory(n->Pending, NOISE_MAX_PAYLOAD);
		HeapFree(GetProcessHeap(), 0, n->Pending);
	}
	SecureZeroMemory(n, sizeof(TRANSPORT_NOISE));
}

bool TransportNoiseQueueStatus(TRANSPORT_NOISE *n, TRANSPORT_QUEUE_STATUS *st) {
	if (st != NULL)
		ZeroMemory(st, sizeof(TRANSPORT_QUEUE_STATUS));
	if (n == NULL || st == NULL || n->Queue == NULL)
		return false;

	AcquireSRWLockShared(&n->QueueLock);
	st->NumRecords = n->Queue->NumRecords;
	st->NumPushed = n->Queue->NumPushed;
	st->NumPopped = n->Queue->NumPopped;
	st->NumDropped = n->Queue->NumDropped;
	st->NumOverflow = n->Queue->NumOverflow;
	ReleaseSRWLockShared(&n->QueueLock);

	return true;
}
