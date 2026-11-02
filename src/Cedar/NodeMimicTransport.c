// NodeMimicTransport.c
// The mimic transport of a node (ADR-0023; CORE-P2-6, #406): the transport interface of Core/Transport.h over the data
// pipes of the mimicry sidecar (NodeMimic.c), so that the session layer runs a Noise session over a REALITY stream as it
// does over QUIC and TLS-443. Each inner stream is one connection of a named pipe, with one line in front of it that
// carries the channel binding of the outer TLS session (the protocol of controller/internal/mimic/control.go):
// - The server role: Listen creates the data pipe, with one pipe instance ready at all times, and then starts the
//   sidecar as a server, which names the pipe in its start message. The sidecar connects to the pipe once for each
//   client that proved the key of the server and writes "bind <binding>"; the listener takes only the sidecar that the
//   node started as the client of the pipe, and Accept gives the stream with that binding.
// - The client role: Dial connects to the data pipe that the sidecar of the client role listens on, takes it only from
//   that process, and writes "dial <address>", the address of a link of the client settings; the sidecar answers
//   "ok <binding>" and the stream starts, or "error <reason>". A cancelled dial returns at once.
// The binding is the TLS exporter of the outer session with the label of the session module (NOISE_EXPORTER_LABEL), as
// on TLS-443, and goes into the Noise handshake. The outer connection is TCP, so the sessions over the transport use the
// CoDel ingress queue of TLS-443; the transport updates no outer keys (the sidecar's TLS session is its own), and it
// takes no connection from the front door: the sidecar listens on an address of its own.

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "NodeInternal.h"
#include "NodeMimicInternal.h"

#define NODE_MIMIC_PIPE_BUFFER 65536 // Bytes of the buffers of a data pipe, in each direction (pipeBuffer of the sidecar)
#define NODE_MIMIC_PIPE_WAIT   10000 // How long a dial waits for a free instance of the data pipe of the client role (ms)
#define NODE_MIMIC_PIPE_SLICE  50    // ... in slices of this many ms, so that a cancel ends it
#define NODE_MIMIC_LINE_WAIT   10000 // How long the line in front of a stream of the server role may take (ms)
#define NODE_MIMIC_MAX_REQUEST 300   // Bytes of the dial request at most, with its newline (maxRequest of the sidecar)
#define NODE_MIMIC_MAX_READ    65536 // Bytes of one read of a stream at most

// A stream of the transport: one connection of a data pipe
typedef struct MIMIC_STREAM {
	HANDLE Pipe;                       // The pipe, overlapped
	HANDLE ReadEvent;                  // The event of a read ...
	HANDLE WriteEvent;                 // ... and of a write, which may run at the same time
	UINT BindingSize;                  // The size of the channel binding, 0 when the sidecar had none
	UCHAR Binding[NODE_MIMIC_BINDING]; // The channel binding
} MIMIC_STREAM;

// The listener of the server role: the data pipe that the sidecar connects to
typedef struct MIMIC_LISTENER {
	NODE_MIMIC *Mimic;           // The sidecars of the node
	NODE_MIMIC_SIDECAR *Sidecar; // The sidecar of the server role
	SECURITY_ATTRIBUTES *Sa;     // The security attributes of every instance of the pipe
	HANDLE First;                // The first instance, which Listen creates before the sidecar starts
	HANDLE StopEvent;            // Ends the thread of the listener
	HANDLE Arrived;              // Set when a connection of the sidecar waits in Pending (auto-reset)
	HANDLE Thread;               // Keeps an instance of the pipe ready and takes the connections of the sidecar
	LOCK *Lock;                  // Pending
	LIST *Pending;               // The connections that Accept did not take yet (pipe handles)
} MIMIC_LISTENER;

// The hexadecimal digit c, or -1
static int NodeMimicHexDigit(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

// Whether line starts with word, exactly as the sidecar writes it: the protocol has one spelling
static bool NodeMimicWord(const char *line, const char *word) {
	UINT len = StrLen(word);

	return (StrLen(line) >= len && Cmp((void *)line, (void *)word, len) == 0);
}

// Read a channel binding as the sidecar writes it after its word: NODE_MIMIC_BINDING bytes as hexadecimal digits, or "-"
// for none (size 0). False for anything else.
static bool NodeMimicParseBinding(const char *s, UCHAR *binding, UINT *size) {
	if (StrCmp(s, "-") == 0) {
		*size = 0;
		return true;
	}

	if (StrLen(s) != NODE_MIMIC_BINDING * 2)
		return false;

	for (UINT i = 0; i < NODE_MIMIC_BINDING; i++) {
		int hi = NodeMimicHexDigit(s[i * 2]);
		int lo = NodeMimicHexDigit(s[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return false;

		binding[i] = (UCHAR)(hi * 16 + lo);
	}

	*size = NODE_MIMIC_BINDING;

	return true;
}

// Read the line that the sidecar of the server role writes in front of a stream, without its newline: "bind" and the
// channel binding (NODE_MIMIC_BINDING bytes, NODE_MIMIC_BINDING bytes of binding at most). False when it is no such line.
bool NodeMimicParseBind(const char *line, UCHAR *binding, UINT *size) {
	if (line == NULL || binding == NULL || size == NULL || NodeMimicWord(line, "bind ") == false)
		return false;

	return NodeMimicParseBinding(line + 5, binding, size);
}

// Read the answer of the sidecar of the client role to a dial, the line without its newline: NODE_MIMIC_ANSWER_OK for "ok"
// and the channel binding (as NodeMimicParseBind), NODE_MIMIC_ANSWER_ERROR for "error" and the reason, which goes into
// reason (reason_size bytes with the NUL), NODE_MIMIC_ANSWER_BAD for anything else
UINT NodeMimicParseAnswer(const char *line, UCHAR *binding, UINT *size, char *reason, UINT reason_size) {
	if (reason != NULL)
		StrCpy(reason, reason_size, "");

	if (line == NULL || binding == NULL || size == NULL)
		return NODE_MIMIC_ANSWER_BAD;

	if (NodeMimicWord(line, "ok ") && NodeMimicParseBinding(line + 3, binding, size))
		return NODE_MIMIC_ANSWER_OK;

	if (StrCmp(line, "error") == 0 || NodeMimicWord(line, "error ")) {
		if (reason != NULL)
			StrCpy(reason, reason_size, line[5] == 0 ? "" : line + 6);
		return NODE_MIMIC_ANSWER_ERROR;
	}

	return NODE_MIMIC_ANSWER_BAD;
}

// Read one line of a data pipe, a byte at a time so that nothing of the stream after it is taken, into line (size bytes
// with the NUL, the newline left out). It waits timeout ms at most, and ends at once when cancel (NULL for none) is set.
// False when the pipe ended, the line is longer, holds a NUL or did not come in time.
static bool NodeMimicReadLine(HANDLE pipe, HANDLE event, HANDLE cancel, UINT timeout, char *line, UINT size) {
	UINT64 end = (timeout == INFINITE ? 0 : Tick64() + timeout);
	HANDLE waits[2] = {event, cancel};
	UINT len = 0;

	while (true) {
		OVERLAPPED ov;
		char c = 0;
		DWORD got = 0;

		Zero(&ov, sizeof(ov));
		ov.hEvent = event;
		ResetEvent(event);

		if (ReadFile(pipe, &c, 1, NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
			return false;

		UINT wait = INFINITE;
		if (end != 0) {
			UINT64 now = Tick64();
			wait = (now >= end ? 0 : (UINT)(end - now));
		}

		DWORD w = WaitForMultipleObjects(cancel != NULL ? 2 : 1, waits, FALSE, wait);
		if (w != WAIT_OBJECT_0) {
			CancelIoEx(pipe, &ov);
			GetOverlappedResult(pipe, &ov, &got, TRUE);
			return false;
		}

		if (GetOverlappedResult(pipe, &ov, &got, FALSE) == FALSE || got != 1 || c == 0)
			return false;

		if (c == '\n') {
			line[len] = 0;
			return true;
		}

		if (len + 1 >= size)
			return false;

		line[len++] = c;
	}
}

// Keep the channel binding of the last stream of a role in its status, which a test compares at both ends of a session
// (CORE-P2-7, #424)
static void NodeMimicKeepBinding(NODE_MIMIC_SIDECAR *sc, const UCHAR *binding, UINT size) {
	Lock(sc->Lock);
	{
		sc->St.BindingSize = MIN(size, NODE_MIMIC_BINDING);
		Copy(sc->St.Binding, binding, sc->St.BindingSize);
	}
	Unlock(sc->Lock);
}

// A stream on a connected pipe, with the binding of its line
static MIMIC_STREAM *NodeMimicNewStream(HANDLE pipe, const UCHAR *binding, UINT binding_size) {
	MIMIC_STREAM *s = ZeroMalloc(sizeof(MIMIC_STREAM));

	s->Pipe = pipe;
	s->ReadEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->WriteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	s->BindingSize = binding_size;
	Copy(s->Binding, binding, binding_size);

	return s;
}

//
// The streams
//

static UINT NodeMimicRead(void *stream, void *buf, UINT size, UINT timeout) {
	MIMIC_STREAM *s = (MIMIC_STREAM *)stream;
	OVERLAPPED ov;
	DWORD got = 0;

	if (size == 0)
		return TRANSPORT_LATER;

	Zero(&ov, sizeof(ov));
	ov.hEvent = s->ReadEvent;
	ResetEvent(s->ReadEvent);

	if (ReadFile(s->Pipe, buf, MIN(size, NODE_MIMIC_MAX_READ), NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
		return 0;

	if (WaitForSingleObject(s->ReadEvent, timeout) != WAIT_OBJECT_0) {
		// Nothing came: the read is cancelled, unless it completed meanwhile
		CancelIoEx(s->Pipe, &ov);
		if (GetOverlappedResult(s->Pipe, &ov, &got, TRUE))
			return (got != 0 ? (UINT)got : TRANSPORT_LATER);

		return (GetLastError() == ERROR_OPERATION_ABORTED ? TRANSPORT_LATER : 0);
	}

	if (GetOverlappedResult(s->Pipe, &ov, &got, FALSE) == FALSE)
		return 0;

	return (got != 0 ? (UINT)got : TRANSPORT_LATER);
}

static bool NodeMimicWriteStream(void *stream, const void *buf, UINT size) {
	MIMIC_STREAM *s = (MIMIC_STREAM *)stream;
	const UCHAR *p = (const UCHAR *)buf;

	while (size != 0) {
		OVERLAPPED ov;
		DWORD done = 0;
		DWORD part = MIN(size, NODE_MIMIC_PIPE_BUFFER);

		Zero(&ov, sizeof(ov));
		ov.hEvent = s->WriteEvent;
		ResetEvent(s->WriteEvent);

		if (WriteFile(s->Pipe, p, part, NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
			return false;

		if (GetOverlappedResult(s->Pipe, &ov, &done, TRUE) == FALSE || done == 0)
			return false;

		p += done;
		size -= done;
	}

	return true;
}

// The peer reads the bytes that the pipe holds, then the end
static void NodeMimicClose(void *stream) {
	MIMIC_STREAM *s = (MIMIC_STREAM *)stream;

	CloseHandle(s->Pipe);
	if (s->ReadEvent != NULL)
		CloseHandle(s->ReadEvent);
	if (s->WriteEvent != NULL)
		CloseHandle(s->WriteEvent);
	Free(s);
}

// The TLS exporter of the outer session that the sidecar gave in the line of the stream
static UINT NodeMimicBinding(void *stream, UCHAR *binding, UINT max, UINT *size) {
	MIMIC_STREAM *s = (MIMIC_STREAM *)stream;

	if (s->BindingSize == 0 || s->BindingSize > max)
		return NOISE_BINDING_NONE;

	Copy(binding, s->Binding, s->BindingSize);
	*size = s->BindingSize;

	return NOISE_BINDING_EXPORTER;
}

//
// The client role
//

static bool NodeMimicDial(void *param, const char *address, HANDLE cancel, void **stream) {
	NODE_MIMIC *m = (NODE_MIMIC *)param;
	NODE_MIMIC_SIDECAR *sc = &m->Sidecars[NODE_MIMIC_ROLE_CLIENT];
	UCHAR binding[NODE_MIMIC_BINDING];
	char line[NODE_MIMIC_DATA_LINE];
	char request[NODE_MIMIC_MAX_REQUEST + 1];
	UINT binding_size = 0;
	UINT pid = 0;
	ULONG server = 0;

	*stream = NULL;
	Zero(binding, sizeof(binding));

	if (sc->Settings == NULL || IsEmptyStr(address) || StrLen(address) + 6 > NODE_MIMIC_MAX_REQUEST || NodeMimicSidecarReady(sc, &pid, NULL) == false)
		return false;

	// The sidecar keeps an instance of its pipe ready; another dial may hold it for a moment
	HANDLE pipe = INVALID_HANDLE_VALUE;
	UINT64 end = Tick64() + NODE_MIMIC_PIPE_WAIT;

	while (true) {
		if (cancel != NULL && WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT)
			return false;

		// The sidecar may identify the node and no more: it cannot act as the account of the node
		pipe = CreateFileW(sc->DataPipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
			break;

		if (GetLastError() != ERROR_PIPE_BUSY || Tick64() >= end)
			return false;

		WaitNamedPipeW(sc->DataPipe, NODE_MIMIC_PIPE_SLICE);
	}

	// Only the sidecar that the node started may serve the pipe
	MIMIC_STREAM *s = NodeMimicNewStream(pipe, binding, 0);
	bool ok = (s->ReadEvent != NULL && s->WriteEvent != NULL && GetNamedPipeServerProcessId(pipe, &server) && server == pid);

	if (ok) {
		Format(request, sizeof(request), "dial %s\n", address);
		ok = NodeMimicWriteStream(s, request, StrLen(request));
	}

	if (ok)
		ok = NodeMimicReadLine(pipe, s->ReadEvent, cancel, INFINITE, line, sizeof(line)) &&
		     NodeMimicParseAnswer(line, binding, &binding_size, NULL, 0) == NODE_MIMIC_ANSWER_OK;

	if (ok == false) {
		NodeMimicClose(s);
		return false;
	}

	s->BindingSize = binding_size;
	Copy(s->Binding, binding, binding_size);
	NodeMimicKeepBinding(sc, binding, binding_size);
	*stream = s;

	return true;
}

//
// The server role
//

// A new instance of the data pipe of the listener; the first one claims the name
static HANDLE NodeMimicNewInstance(MIMIC_LISTENER *l, bool first) {
	DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
	DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

	return CreateNamedPipeW(l->Sidecar->DataPipe, open_mode, pipe_mode, PIPE_UNLIMITED_INSTANCES, NODE_MIMIC_PIPE_BUFFER, NODE_MIMIC_PIPE_BUFFER, 0, l->Sa);
}

// The thread of the listener: it waits on an instance of the pipe, creates the next one as soon as the sidecar connects,
// and keeps the connection for Accept when its client is the sidecar of the server role
static DWORD WINAPI NodeMimicListenThread(void *param) {
	MIMIC_LISTENER *l = (MIMIC_LISTENER *)param;
	NODE *n = l->Mimic->Node;
	HANDLE inst = l->First;
	OVERLAPPED ov;

	l->First = INVALID_HANDLE_VALUE;

	HANDLE connect_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (connect_event == NULL) {
		CloseHandle(inst);
		return 0;
	}

	HANDLE waits[2] = {l->StopEvent, connect_event};

	while (inst != INVALID_HANDLE_VALUE) {
		DWORD done = 0;
		bool connected = false;

		Zero(&ov, sizeof(ov));
		ov.hEvent = connect_event;
		ResetEvent(connect_event);

		if (ConnectNamedPipe(inst, &ov) == FALSE) {
			DWORD err = GetLastError();

			if (err == ERROR_PIPE_CONNECTED) {
				connected = true;
			} else if (err == ERROR_IO_PENDING) {
				if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
					CancelIoEx(inst, &ov);
					GetOverlappedResult(inst, &ov, &done, TRUE);
					CloseHandle(inst);
					break;
				}

				connected = (GetOverlappedResult(inst, &ov, &done, FALSE) != FALSE);
			} else if (WaitForSingleObject(l->StopEvent, NODE_MIMIC_PIPE_SLICE) != WAIT_TIMEOUT) {
				// Another error (a client that left before the wait): the next instance takes over a moment later,
				// unless the listener closes
				CloseHandle(inst);
				break;
			}
		}

		// The next instance is ready before this connection is looked at
		HANDLE next = NodeMimicNewInstance(l, false);
		if (next == INVALID_HANDLE_VALUE)
			NodeLog(n, "Mimic transport: the data pipe has no free instance any more (error %u), the listener takes no stream", (UINT)GetLastError());

		ULONG client = 0;
		UINT pid = 0;

		if (connected && GetNamedPipeClientProcessId(inst, &client) && NodeMimicSidecarReady(l->Sidecar, &pid, NULL) && client == pid) {
			Lock(l->Lock);
			{
				Add(l->Pending, inst);
			}
			Unlock(l->Lock);

			SetEvent(l->Arrived);
		} else {
			if (connected)
				NodeLog(n, "Mimic transport: process %u connected to the data pipe, not the sidecar %u: refused", (UINT)client, pid);
			CloseHandle(inst);
		}

		inst = next;
	}

	CloseHandle(connect_event);

	return 0;
}

// Listen: the data pipe first, with an instance ready, then the sidecar of the server role, which names it in its start
// message. The server settings name the address of the REALITY listener (listen, TCP 443 without one), so the address
// of the transport is not used.
static bool NodeMimicListen(void *param, const char *address, void **listener) {
	NODE_MIMIC *m = (NODE_MIMIC *)param;
	NODE_MIMIC_SIDECAR *sc = &m->Sidecars[NODE_MIMIC_ROLE_SERVER];
	DWORD thread_id = 0;
	bool ok = false;

	UNREFERENCED_PARAMETER(address);
	*listener = NULL;

	if (sc->Settings == NULL)
		return false;

	MIMIC_LISTENER *l = ZeroMalloc(sizeof(MIMIC_LISTENER));
	l->Mimic = m;
	l->Sidecar = sc;
	l->First = INVALID_HANDLE_VALUE;
	l->Lock = NewLock();
	l->Pending = NewListFast(NULL);
	l->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	l->Arrived = CreateEventW(NULL, FALSE, FALSE, NULL);
	l->Sa = NodeMimicPipeSa();

	Lock(m->ListenerLock);
	{
		if (m->Listener == NULL && l->StopEvent != NULL && l->Arrived != NULL && l->Sa != NULL) {
			NodeMimicPipeName(sc->DataPipe, sizeof(sc->DataPipe), L"server");
			l->First = NodeMimicNewInstance(l, true);

			if (l->First != INVALID_HANDLE_VALUE) {
				l->Thread = CreateThread(NULL, 0, NodeMimicListenThread, l, 0, &thread_id);
				if (l->Thread == NULL) {
					CloseHandle(l->First);
					l->First = INVALID_HANDLE_VALUE;
				} else {
					m->Listener = l;
					ok = true;
				}
			}
		}
	}
	Unlock(m->ListenerLock);

	if (ok && NodeMimicStartSidecar(sc) == false) {
		NodeLog(m->Node, "Mimic transport: the server role cannot listen: its sidecar is not ready");
		ok = false;
		NodeMimicStopSidecar(sc);
		SetEvent(l->StopEvent);
		WaitForSingleObject(l->Thread, INFINITE);
		CloseHandle(l->Thread);
		l->Thread = NULL;

		Lock(m->ListenerLock);
		{
			m->Listener = NULL;
		}
		Unlock(m->ListenerLock);
	}

	if (ok == false) {
		if (l->StopEvent != NULL)
			CloseHandle(l->StopEvent);
		if (l->Arrived != NULL)
			CloseHandle(l->Arrived);
		NodeMimicFreePipeSa(l->Sa);
		ReleaseList(l->Pending);
		DeleteLock(l->Lock);
		Free(l);
		return false;
	}

	*listener = l;

	return true;
}

static bool NodeMimicAccept(void *listener, UINT timeout, void **stream) {
	MIMIC_LISTENER *l = (MIMIC_LISTENER *)listener;
	UINT64 end = (timeout == INFINITE ? 0 : Tick64() + timeout);
	HANDLE waits[2] = {l->StopEvent, l->Arrived};

	*stream = NULL;

	while (true) {
		HANDLE pipe = NULL;

		Lock(l->Lock);
		{
			if (LIST_NUM(l->Pending) != 0) {
				pipe = LIST_DATA(l->Pending, 0);
				Delete(l->Pending, pipe);
			}
		}
		Unlock(l->Lock);

		if (pipe != NULL) {
			char line[NODE_MIMIC_DATA_LINE];
			UCHAR binding[NODE_MIMIC_BINDING];
			UINT binding_size = 0;

			Zero(binding, sizeof(binding));
			MIMIC_STREAM *s = NodeMimicNewStream(pipe, binding, 0);

			// The sidecar writes the line as soon as it connected
			if (s->ReadEvent != NULL && s->WriteEvent != NULL && NodeMimicReadLine(pipe, s->ReadEvent, l->StopEvent, NODE_MIMIC_LINE_WAIT, line, sizeof(line)) &&
			    NodeMimicParseBind(line, binding, &binding_size)) {
				s->BindingSize = binding_size;
				Copy(s->Binding, binding, binding_size);
				NodeMimicKeepBinding(l->Sidecar, binding, binding_size);
				*stream = s;
				return true;
			}

			NodeMimicClose(s);
			continue;
		}

		UINT wait = INFINITE;
		if (end != 0) {
			UINT64 now = Tick64();
			if (now >= end)
				return false;
			wait = (UINT)(end - now);
		}

		if (WaitForMultipleObjects(2, waits, FALSE, wait) != WAIT_OBJECT_0 + 1)
			return false;
	}
}

// Close the listener: its thread and the sidecar of the server role, which closes its REALITY listener and its streams,
// and the connections that Accept did not take
static void NodeMimicCloseListener(void *listener) {
	MIMIC_LISTENER *l = (MIMIC_LISTENER *)listener;
	NODE_MIMIC *m = l->Mimic;

	SetEvent(l->StopEvent);
	WaitForSingleObject(l->Thread, INFINITE);
	CloseHandle(l->Thread);

	NodeMimicStopSidecar(l->Sidecar);

	for (UINT i = 0; i < LIST_NUM(l->Pending); i++)
		CloseHandle(LIST_DATA(l->Pending, i));
	ReleaseList(l->Pending);

	Lock(m->ListenerLock);
	{
		m->Listener = NULL;
	}
	Unlock(m->ListenerLock);

	CloseHandle(l->StopEvent);
	CloseHandle(l->Arrived);
	NodeMimicFreePipeSa(l->Sa);
	DeleteLock(l->Lock);
	Free(l);
}

// Fill in the mimic transport of the sidecars
void NodeMimicTransportInit(NODE_MIMIC *m) {
	TRANSPORT *t = &m->Transport;

	Zero(t, sizeof(TRANSPORT));
	StrCpy(t->Name, sizeof(t->Name), NODE_MIMIC_TRANSPORT);
	t->Param = m;
	t->Dial = NodeMimicDial;
	t->Listen = NodeMimicListen;
	t->Accept = NodeMimicAccept;
	t->CloseListener = NodeMimicCloseListener;
	t->Read = NodeMimicRead;
	t->Write = NodeMimicWriteStream;
	t->Close = NodeMimicClose;
	t->Binding = NodeMimicBinding;
	t->Rekey = NULL;
	t->Queue = TRANSPORT_QUEUE_CODEL;
	t->Take = NULL;
}
