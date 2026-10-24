// FrontDoor.c
// The front door of the new core (SDN-29, #205; ADR-0035): the TCP listener that peeks the first bytes of each
// connection, routes it by its ClientHello or its first bytes (FrontDoorHello.c) and hands the socket to its owner: in
// this process through the owner's procedure, in another through the owner's handoff pipe with WSADuplicateSocketW
// (FrontDoorPipe.c is the owner's end). The front door only peeks: it reads no byte of a connection, so the owner reads
// the first bytes itself, and once it answered the handoff the front door closes its own handle and is out of the path.
//
// The listener waits on the Windows thread pool and routes each connection on a callback of the pool, so a peer that
// sends nothing holds no other back; the callbacks belong to a cleanup group, which Stop waits for. The sockets of the
// front door are not inherited by the processes that its process starts.

#include "Core/FrontDoor.h"

#include <ws2tcpip.h>

#include <string.h>

#define FRONT_DOOR_STOP_POLL 50 // How often a wait of a connection looks whether the front door stops (ms)

struct FRONT_DOOR {
	FRONT_DOOR_OWNER Owners[FRONT_DOOR_MAX_OWNERS]; // The owner table, a copy of the configuration's
	UINT NumOwners;                                 // ... its owners
	UINT PeekTimeout;                               // ms the first bytes may take to decide the owner
	UINT HandoffTimeout;                            // ms an owner process may take to answer a handoff
	SOCKET Socket;                                  // The listening socket
	USHORT Port;                                    // ... the port it bound
	WSAEVENT Event;                                 // Set while a connection waits to be accepted
	HANDLE Closing;                                 // Set once Stop runs: the connections being routed end
	PTP_WAIT Wait;                                  // The wait of the pool on Event
	TP_CALLBACK_ENVIRON Env;                        // The environment of the wait and the connections ...
	PTP_CLEANUP_GROUP Group;                        // ... and their cleanup group, which waits for every callback
	SRWLOCK Lock;                                   // Stopped
	bool Stopped;                                   // Stop runs: the wait is not set again
	bool HaveWinsock;                               // WSAStartup succeeded
	volatile LONG64 Accepted;                       // The counters of FRONT_DOOR_STATS
	volatile LONG64 Handed[FRONT_DOOR_MAX_OWNERS];
	volatile LONG64 Unrouted;
	volatile LONG64 Refused;
};

// A connection that the listener took, for the callback that routes it
typedef struct FRONT_DOOR_CONN {
	FRONT_DOOR *Door; // The front door
	SOCKET Socket;    // The connection
} FRONT_DOOR_CONN;

// The host and the port of an address: "host:port", "[ipv6]:port" or ":port" for every address; false when it is
// malformed
static bool FrontDoorSplitAddress(const char *address, char *host, UINT host_size, char *port, UINT port_size) {
	const char *colon = strrchr(address, ':');

	if (colon == NULL)
		return false;

	const char *start = address;
	UINT host_len = (UINT)(colon - address);
	UINT port_len = (UINT)strlen(colon + 1);

	if (host_len >= 2 && address[0] == '[' && colon[-1] == ']') {
		start++;
		host_len -= 2;
	}
	if (host_len >= host_size || port_len == 0 || port_len > 5 || port_len >= port_size)
		return false;

	UINT port_number = 0;
	for (UINT i = 0; i < port_len; i++) {
		if (colon[1 + i] < '0' || colon[1 + i] > '9')
			return false;
		port_number = port_number * 10 + (UINT)(colon[1 + i] - '0');
	}
	if (port_number > 65535)
		return false;

	memcpy(host, start, host_len);
	host[host_len] = 0;
	memcpy(port, colon + 1, port_len + 1);

	return true;
}

// Whether the owners of a configuration make a table: each of a kind, a byte owner with its prefix, and each owner
// either in this process (its procedure) or in another (its pipe)
static bool FrontDoorValidOwners(const FRONT_DOOR_OWNER *owners, UINT num) {
	if (owners == NULL || num == 0 || num > FRONT_DOOR_MAX_OWNERS)
		return false;

	for (UINT i = 0; i < num; i++) {
		const FRONT_DOOR_OWNER *o = &owners[i];

		if (o->Kind != FRONT_DOOR_TLS && o->Kind != FRONT_DOOR_BYTES)
			return false;
		if (o->Kind == FRONT_DOOR_BYTES && (o->PrefixSize == 0 || o->PrefixSize > FRONT_DOOR_PREFIX_SIZE))
			return false;
		if (o->Pipe[0] == 0 && o->Take == NULL)
			return false;
	}

	return true;
}

// The listening socket on host and port, every address of both families where host is empty, held exclusively
static bool FrontDoorListen(FRONT_DOOR *fd, const char *host, const char *port) {
	struct addrinfo hints, *res = NULL;
	struct sockaddr_storage local;
	int local_size = sizeof(local);
	DWORD on = 1, off = 0;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = (host[0] == 0 ? AF_INET6 : AF_UNSPEC);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host[0] == 0 ? NULL : host, port, &hints, &res) != 0)
		return false;

	SOCKET s = WSASocketW(res->ai_family, res->ai_socktype, res->ai_protocol, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
	bool ok = (s != INVALID_SOCKET && setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&on, sizeof(on)) == 0);
	if (ok && host[0] == 0)
		ok = (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof(off)) == 0);
	ZeroMemory(&local, sizeof(local));
	if (ok)
		ok = (bind(s, res->ai_addr, (int)res->ai_addrlen) == 0 && listen(s, SOMAXCONN) == 0 && getsockname(s, (struct sockaddr *)&local, &local_size) == 0);
	freeaddrinfo(res);

	if (ok == false) {
		if (s != INVALID_SOCKET)
			closesocket(s);
		return false;
	}

	fd->Socket = s;
	fd->Port = ntohs(local.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&local)->sin6_port : ((struct sockaddr_in *)&local)->sin_port);

	return true;
}

// Wait until the connection has bytes or its end: 1; 0 once end passed or the front door stops; -1 on an error
static int FrontDoorWait(FRONT_DOOR *fd, SOCKET s, UINT64 end) {
	while (true) {
		UINT64 now = GetTickCount64();
		WSAPOLLFD p;

		if (now >= end || WaitForSingleObject(fd->Closing, 0) == WAIT_OBJECT_0)
			return 0;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLRDNORM;
		int r = WSAPoll(&p, 1, (INT)(end - now < FRONT_DOOR_STOP_POLL ? end - now : FRONT_DOOR_STOP_POLL));
		if (r != 0)
			return (r > 0 ? 1 : -1);
	}
}

// The owner of a connection by its first bytes, which stay in the socket: they are peeked, never read. The bytes so
// far may decide nothing yet: the socket stays readable with them, so the front door waits FRONT_DOOR_PEEK_POLL and
// peeks again, until the peek timeout. The socket does not block here (the listener's event selection made it so).
static UINT FrontDoorPeek(FRONT_DOOR *fd, SOCKET s, UCHAR *buf) {
	UINT64 end = GetTickCount64() + fd->PeekTimeout;

	int ready = FrontDoorWait(fd, s, end);
	if (ready < 0 || WaitForSingleObject(fd->Closing, 0) == WAIT_OBJECT_0)
		return FRONT_DOOR_NONE;

	while (true) {
		int n = recv(s, (char *)buf, FRONT_DOOR_MAX_PEEK, MSG_PEEK);
		bool last = (ready == 0 || GetTickCount64() >= end);

		if (n == SOCKET_ERROR) {
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				return FRONT_DOOR_NONE;
			n = 0;
		} else if (n == 0 || n >= FRONT_DOOR_MAX_PEEK) {
			// The peer ended, or the bytes fill what the front door looks at: no more bytes count
			last = true;
		}

		UINT owner = FrontDoorRoute(fd->Owners, fd->NumOwners, buf, (UINT)n, last);
		if (owner != FRONT_DOOR_MORE)
			return owner;

		if (WaitForSingleObject(fd->Closing, FRONT_DOOR_PEEK_POLL) == WAIT_OBJECT_0)
			return FRONT_DOOR_NONE;
	}
}

// One overlapped read or write of size bytes on the pipe of an owner, within end; a wait that the front door stops or
// that times out is cancelled
static bool FrontDoorPipeIo(FRONT_DOOR *fd, HANDLE pipe, HANDLE event, bool write, void *buf, DWORD size, UINT64 end) {
	OVERLAPPED ov;
	DWORD done = 0;

	ZeroMemory(&ov, sizeof(ov));
	ov.hEvent = event;

	BOOL started = (write ? WriteFile(pipe, buf, size, NULL, &ov) : ReadFile(pipe, buf, size, NULL, &ov));
	if (started == FALSE && GetLastError() != ERROR_IO_PENDING)
		return false;

	HANDLE waits[2] = {event, fd->Closing};
	UINT64 now = GetTickCount64();
	if (WaitForMultipleObjects(2, waits, FALSE, (DWORD)(now < end ? end - now : 0)) != WAIT_OBJECT_0)
		CancelIoEx(pipe, &ov);

	return (GetOverlappedResult(pipe, &ov, &done, TRUE) && done == size);
}

// Hand a connection to an owner in another process, through its pipe: the socket duplicated into the owner process,
// whose id the pipe gives, in a handoff message, and the owner's answer. True once the owner took it; the front door's
// own handle closes after, either way. While every instance of the pipe serves another handoff, the front door waits.
static bool FrontDoorSend(FRONT_DOOR *fd, const FRONT_DOOR_OWNER *o, SOCKET s) {
	UINT64 end = GetTickCount64() + fd->HandoffTimeout;
	FRONT_DOOR_HANDOFF m;
	HANDLE pipe;
	ULONG pid = 0;
	UCHAR answer = FRONT_DOOR_NOT_TAKEN;

	while (true) {
		pipe = CreateFileW(o->Pipe, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
			break;

		UINT64 now = GetTickCount64();
		if (GetLastError() != ERROR_PIPE_BUSY || now >= end || WaitForSingleObject(fd->Closing, 0) == WAIT_OBJECT_0)
			return false;
		(void)WaitNamedPipeW(o->Pipe, (DWORD)(end - now < FRONT_DOOR_STOP_POLL ? end - now : FRONT_DOOR_STOP_POLL));
	}

	ZeroMemory(&m, sizeof(m));
	m.Magic = FRONT_DOOR_HANDOFF_MAGIC;
	m.Size = sizeof(m);

	HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
	bool ok = (event != NULL && GetNamedPipeServerProcessId(pipe, &pid) && WSADuplicateSocketW(s, pid, &m.Info) == 0);
	if (ok)
		ok = FrontDoorPipeIo(fd, pipe, event, true, &m, sizeof(m), end);
	if (ok)
		ok = (FrontDoorPipeIo(fd, pipe, event, false, &answer, 1, end) && answer == FRONT_DOOR_TAKEN);

	if (event != NULL)
		CloseHandle(event);
	CloseHandle(pipe);

	return ok;
}

// Route a connection, on a callback of the pool: peek, decide the owner, hand the socket over. It goes to the owner
// blocking; a connection that no owner takes, or whose owner does not take it, is closed. The front door's handle of a
// connection handed to another process closes once the owner answered: the owner's handle keeps the connection.
static void CALLBACK FrontDoorRouteCallback(PTP_CALLBACK_INSTANCE instance, void *param) {
	FRONT_DOOR_CONN *c = (FRONT_DOOR_CONN *)param;
	FRONT_DOOR *fd = c->Door;
	SOCKET s = c->Socket;
	u_long blocking = 0;
	bool taken = false;

	// It waits for the peer: the pool starts another thread for the next callback
	(void)CallbackMayRunLong(instance);
	HeapFree(GetProcessHeap(), 0, c);

	UCHAR *buf = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, FRONT_DOOR_MAX_PEEK);
	UINT owner = (buf != NULL ? FrontDoorPeek(fd, s, buf) : FRONT_DOOR_NONE);
	if (buf != NULL)
		HeapFree(GetProcessHeap(), 0, buf);

	if (owner >= fd->NumOwners || owner >= FRONT_DOOR_MAX_OWNERS) {
		InterlockedIncrement64(&fd->Unrouted);
		closesocket(s);
		return;
	}

	const FRONT_DOOR_OWNER *o = &fd->Owners[owner];
	if (ioctlsocket(s, FIONBIO, &blocking) == 0) {
		if (o->Pipe[0] != 0) {
			taken = FrontDoorSend(fd, o, s);
		} else {
			taken = o->Take(o->Param, s);
			if (taken)
				s = INVALID_SOCKET;
		}
	}

	InterlockedIncrement64(taken ? &fd->Handed[owner] : &fd->Refused);
	if (s != INVALID_SOCKET)
		closesocket(s);
}

// A connection that the listener took: its own event selection goes, which leaves it not blocking, no process that
// this one starts inherits it, and its route runs on a callback of the pool; it is closed when the callback cannot start
static void FrontDoorTake(FRONT_DOOR *fd, SOCKET s) {
	FRONT_DOOR_CONN *c = (FRONT_DOOR_CONN *)HeapAlloc(GetProcessHeap(), 0, sizeof(FRONT_DOOR_CONN));

	InterlockedIncrement64(&fd->Accepted);
	(void)SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, 0);
	if (c == NULL || WSAEventSelect(s, NULL, 0) != 0) {
		InterlockedIncrement64(&fd->Unrouted);
		closesocket(s);
		if (c != NULL)
			HeapFree(GetProcessHeap(), 0, c);
		return;
	}

	c->Door = fd;
	c->Socket = s;
	if (TrySubmitThreadpoolCallback(FrontDoorRouteCallback, c, &fd->Env) == false) {
		InterlockedIncrement64(&fd->Unrouted);
		closesocket(s);
		HeapFree(GetProcessHeap(), 0, c);
	}
}

// The wait of the pool on the listener's event: every connection that waits is taken, and the wait is set again
// unless the front door stops
static void CALLBACK FrontDoorAcceptCallback(PTP_CALLBACK_INSTANCE instance, void *param, PTP_WAIT wait, TP_WAIT_RESULT result) {
	FRONT_DOOR *fd = (FRONT_DOOR *)param;
	WSANETWORKEVENTS events;

	UNREFERENCED_PARAMETER(instance);
	UNREFERENCED_PARAMETER(result);

	// Reset the event, then take the connections; one that its peer reset before it was taken is skipped
	ZeroMemory(&events, sizeof(events));
	if (WSAEnumNetworkEvents(fd->Socket, fd->Event, &events) == 0) {
		while (true) {
			SOCKET s = accept(fd->Socket, NULL, NULL);

			if (s != INVALID_SOCKET)
				FrontDoorTake(fd, s);
			else if (WSAGetLastError() != WSAECONNRESET)
				break;
		}
	}

	AcquireSRWLockExclusive(&fd->Lock);
	if (fd->Stopped == false)
		SetThreadpoolWait(wait, fd->Event, NULL);
	ReleaseSRWLockExclusive(&fd->Lock);
}

// Free a front door whose wait is not set any more: close the members of the cleanup group, which waits for every
// callback that runs, then the socket and the events
static void FrontDoorFree(FRONT_DOOR *fd) {
	if (fd->Group != NULL) {
		CloseThreadpoolCleanupGroupMembers(fd->Group, FALSE, NULL);
		CloseThreadpoolCleanupGroup(fd->Group);
	}
	DestroyThreadpoolEnvironment(&fd->Env);

	if (fd->Socket != INVALID_SOCKET)
		closesocket(fd->Socket);
	if (fd->Event != WSA_INVALID_EVENT)
		WSACloseEvent(fd->Event);
	if (fd->Closing != NULL)
		CloseHandle(fd->Closing);
	if (fd->HaveWinsock)
		WSACleanup();

	HeapFree(GetProcessHeap(), 0, fd);
}

FRONT_DOOR *FrontDoorStart(const FRONT_DOOR_CONFIG *cfg) {
	char host[FRONT_DOOR_ADDRESS_SIZE];
	char port[8];
	WSADATA wsa;

	if (cfg == NULL || cfg->NumOwners > FRONT_DOOR_MAX_OWNERS || memchr(cfg->Address, 0, sizeof(cfg->Address)) == NULL ||
	    FrontDoorSplitAddress(cfg->Address, host, sizeof(host), port, sizeof(port)) == false || FrontDoorValidOwners(cfg->Owners, cfg->NumOwners) == false)
		return NULL;

	FRONT_DOOR *fd = (FRONT_DOOR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FRONT_DOOR));
	if (fd == NULL)
		return NULL;

	memcpy(fd->Owners, cfg->Owners, sizeof(FRONT_DOOR_OWNER) * cfg->NumOwners);
	fd->NumOwners = cfg->NumOwners;
	for (UINT i = 0; i < fd->NumOwners; i++) {
		FRONT_DOOR_OWNER *o = &fd->Owners[i];

		o->Name[FRONT_DOOR_NAME_SIZE - 1] = 0;
		o->ServerNames[FRONT_DOOR_LIST_SIZE - 1] = 0;
		o->Protocols[FRONT_DOOR_LIST_SIZE - 1] = 0;
		o->Pipe[FRONT_DOOR_PIPE_SIZE - 1] = 0;
	}
	fd->PeekTimeout = (cfg->PeekTimeout != 0 ? cfg->PeekTimeout : FRONT_DOOR_PEEK_TIMEOUT);
	fd->HandoffTimeout = (cfg->HandoffTimeout != 0 ? cfg->HandoffTimeout : FRONT_DOOR_HANDOFF_TIMEOUT);
	fd->Socket = INVALID_SOCKET;
	fd->Event = WSA_INVALID_EVENT;
	InitializeSRWLock(&fd->Lock);
	InitializeThreadpoolEnvironment(&fd->Env);

	ZeroMemory(&wsa, sizeof(wsa));
	fd->HaveWinsock = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	fd->Event = WSACreateEvent();
	fd->Closing = CreateEventW(NULL, TRUE, FALSE, NULL);
	fd->Group = CreateThreadpoolCleanupGroup();

	bool ok = (fd->HaveWinsock && fd->Event != WSA_INVALID_EVENT && fd->Closing != NULL && fd->Group != NULL && FrontDoorListen(fd, host, port));
	if (ok) {
		SetThreadpoolCallbackCleanupGroup(&fd->Env, fd->Group, NULL);
		fd->Wait = CreateThreadpoolWait(FrontDoorAcceptCallback, fd, &fd->Env);
		ok = (fd->Wait != NULL && WSAEventSelect(fd->Socket, fd->Event, FD_ACCEPT) == 0);
	}
	if (ok == false) {
		FrontDoorFree(fd);
		return NULL;
	}

	SetThreadpoolWait(fd->Wait, fd->Event, NULL);

	return fd;
}

USHORT FrontDoorPort(FRONT_DOOR *fd) {
	return (fd != NULL ? fd->Port : 0);
}

void FrontDoorGetStats(FRONT_DOOR *fd, FRONT_DOOR_STATS *st) {
	if (st == NULL)
		return;

	ZeroMemory(st, sizeof(FRONT_DOOR_STATS));
	if (fd == NULL)
		return;

	st->Accepted = (UINT64)InterlockedOr64(&fd->Accepted, 0);
	for (UINT i = 0; i < fd->NumOwners && i < FRONT_DOOR_MAX_OWNERS; i++)
		st->Handed[i] = (UINT64)InterlockedOr64(&fd->Handed[i], 0);
	st->Unrouted = (UINT64)InterlockedOr64(&fd->Unrouted, 0);
	st->Refused = (UINT64)InterlockedOr64(&fd->Refused, 0);
}

void FrontDoorStop(FRONT_DOOR *fd) {
	if (fd == NULL)
		return;

	// No wait is set again once Stopped is: the one that is set is taken back, and its callback, if one runs, returns
	// first. The connections being routed see Closing and end.
	AcquireSRWLockExclusive(&fd->Lock);
	fd->Stopped = true;
	ReleaseSRWLockExclusive(&fd->Lock);
	SetEvent(fd->Closing);
	SetThreadpoolWait(fd->Wait, NULL, NULL);
	WaitForThreadpoolWaitCallbacks(fd->Wait, FALSE);

	FrontDoorFree(fd);
}
