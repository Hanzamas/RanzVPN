// FrontDoorPipe.c
// The handoff pipe of an owner process (SDN-29, #205; ADR-0035): the end of the front door's handoff in a process that
// owns a protocol on TCP 443. One instance of the named pipe, served on a thread of its own: a front door connects and
// writes a handoff message, the owner makes its own socket of the WSAPROTOCOL_INFOW in it (WSASocketW with
// FROM_PROTOCOL_INFO) and answers, and the socket waits for Accept. The instance serves the next handoff once the
// front door closed its end, so the answer is read before the instance disconnects; a front door that comes meanwhile
// waits for it (ERROR_PIPE_BUSY, WaitNamedPipeW). The pipe takes local clients only.

#include "Core/FrontDoor.h"

#include <sddl.h>

#define FRONT_DOOR_PIPE_BACKLOG 16   // Sockets that wait for Accept at most: a handoff beyond them is refused
#define FRONT_DOOR_PIPE_RETRY   10   // How long the thread waits after a connect of the pipe failed (ms)
#define FRONT_DOOR_PIPE_BUFFER  4096 // The buffers of the pipe (bytes): a handoff message and an answer fit

struct FRONT_DOOR_PIPE {
	HANDLE Pipe;                           // The instance of the pipe
	HANDLE Io;                             // The event of its overlapped I/O
	HANDLE Stop;                           // Set by Free: the thread ends
	HANDLE Thread;                         // The thread that serves the pipe
	SRWLOCK Lock;                          // The fields below
	CONDITION_VARIABLE Changed;            // A socket was queued, an Accept returned, or the pipe closes
	SOCKET Queue[FRONT_DOOR_PIPE_BACKLOG]; // The sockets handed over and not accepted yet, oldest first ...
	UINT NumQueued;                        // ... their number
	UINT NumWaiting;                       // The Accept calls that wait
	bool Closed;                           // Free runs
	bool HaveWinsock;                      // WSAStartup succeeded
};

// Wait for an overlapped I/O of the pipe within timeout ms: true once it completed, with the bytes it moved in done;
// false when it failed, or Stop was set or the time passed, which cancels it. A connect whose front door came first
// completed at once (ERROR_PIPE_CONNECTED).
static bool FrontDoorPipeWait(FRONT_DOOR_PIPE *p, OVERLAPPED *ov, BOOL started, DWORD timeout, DWORD *done) {
	HANDLE waits[2] = {p->Io, p->Stop};

	*done = 0;
	if (started == FALSE) {
		DWORD error = GetLastError();

		if (error == ERROR_PIPE_CONNECTED)
			return true;
		if (error != ERROR_IO_PENDING)
			return false;
	}

	if (WaitForMultipleObjects(2, waits, FALSE, timeout) != WAIT_OBJECT_0)
		CancelIoEx(p->Pipe, ov);

	return (GetOverlappedResult(p->Pipe, ov, done, TRUE) != FALSE);
}

// Serve one front door that connected: read its handoff message, make the socket, answer, wait until the front door
// closed its end, and queue the socket for Accept
static void FrontDoorPipeServe(FRONT_DOOR_PIPE *p) {
	UCHAR message[sizeof(FRONT_DOOR_HANDOFF) + 1];
	WSAPROTOCOL_INFOW info;
	OVERLAPPED ov;
	DWORD got = 0;
	SOCKET s = INVALID_SOCKET;
	UCHAR answer, end;

	// One byte more than a message of this version: a longer one is none
	ZeroMemory(&ov, sizeof(ov));
	ov.hEvent = p->Io;
	bool ok = FrontDoorPipeWait(p, &ov, ReadFile(p->Pipe, message, sizeof(message), NULL, &ov), FRONT_DOOR_HANDOFF_TIMEOUT, &got);
	if (ok)
		ok = FrontDoorHandoffDecode(message, got, &info);

	AcquireSRWLockExclusive(&p->Lock);
	bool room = (p->Closed == false && p->NumQueued < FRONT_DOOR_PIPE_BACKLOG);
	ReleaseSRWLockExclusive(&p->Lock);

	if (ok && room)
		s = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

	answer = (s != INVALID_SOCKET ? FRONT_DOOR_TAKEN : FRONT_DOOR_NOT_TAKEN);
	ZeroMemory(&ov, sizeof(ov));
	ov.hEvent = p->Io;
	(void)FrontDoorPipeWait(p, &ov, WriteFile(p->Pipe, &answer, 1, NULL, &ov), FRONT_DOOR_HANDOFF_TIMEOUT, &got);

	// The front door reads the answer and closes its end, which ends this read: a disconnect before would drop the
	// answer
	ZeroMemory(&ov, sizeof(ov));
	ov.hEvent = p->Io;
	(void)FrontDoorPipeWait(p, &ov, ReadFile(p->Pipe, &end, 1, NULL, &ov), FRONT_DOOR_HANDOFF_TIMEOUT, &got);

	if (s == INVALID_SOCKET)
		return;

	// The socket goes to Accept blocking, as the front door handed it
	u_long blocking = 0;
	(void)ioctlsocket(s, FIONBIO, &blocking);

	AcquireSRWLockExclusive(&p->Lock);
	if (p->Closed == false && p->NumQueued < FRONT_DOOR_PIPE_BACKLOG) {
		p->Queue[p->NumQueued++] = s;
		s = INVALID_SOCKET;
		WakeAllConditionVariable(&p->Changed);
	}
	ReleaseSRWLockExclusive(&p->Lock);

	if (s != INVALID_SOCKET)
		closesocket(s);
}

// The thread of the pipe: one front door after the other until Free
static DWORD WINAPI FrontDoorPipeThread(LPVOID param) {
	FRONT_DOOR_PIPE *p = (FRONT_DOOR_PIPE *)param;

	while (WaitForSingleObject(p->Stop, 0) != WAIT_OBJECT_0) {
		OVERLAPPED ov;
		DWORD done = 0;

		ZeroMemory(&ov, sizeof(ov));
		ov.hEvent = p->Io;
		if (FrontDoorPipeWait(p, &ov, ConnectNamedPipe(p->Pipe, &ov), INFINITE, &done))
			FrontDoorPipeServe(p);
		else
			(void)WaitForSingleObject(p->Stop, FRONT_DOOR_PIPE_RETRY);

		DisconnectNamedPipe(p->Pipe);
	}

	return 0;
}

// Close what a pipe holds; its thread ended or never ran
static void FrontDoorPipeRelease(FRONT_DOOR_PIPE *p) {
	for (UINT i = 0; i < p->NumQueued; i++)
		closesocket(p->Queue[i]);

	if (p->Pipe != INVALID_HANDLE_VALUE)
		CloseHandle(p->Pipe);
	if (p->Io != NULL)
		CloseHandle(p->Io);
	if (p->Stop != NULL)
		CloseHandle(p->Stop);
	if (p->HaveWinsock)
		WSACleanup();

	HeapFree(GetProcessHeap(), 0, p);
}

FRONT_DOOR_PIPE *FrontDoorPipeNew(const wchar_t *name, const wchar_t *sddl) {
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	WSADATA wsa;

	if (name == NULL || name[0] == 0)
		return NULL;

	FRONT_DOOR_PIPE *p = (FRONT_DOOR_PIPE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FRONT_DOOR_PIPE));
	if (p == NULL)
		return NULL;

	p->Pipe = INVALID_HANDLE_VALUE;
	InitializeSRWLock(&p->Lock);
	InitializeConditionVariable(&p->Changed);

	ZeroMemory(&wsa, sizeof(wsa));
	p->HaveWinsock = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	p->Io = CreateEventW(NULL, TRUE, FALSE, NULL);
	p->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);

	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = FALSE;
	bool ok = (p->HaveWinsock && p->Io != NULL && p->Stop != NULL);
	if (ok && sddl != NULL) {
		ok = (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL) != FALSE);
		sa.lpSecurityDescriptor = sd;
	}

	// The first instance: a process that took the name first makes this fail
	if (ok) {
		p->Pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
		                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, FRONT_DOOR_PIPE_BUFFER,
		                           FRONT_DOOR_PIPE_BUFFER, 0, &sa);
		ok = (p->Pipe != INVALID_HANDLE_VALUE);
	}
	if (sd != NULL)
		LocalFree(sd);

	if (ok) {
		p->Thread = CreateThread(NULL, 0, FrontDoorPipeThread, p, 0, NULL);
		ok = (p->Thread != NULL);
	}
	if (ok == false) {
		FrontDoorPipeRelease(p);
		return NULL;
	}

	return p;
}

SOCKET FrontDoorPipeAccept(FRONT_DOOR_PIPE *p, UINT timeout) {
	SOCKET s = INVALID_SOCKET;

	if (p == NULL)
		return INVALID_SOCKET;

	UINT64 end = GetTickCount64() + timeout;

	AcquireSRWLockExclusive(&p->Lock);
	p->NumWaiting++;
	while (p->NumQueued == 0 && p->Closed == false) {
		DWORD wait = INFINITE;

		if (timeout != INFINITE) {
			UINT64 now = GetTickCount64();
			if (now >= end)
				break;
			wait = (DWORD)(end - now);
		}
		SleepConditionVariableSRW(&p->Changed, &p->Lock, wait, 0);
	}

	if (p->NumQueued != 0 && p->Closed == false) {
		s = p->Queue[0];
		p->NumQueued--;
		MoveMemory(p->Queue, p->Queue + 1, sizeof(SOCKET) * p->NumQueued);
	}
	p->NumWaiting--;
	WakeAllConditionVariable(&p->Changed);
	ReleaseSRWLockExclusive(&p->Lock);

	return s;
}

void FrontDoorPipeFree(FRONT_DOOR_PIPE *p) {
	if (p == NULL)
		return;

	// The Accept calls that wait return; the thread ends its I/O and returns
	AcquireSRWLockExclusive(&p->Lock);
	p->Closed = true;
	WakeAllConditionVariable(&p->Changed);
	ReleaseSRWLockExclusive(&p->Lock);
	SetEvent(p->Stop);
	WaitForSingleObject(p->Thread, INFINITE);
	CloseHandle(p->Thread);

	AcquireSRWLockExclusive(&p->Lock);
	while (p->NumWaiting != 0)
		SleepConditionVariableSRW(&p->Changed, &p->Lock, INFINITE, 0);
	ReleaseSRWLockExclusive(&p->Lock);

	FrontDoorPipeRelease(p);
}
