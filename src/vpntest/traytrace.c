// traytrace.c
// Named tray tracer node of vpntest ("traytrace" command, SDN-55 #248)
//
// The Node of the tray tracer (.github/scripts/tray-tracer.ps1; seam 3 of #45 as ADR-0002 amended it on 2026-10-21): a
// node of the new core in this process, as the Node service of a laptop runs, with the client role on a Wintun adapter and
// the pipe of its logged-in user, which the script names, and no Controller settings. ranz tray signs a user in at the
// controller of the tracer and gives the node the keys of that Controller on the pipe (enrol); the node takes them, starts
// its client role again and joins the Controller, which gives it its state.
//
//   vpntest traytrace <pipe> <ready> <stop>
//
// It creates the file ready once the client role runs with its pipe, stops the node once the file stop exists, and prints
// "TRAYTRACE TEST OK" when the node ran and stopped. Its Client setting names one server, whose fallback list names a port of
// the loopback interface that no node listens on: the role needs one, and the Controller of the tracer gives the node no
// peer to dial. Needs administrator rights and wintun.dll next to vpntest.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Crypto.h"
#include "Core/Peer.h"

#include <stdio.h>

#define	TRAYTRACE_WAIT		600000		// The node runs for this long at most, as long as the script waits for it (ms)
#define	TRAYTRACE_BOUND		20000		// The client role comes up within this (ms)
#define	TRAYTRACE_POLL		200			// Poll interval of the role and of the file stop (ms)

// The watchdog: a tracer whose script went away ends the process
static DWORD WINAPI TrayTraceWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, TRAYTRACE_WAIT + TRAYTRACE_BOUND) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "TRAYTRACE TEST FAILED (did not end within %u ms)\n", TRAYTRACE_WAIT + TRAYTRACE_BOUND);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void TrayTraceDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The node of the tracer, with the client role on the pipe named pipe, until the file stop exists; the file ready once the
// role runs. Whether the role ran.
static bool TrayTraceRun(char *pipe, wchar_t *ready, wchar_t *stop)
{
	wchar_t dir[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	wchar_t log_dir[MAX_PATH];
	char identity[MAX_SIZE];
	wchar_t identity_w[MAX_SIZE];
	char *setting = ZeroMalloc(NODE_CLIENT_MAX_SETTING);
	NODE_CLIENT_STATUS cs;
	UINT r = Rand32() & 0xFFFF;
	bool running = false;

	Format(identity, sizeof(identity), "Ranz traytrace %u", r);
	StrToUni(identity_w, sizeof(identity_w), identity);
	Format(setting, NODE_CLIENT_MAX_SETTING,
		"{\"adapter\":\"RanzTray%04x\",\"pipe\":\"%s\",\"servers\":[{\"name\":\"traytrace-none\","
		"\"thumbprint\":\"0000000000000000000000000000000000000000\",\"dial\":\"tls:127.0.0.1:9\"}]}", r, pipe);

	// A data directory of its own with the client role and no Controller settings, as a laptop has before its sign-in
	UniFormat(tmp, sizeof(tmp), L"traytrace_%u", Rand32());
	ConbinePathW(dir, sizeof(dir), MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);
	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "client");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsSetSetting(s, NODE_SETTING_IDENTITY_KEY, identity);
		CsSetSetting(s, NODE_SETTING_CLIENT, setting);
		CsClose(s);
	}

	NODE *n = NewNode(dir);
	NodeStart(n);

	for (UINT64 end = Tick64() + TRAYTRACE_BOUND;Tick64() < end && running == false;SleepThread(TRAYTRACE_POLL))
	{
		NodeClientGetStatus(n, &cs);
		running = cs.Running;
	}
	Print("traytrace: the client role %s, its pipe \\\\.\\pipe\\%s\n", running ? "runs" : "did not start", pipe);

	if (running)
	{
		BUF *b = NewBuf();
		WriteBuf(b, "ready\r\n", 7);
		DumpBufW(b, ready);
		FreeBuf(b);

		for (UINT64 end = Tick64() + TRAYTRACE_WAIT;Tick64() < end && IsFileExistsW(stop) == false;SleepThread(TRAYTRACE_POLL))
		{
			continue;
		}

		NodeClientGetStatus(n, &cs);
		Print("traytrace: at the end the client role %s, adapter interface %u, %I64u packets of the host taken\n", cs.Running ? "runs" : "is gone",
			cs.InterfaceIndex, cs.FromHost);
	}

	NodeStop(n);
	FreeNode(n);

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	TrayTraceDeleteDir(log_dir);
	TrayTraceDeleteDir(dir);
	PeerKeyDelete(identity_w);
	Free(setting);

	return running;
}

RANZ_TEST("traytrace", traytrace_test, "Tray tracer: a node with the client role and the pipe of the logged-in user, no Controller settings, which ranz tray enrols (.github/scripts/tray-tracer.ps1). Args: <pipe> <ready file> <stop file>.");
void traytrace_test(UINT num, char **arg)
{
	wchar_t ready[MAX_PATH];
	wchar_t stop[MAX_PATH];
	UINT error = 0;

	if (num < 3)
	{
		Print("usage: traytrace <pipe> <ready file> <stop file>\n");
		Print("TRAYTRACE TEST FAILED (usage)\n");
		return;
	}

	StrToUni(ready, sizeof(ready), arg[1]);
	StrToUni(stop, sizeof(stop), arg[2]);

	if (CryptoInit() == false || NodeWintunAvailable(&error) == false)
	{
		Print("TRAYTRACE TEST FAILED (the crypto module or wintun.dll is not there: error %u)\n", error);
		return;
	}

	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, TrayTraceWatchdog, done, 0, NULL) : NULL);

	bool ok = TrayTraceRun(arg[0], ready, stop);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ok)
	{
		Print("TRAYTRACE TEST OK\n");
	}
	else
	{
		Print("TRAYTRACE TEST FAILED (the client role did not start)\n");
	}
}
