// nodestatetest.c
// Named node state test of vpntest ("nodestate" command, SDN-91 #396): the answer of the admin pipe of a Node to the
// command state, which ranz node state prints, and the local channel that it comes on. The first-test job
// (.github/scripts/first-test.ps1) reads the state of the Node service of its runner joined to a real Controller; this
// test checks what needs none:
// - The state of a running node names its Roles, its control stream (not connected, and why: no Controller settings),
//   its adapters, its Noise sessions, the number of its peers, its EVPN, which does not run, with the counters of its frames
//   at 0 (SDN-25-R3 #571), and its listeners.
// - The admin pipe refuses a caller that is neither SYSTEM nor an administrator: the test asks it as an ordinary user, a
//   token of its own account in which the Administrators and SYSTEM are deny-only, and the open fails with access
//   denied. The same caller as an administrator is answered after that.
// - A stopped node has no admin pipe, which is how ranz node state tells that the service is stopped.
// Print "NODESTATE TEST OK" only when every check passes. Needs an elevated window, as the admin pipe lets in only SYSTEM
// and the Administrators.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#define	NODESTATE_WAIT		20000		// The admin pipe answers within this time (ms)
#define	NODESTATE_POLL		50			// Poll interval of a busy pipe (ms)
#define	NODESTATE_REPLY		65536		// Bytes of an answer of the admin pipe at most (NODE_ADMIN_REPLY)

// The checks of the test
typedef struct NODESTATE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} NODESTATE_CTX;

static bool NodeStateCheck(NODESTATE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NodeStateCheck(NODESTATE_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 4];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// Open the admin pipe pipe, waiting while it is busy: INVALID_HANDLE_VALUE with the error of the last open in *error
static HANDLE NodeStateOpen(wchar_t *pipe, DWORD *error)
{
	wchar_t path[MAX_PATH];
	HANDLE h = INVALID_HANDLE_VALUE;

	*error = ERROR_SUCCESS;
	UniFormat(path, sizeof(path), L"\\\\.\\pipe\\%s", pipe);

	for (UINT64 end = Tick64() + NODESTATE_WAIT;h == INVALID_HANDLE_VALUE && Tick64() < end;)
	{
		h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h != INVALID_HANDLE_VALUE)
		{
			break;
		}
		*error = GetLastError();
		if (*error != ERROR_PIPE_BUSY)
		{
			break;
		}
		WaitNamedPipeW(path, NODESTATE_POLL);
	}

	return h;
}

// One command on the admin pipe, as ranz node sends it, and its answer line into reply, without its newline
static bool NodeStateAsk(wchar_t *pipe, char *command, char *reply, UINT size)
{
	char line[MAX_SIZE];
	DWORD n = 0;
	DWORD error = 0;
	UINT used = 0;

	StrCpy(reply, size, "");
	HANDLE h = NodeStateOpen(pipe, &error);
	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Format(line, sizeof(line), "%s\n", command);
	bool ok = (WriteFile(h, line, StrLen(line), &n, NULL) && n == StrLen(line));
	while (ok && used < size - 1 && InStr(reply, "\n") == false)
	{
		ok = (ReadFile(h, reply + used, size - 1 - used, &n, NULL) && n != 0);
		used += (ok ? n : 0);
		reply[used] = 0;
	}
	CloseHandle(h);

	TrimCrlf(reply);
	return (ok && IsEmptyStr(reply) == false);
}

// Open the admin pipe as an ordinary user: the account of the process with the Administrators and SYSTEM deny-only, in a
// restricted token that the thread impersonates while it opens the pipe. The error of the open into *error; false when
// the token cannot be made or impersonated.
static bool NodeStateOpenAsUser(wchar_t *pipe, DWORD *error)
{
	BYTE admins[SECURITY_MAX_SID_SIZE];
	BYTE system[SECURITY_MAX_SID_SIZE];
	DWORD admins_size = sizeof(admins);
	DWORD system_size = sizeof(system);
	SID_AND_ATTRIBUTES disable[2];
	HANDLE token = NULL;
	HANDLE user = NULL;
	bool ok = false;

	*error = ERROR_SUCCESS;
	if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins, &admins_size) == FALSE ||
		CreateWellKnownSid(WinLocalSystemSid, NULL, system, &system_size) == FALSE ||
		OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &token) == FALSE)
	{
		return false;
	}

	Zero(disable, sizeof(disable));
	disable[0].Sid = admins;
	disable[1].Sid = system;
	if (CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 2, disable, 0, NULL, 0, NULL, &user) && ImpersonateLoggedOnUser(user))
	{
		HANDLE h = NodeStateOpen(pipe, error);

		RevertToSelf();
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
		}
		ok = true;
	}

	if (user != NULL)
	{
		CloseHandle(user);
	}
	CloseHandle(token);

	return ok;
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs the server
// role on one worker
static void NodeStateNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"nodestate_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of the node log and of a data directory, then both directories
static void NodeStateDeleteDir(wchar_t *dir)
{
	wchar_t log_dir[MAX_PATH];

	ConbinePathW(log_dir, sizeof(log_dir), dir, NODE_LOG_DIR_NAME);
	for (UINT k = 0;k < 2;k++)
	{
		wchar_t *d_path = (k == 0 ? log_dir : dir);
		DIRLIST *d = EnumDirW(d_path);

		for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
		{
			wchar_t path[MAX_PATH];

			if (d->File[i]->Folder == false)
			{
				ConbinePathW(path, sizeof(path), d_path, d->File[i]->FileNameW);
				FileDeleteW(path);
			}
		}
		FreeDir(d);
		DeleteDirW(d_path);
	}
}

RANZ_TEST("nodestate", nodestate_test, "State of a Node on its admin pipe (SDN-91): Roles, control stream, adapters, sessions and listeners, refused for an ordinary user, no pipe once stopped.");
void nodestate_test(UINT num, char **arg)
{
	NODESTATE_CTX *ctx = ZeroMalloc(sizeof(NODESTATE_CTX));
	char *reply = ZeroMalloc(NODESTATE_REPLY);
	wchar_t pipe[MAX_SIZE];
	wchar_t dir[MAX_PATH] = {0};
	DWORD error = 0;

	Print("Node state: the answer of the admin pipe of a Node to state, and who may ask it\n");

	UniFormat(pipe, sizeof(pipe), L"ranz-nodestate-%u", Rand32() & 0xFFFF);
	NodeStateNewDir(dir, sizeof(dir));
	NODE *n = NewNode(dir);
	UniStrCpy(n->AdminPipe, sizeof(n->AdminPipe), pipe);
	NodeStart(n);

	// The state of a running node with no role and no Controller settings
	bool asked = NodeStateAsk(pipe, "state", reply, NODESTATE_REPLY);
	// A refused command is an object with error alone; the front door of a state has an error of its own, "" here
	NodeStateCheck(ctx, asked && StartWith(reply, "{\"error\"") == false, "state: the admin pipe answers the command", "the answer is %s", reply);
	NodeStateCheck(ctx, InStr(reply, "\"running\":true") && InStr(reply, "\"roles\":"), "state: the node runs, with its Roles", "the answer is %s", reply);
	NodeStateCheck(ctx, InStr(reply, "\"controlStream\":{") && InStr(reply, "\"connected\":false") && InStr(reply, "the node has no Controller settings"),
		"state: the control stream is not connected, and says why", "the answer is %s", reply);
	NodeStateCheck(ctx, InStr(reply, "\"adapters\":[]") && InStr(reply, "\"sessions\":[]") && InStr(reply, "\"numPeers\":0"),
		"state: no adapter and no session without an overlay", "the answer is %s", reply);
	NodeStateCheck(ctx, InStr(reply, "\"listeners\":{") && InStr(reply, "\"frontDoor\":{") && InStr(reply, "\"relayUdpPort\":0"),
		"state: the listeners, none of them running", "the answer is %s", reply);
	// The EVPN of a gateway (SDN-25-R3, #571): none runs, and each counter of its frames, the frames of unknown VTEPs among them, is 0
	NodeStateCheck(ctx, InStr(reply, "\"evpn\":{\"running\":false,\"udpPort\":0,\"fabricPort\":0,\"vrfs\":0,\"routes\":0,\"sent\":0,\"failed\":0,\"delivered\":0,"
		"\"undelivered\":0,\"unknownVtep\":0,\"strangers\":0,\"notOurs\":0,\"unknownVni\":0,\"malformed\":0}"),
		"state: no EVPN runs, and the counters of its frames are 0", "the answer is %s", reply);
	// What the limits for a source of the front door and of QUIC refused (AUD1-DT-3, #451): none yet
	NodeStateCheck(ctx, InStr(reply, "\"refused\":{\"tcp\":{\"pending\":0,\"sources\":0,\"admitted\":0,\"refusedFull\":0,\"refusedSource\":0,\"refusedRate\":0,\"refusedHandshake\":0}") &&
		InStr(reply, "\"quic\":{\"pending\":0") && InStr(reply, "\"retryMemoryLimit\":0,\"retrying\":false,\"retries\":0"),
		"state: the refusals of the limits for a source, none yet", "the answer is %s", reply);

	// An ordinary user is refused, and the administrator is answered after that
	bool as_user = NodeStateOpenAsUser(pipe, &error);
	NodeStateCheck(ctx, as_user && error == ERROR_ACCESS_DENIED, "the admin pipe refuses an ordinary user", "the token was %s, the open ended with the error %u",
		(as_user ? "made" : "not made"), (UINT)error);
	NodeStateCheck(ctx, NodeStateAsk(pipe, "state", reply, NODESTATE_REPLY) && InStr(reply, "\"running\":true"), "the admin pipe answers an administrator after that", "the answer is %s", reply);

	// A stopped node has no admin pipe
	NodeStop(n);
	HANDLE h = NodeStateOpen(pipe, &error);
	if (h != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h);
	}
	NodeStateCheck(ctx, h == INVALID_HANDLE_VALUE && error == ERROR_FILE_NOT_FOUND, "a stopped node has no admin pipe", "the open ended with the error %u", (UINT)error);

	FreeNode(n);
	NodeStateDeleteDir(dir);
	Free(reply);

	if (ctx->NumFailed == 0)
	{
		Print("NODESTATE TEST OK\n");
	}
	else
	{
		Print("NODESTATE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}
	Free(ctx);
}
