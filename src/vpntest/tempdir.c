// tempdir.c
// Named temp directory and string table test of vpntest ("tempdir" command, SEC-8 #96)
//
// The temp directory of the process (MsGetMyTempDirW) used to be VPN_xxxx: two rand() bytes as
// the name, the access rights inherited from %TEMP%, which is C:\Windows\Temp for the service.
// The parsed string table was cached as .unicode_cache_<hash>.dat in %TEMP% and read back at the
// next start. The test pins the fix: the name holds 64 random bits, the DACL is protected and
// grants nothing to Users, Authenticated Users or Everyone, and loading a string table writes no
// cache file.
//
// FND-65 (#121): each process deletes the temp directories that earlier processes left in %TEMP%
// (MsDeleteTempDir, at start and at exit). It went into every directory it found there, also
// through junctions: a junction named like a temp directory, or one inside a stale temp directory,
// had the files of its target deleted. The service process also copied System32\imm32.dll into
// its temp directory and loaded the copy (MsDisableIme through MsLoadLibrary). The test runs
// ranz-node.exe without arguments (MsServiceEx prints its help) with TMP and TEMP set to a test
// directory that holds a stale temp directory with a junction in it and a junction named like a
// temp directory. The files in both junction targets must survive, the stale directory must go,
// and a watch on the test directory must see the child make its temp directory and no .dll file.
//
// Prints "TEMPDIR TEST OK" only when every check passes, and frees everything it allocates.

#include "testlist.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <AclAPI.h>
#include <stdarg.h>
#include <winioctl.h>

#define	TEMPDIR_PREFIX			L"VPN_"				// Prefix of the name of the temp directory
#define	TEMPDIR_RANDOM_CHARS	16					// Hex digits after the prefix: 64 random bits
#define	TEMPDIR_CACHE_PREFIX	L".unicode_cache_"	// Name prefix of the former string table cache
#define	TEMPDIR_CACHE_SUFFIX	L".dat"				// Name suffix of the former string table cache

// The stale temp directories of the junction case (FND-65), in the test directory the child uses as
// its %TEMP%: a real one with a junction in it, and a junction named like a temp directory
#define	TEMPDIR_STALE_DIR		L"VPN_0123456789ABCDEF"
#define	TEMPDIR_STALE_LINK		L"VPN_FEDCBA9876543210"
#define	TEMPDIR_NESTED_LINK		L"link"				// The junction inside TEMPDIR_STALE_DIR
#define	TEMPDIR_TOP_TARGET		L"target_top"		// Target of TEMPDIR_STALE_LINK
#define	TEMPDIR_NESTED_TARGET	L"target_nested"	// Target of TEMPDIR_NESTED_LINK
#define	TEMPDIR_SENTINEL		L"sentinel.txt"		// File in each target that must survive
#define	TEMPDIR_CHILD_EXE		L"ranz-node.exe"	// Next to vpntest.exe; without arguments MsServiceEx prints its help
#define	TEMPDIR_CHILD_TIMEOUT	120000				// Milliseconds the child may run
#define	TEMPDIR_WATCH_SIZE		65536				// Bytes of the change buffer of ReadDirectoryChangesW
#define	TEMPDIR_WATCH_IDLE		1000				// Milliseconds without a change that end the watch
#define	TEMPDIR_ENV_SIZE		1024				// Characters kept of TMP and TEMP while the child runs
#define	TEMPDIR_MOUNT_CHARS		(2 * MAX_PATH + 8)	// Characters of the path buffer of a junction

// The mount point (junction) form of REPARSE_DATA_BUFFER, which is in ntifs.h and not in the SDK
typedef struct TEMPDIR_MOUNT_POINT
{
	DWORD ReparseTag;						// IO_REPARSE_TAG_MOUNT_POINT
	USHORT ReparseDataLength;				// Bytes after Reserved
	USHORT Reserved;
	USHORT SubstituteNameOffset;			// Bytes into PathBuffer
	USHORT SubstituteNameLength;			// Bytes, without the terminator
	USHORT PrintNameOffset;					// Bytes into PathBuffer
	USHORT PrintNameLength;					// Bytes, without the terminator
	wchar_t PathBuffer[TEMPDIR_MOUNT_CHARS];	// "\??\" and the target, then the target, each terminated
} TEMPDIR_MOUNT_POINT;

// Names added under a directory tree while the child runs (ReadDirectoryChangesW)
typedef struct TEMPDIR_WATCH
{
	HANDLE Dir;							// The watched directory, opened for overlapped reads
	OVERLAPPED Overlapped;				// The pending read; its event signals a completion
	DWORD *Buf;							// TEMPDIR_WATCH_SIZE bytes, DWORD aligned as the API needs
	bool Pending;						// A read is pending
	bool Lost;							// A read failed or the system dropped changes
	UINT NumTempDirs;					// Names added that are VPN_ and 16 hex digits
	UINT NumDlls;						// Names added that end with .dll
	wchar_t FirstDll[MAX_PATH];			// The first of them, relative to the watched directory
} TEMPDIR_WATCH;

// Run state of the test
typedef struct TEMPDIR_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TEMPDIR_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail; returns ok
static bool TempDirCheck(TEMPDIR_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;

	return false;
}

// True when the last part of the path is the prefix and TEMPDIR_RANDOM_CHARS hex digits
static bool TempDirNameOk(wchar_t *path)
{
	if (path == NULL)
	{
		return false;
	}

	wchar_t *name = path;
	for (UINT i = 0;path[i] != 0;i++)
	{
		if (path[i] == L'\\' || path[i] == L'/')
		{
			name = &path[i + 1];
		}
	}

	if (UniStartWith(name, TEMPDIR_PREFIX) == false)
	{
		return false;
	}

	name += UniStrLen(TEMPDIR_PREFIX);

	if (UniStrLen(name) != TEMPDIR_RANDOM_CHARS)
	{
		return false;
	}

	for (UINT i = 0;i < TEMPDIR_RANDOM_CHARS;i++)
	{
		wchar_t c = name[i];

		if ((c >= L'0' && c <= L'9') == false && (c >= L'A' && c <= L'F') == false && (c >= L'a' && c <= L'f') == false)
		{
			return false;
		}
	}

	return true;
}

// True when the ACE list grants any access to the well-known SID
static bool TempDirAclGrants(ACL *dacl, WELL_KNOWN_SID_TYPE type)
{
	UCHAR sid_buf[SECURITY_MAX_SID_SIZE];
	DWORD sid_size = sizeof(sid_buf);

	if (dacl == NULL)
	{
		// A NULL DACL grants everything to everyone
		return true;
	}

	if (CreateWellKnownSid(type, NULL, (PSID)sid_buf, &sid_size) == FALSE)
	{
		return true;
	}

	for (UINT i = 0;i < dacl->AceCount;i++)
	{
		ACE_HEADER *h = NULL;

		if (GetAce(dacl, i, (void **)&h) == FALSE || h == NULL)
		{
			continue;
		}

		if (h->AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)h;

			if (a->Mask != 0 && EqualSid((PSID)&a->SidStart, (PSID)sid_buf))
			{
				return true;
			}
		}
	}

	return false;
}

// Number of former string table cache files in the directory
static UINT TempDirCountCacheFiles(wchar_t *dir, bool delete_them)
{
	UINT num = 0;

	DIRLIST *d = EnumDirW(dir);
	if (d == NULL)
	{
		return 0;
	}

	for (UINT i = 0;i < d->NumFiles;i++)
	{
		struct DIRENT *e = d->File[i];

		if (e->Folder == false && UniStartWith(e->FileNameW, TEMPDIR_CACHE_PREFIX) &&
			UniEndWith(e->FileNameW, TEMPDIR_CACHE_SUFFIX))
		{
			num++;

			if (delete_them)
			{
				wchar_t full[MAX_PATH];

				CombinePathW(full, sizeof(full), dir, e->FileNameW);
				FileDeleteW(full);
			}
		}
	}

	FreeDir(d);

	return num;
}

// Name of the string table of the language, or false when the list has no such language
static bool TempDirTableName(LIST *o, UINT id, bool same, char *name, UINT size)
{
	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if ((e->Id == id) == same)
		{
			Format(name, size, "|strtable_%s.stb", e->Name);
			return true;
		}
	}

	return false;
}

// Make link a junction (mount point) to the directory target, a full path without a trailing
// backslash
static bool TempDirMakeJunction(wchar_t *link, const wchar_t *target)
{
	UINT target_len = UniStrLen(target);
	UINT sub_len = 4 + target_len;		// "\??\" and the target
	DWORD bytes = 0;
	bool ret = false;

	if (target_len == 0 || sub_len + 1 + target_len + 1 > TEMPDIR_MOUNT_CHARS)
	{
		return false;
	}

	if (CreateDirectoryW(link, NULL) == FALSE)
	{
		return false;
	}

	// Substitute name (the NT path) and print name, each followed by the terminator ZeroMalloc left
	TEMPDIR_MOUNT_POINT *m = ZeroMalloc(sizeof(TEMPDIR_MOUNT_POINT));
	m->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	m->SubstituteNameOffset = 0;
	m->SubstituteNameLength = (USHORT)(sub_len * sizeof(wchar_t));
	m->PrintNameOffset = (USHORT)((sub_len + 1) * sizeof(wchar_t));
	m->PrintNameLength = (USHORT)(target_len * sizeof(wchar_t));
	m->ReparseDataLength = (USHORT)(4 * sizeof(USHORT) + (sub_len + 1 + target_len + 1) * sizeof(wchar_t));
	Copy(m->PathBuffer, L"\\??\\", 4 * sizeof(wchar_t));
	Copy(m->PathBuffer + 4, target, target_len * sizeof(wchar_t));
	Copy(m->PathBuffer + sub_len + 1, target, target_len * sizeof(wchar_t));

	HANDLE h = CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		ret = (DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, m, FIELD_OFFSET(TEMPDIR_MOUNT_POINT, SubstituteNameOffset) + m->ReparseDataLength,
			NULL, 0, &bytes, NULL) != FALSE);
		CloseHandle(h);
	}

	Free(m);

	if (ret == false)
	{
		RemoveDirectoryW(link);
	}

	return ret;
}

// Make the directory with an empty TEMPDIR_SENTINEL file in it
static bool TempDirMakeTarget(wchar_t *dir)
{
	wchar_t file[MAX_PATH];

	if (CreateDirectoryW(dir, NULL) == FALSE)
	{
		return false;
	}

	UniFormat(file, sizeof(file), L"%s\\%s", dir, TEMPDIR_SENTINEL);

	HANDLE h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	CloseHandle(h);

	return true;
}

// True when the TEMPDIR_SENTINEL file of the directory is there
static bool TempDirSentinelThere(wchar_t *dir)
{
	wchar_t file[MAX_PATH];

	UniFormat(file, sizeof(file), L"%s\\%s", dir, TEMPDIR_SENTINEL);

	return GetFileAttributesW(file) != INVALID_FILE_ATTRIBUTES;
}

// Remove what the child case made, never through a junction: the junctions first (removing one
// removes the link only), then the targets, then what the child may have left
static void TempDirCleanChildCase(wchar_t *root, wchar_t *stale_dir, wchar_t *stale_link, wchar_t *nested_link,
								  wchar_t *top_target, wchar_t *nested_target)
{
	wchar_t file[MAX_PATH];

	RemoveDirectoryW(stale_link);
	RemoveDirectoryW(nested_link);
	RemoveDirectoryW(stale_dir);

	UniFormat(file, sizeof(file), L"%s\\%s", top_target, TEMPDIR_SENTINEL);
	DeleteFileW(file);
	RemoveDirectoryW(top_target);

	UniFormat(file, sizeof(file), L"%s\\%s", nested_target, TEMPDIR_SENTINEL);
	DeleteFileW(file);
	RemoveDirectoryW(nested_target);

	MsDeleteAllFileW(root);
	RemoveDirectoryW(root);
}

// Issue the next read of the watch
static void TempDirWatchRead(TEMPDIR_WATCH *w)
{
	ResetEvent(w->Overlapped.hEvent);

	w->Pending = (ReadDirectoryChangesW(w->Dir, w->Buf, TEMPDIR_WATCH_SIZE, TRUE,
		FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, NULL, &w->Overlapped, NULL) != FALSE);

	if (w->Pending == false)
	{
		w->Lost = true;
	}
}

// Start watching the names added under the directory tree
static bool TempDirWatchStart(TEMPDIR_WATCH *w, wchar_t *dir)
{
	w->Dir = CreateFileW(dir, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	w->Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	w->Buf = ZeroMalloc(TEMPDIR_WATCH_SIZE);

	if (w->Dir == INVALID_HANDLE_VALUE || w->Overlapped.hEvent == NULL)
	{
		w->Lost = true;
		return false;
	}

	TempDirWatchRead(w);

	return w->Pending;
}

// Count one name the watch saw added (a path relative to the watched directory)
static void TempDirWatchName(TEMPDIR_WATCH *w, wchar_t *name)
{
	if (TempDirNameOk(name))
	{
		w->NumTempDirs++;
	}

	if (UniEndWith(name, L".dll"))
	{
		if (w->NumDlls == 0)
		{
			UniStrCpy(w->FirstDll, sizeof(w->FirstDll), name);
		}

		w->NumDlls++;
	}
}

// Read the changes until none comes for TEMPDIR_WATCH_IDLE milliseconds, then end the watch
static void TempDirWatchStop(TEMPDIR_WATCH *w)
{
	DWORD bytes = 0;
	UINT head = FIELD_OFFSET(FILE_NOTIFY_INFORMATION, FileName);

	while (w->Pending && WaitForSingleObject(w->Overlapped.hEvent, TEMPDIR_WATCH_IDLE) == WAIT_OBJECT_0)
	{
		UINT pos = 0;

		w->Pending = false;

		if (GetOverlappedResult(w->Dir, &w->Overlapped, &bytes, FALSE) == FALSE || bytes == 0)
		{
			// A failed read, or 0 bytes: the system dropped changes that did not fit its buffer
			w->Lost = true;
			break;
		}

		while (pos + head <= bytes)
		{
			FILE_NOTIFY_INFORMATION *n = (FILE_NOTIFY_INFORMATION *)(((UCHAR *)w->Buf) + pos);
			wchar_t name[MAX_PATH];
			UINT len = MIN(n->FileNameLength, bytes - pos - head) / sizeof(wchar_t);

			len = MIN(len, MAX_PATH - 1);
			Copy(name, n->FileName, len * sizeof(wchar_t));
			name[len] = 0;

			if (n->Action == FILE_ACTION_ADDED || n->Action == FILE_ACTION_RENAMED_NEW_NAME)
			{
				TempDirWatchName(w, name);
			}

			if (n->NextEntryOffset == 0)
			{
				break;
			}

			pos += n->NextEntryOffset;
		}

		TempDirWatchRead(w);
	}

	if (w->Pending)
	{
		// Cancel the last read and wait for it, so that the system no longer writes into Buf
		CancelIoEx(w->Dir, &w->Overlapped);
		GetOverlappedResult(w->Dir, &w->Overlapped, &bytes, TRUE);
		w->Pending = false;
	}

	if (w->Overlapped.hEvent != NULL)
	{
		CloseHandle(w->Overlapped.hEvent);
	}

	if (w->Dir != INVALID_HANDLE_VALUE)
	{
		CloseHandle(w->Dir);
	}

	Free(w->Buf);
}

// Run ranz-node.exe without arguments, with TMP and TEMP set to dir: its MsInit deletes the stale temp
// directories in dir and its exit its own one. True when it ended in time; *exit_code is its exit code.
static bool TempDirRunChild(wchar_t *dir, DWORD *exit_code)
{
	wchar_t exe_dir[MAX_PATH];
	wchar_t exe[MAX_PATH];
	wchar_t cmd[MAX_PATH + 4];
	wchar_t old_tmp[TEMPDIR_ENV_SIZE];
	wchar_t old_temp[TEMPDIR_ENV_SIZE];
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	bool ended = false;

	*exit_code = 0xFFFFFFFF;

	GetExeDirW(exe_dir, sizeof(exe_dir));
	UniFormat(exe, sizeof(exe), L"%s\\%s", exe_dir, TEMPDIR_CHILD_EXE);
	UniFormat(cmd, sizeof(cmd), L"\"%s\"", exe);

	DWORD tmp_len = GetEnvironmentVariableW(L"TMP", old_tmp, TEMPDIR_ENV_SIZE);
	DWORD temp_len = GetEnvironmentVariableW(L"TEMP", old_temp, TEMPDIR_ENV_SIZE);
	if (tmp_len >= TEMPDIR_ENV_SIZE || temp_len >= TEMPDIR_ENV_SIZE)
	{
		return false;
	}

	// The output of the child goes nowhere: none of its lines may reach the output of this test
	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	HANDLE null_out = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
	if (null_out == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	Zero(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = NULL;
	si.hStdOutput = null_out;
	si.hStdError = null_out;
	Zero(&pi, sizeof(pi));

	SetEnvironmentVariableW(L"TMP", dir);
	SetEnvironmentVariableW(L"TEMP", dir);

	// No error dialog when the child crashes: the child inherits this mode
	UINT old_mode = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
	bool started = (CreateProcessW(exe, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) != FALSE);
	SetErrorMode(old_mode);

	// Back to the variables of this process; one that was not set is removed again
	SetEnvironmentVariableW(L"TMP", tmp_len == 0 ? NULL : old_tmp);
	SetEnvironmentVariableW(L"TEMP", temp_len == 0 ? NULL : old_temp);

	CloseHandle(null_out);

	if (started)
	{
		if (WaitForSingleObject(pi.hProcess, TEMPDIR_CHILD_TIMEOUT) == WAIT_OBJECT_0)
		{
			ended = true;
		}
		else
		{
			TerminateProcess(pi.hProcess, 1);
			WaitForSingleObject(pi.hProcess, 10 * 1000);
		}

		GetExitCodeProcess(pi.hProcess, exit_code);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	return ended;
}

// (4) and (5): a child process deletes the stale temp directories of a test directory without going
// through a junction, and copies no DLL into its own temp directory
static void TempDirChildCase(TEMPDIR_CTX *ctx)
{
	wchar_t temp[MAX_PATH];
	wchar_t long_temp[MAX_PATH];
	wchar_t root[MAX_PATH];
	wchar_t stale_dir[MAX_PATH];
	wchar_t stale_link[MAX_PATH];
	wchar_t nested_link[MAX_PATH];
	wchar_t top_target[MAX_PATH];
	wchar_t nested_target[MAX_PATH];
	DWORD exit_code = 0;

	// The long form of %TEMP%: the junction targets hold the path as it is written
	DWORD len = GetTempPathW(MAX_PATH, temp);
	if (TempDirCheck(ctx, len != 0 && len < MAX_PATH, "The temp path of Windows is read", "error %u", GetLastError()) == false)
	{
		return;
	}

	len = GetLongPathNameW(temp, long_temp, MAX_PATH);
	if (len == 0 || len >= MAX_PATH)
	{
		UniStrCpy(long_temp, sizeof(long_temp), temp);
	}

	len = UniStrLen(long_temp);
	while (len >= 1 && long_temp[len - 1] == L'\\')
	{
		long_temp[--len] = 0;
	}

	UniFormat(root, sizeof(root), L"%s\\ranz_tempdir_%u", long_temp, MsGetCurrentProcessId());
	UniFormat(stale_dir, sizeof(stale_dir), L"%s\\%s", root, TEMPDIR_STALE_DIR);
	UniFormat(stale_link, sizeof(stale_link), L"%s\\%s", root, TEMPDIR_STALE_LINK);
	UniFormat(nested_link, sizeof(nested_link), L"%s\\%s", stale_dir, TEMPDIR_NESTED_LINK);
	UniFormat(top_target, sizeof(top_target), L"%s\\%s", root, TEMPDIR_TOP_TARGET);
	UniFormat(nested_target, sizeof(nested_target), L"%s\\%s", root, TEMPDIR_NESTED_TARGET);

	// Leftovers of an earlier run with the same process id
	TempDirCleanChildCase(root, stale_dir, stale_link, nested_link, top_target, nested_target);

	bool setup = CreateDirectoryW(root, NULL) && TempDirMakeTarget(top_target) && TempDirMakeTarget(nested_target) &&
		CreateDirectoryW(stale_dir, NULL) && TempDirMakeJunction(nested_link, nested_target) &&
		TempDirMakeJunction(stale_link, top_target);

	if (TempDirCheck(ctx, setup, "A test directory with a stale temp directory, two junctions and their targets is made",
		"error %u", GetLastError()) == false)
	{
		TempDirCleanChildCase(root, stale_dir, stale_link, nested_link, top_target, nested_target);
		return;
	}

	TEMPDIR_WATCH *w = ZeroMalloc(sizeof(TEMPDIR_WATCH));
	bool watching = TempDirWatchStart(w, root);

	bool ended = TempDirRunChild(root, &exit_code);

	TempDirWatchStop(w);

	TempDirCheck(ctx, ended && exit_code == 0, "ranz-node.exe without arguments ran with the test directory as its %TEMP% and ended",
		"ended %u, exit code 0x%X", ended, (UINT)exit_code);

	TempDirCheck(ctx, w->NumTempDirs >= 1, "The child made its temp directory in the test directory",
		"%u temp directories seen", w->NumTempDirs);

	TempDirCheck(ctx, TempDirSentinelThere(top_target), "A junction named like a stale temp directory is not followed: the file in its target survives",
		"%S was deleted through %S", TEMPDIR_SENTINEL, TEMPDIR_STALE_LINK);

	TempDirCheck(ctx, TempDirSentinelThere(nested_target), "A junction in a stale temp directory is not followed: the file in its target survives",
		"%S was deleted through %S\\%S", TEMPDIR_SENTINEL, TEMPDIR_STALE_DIR, TEMPDIR_NESTED_LINK);

	TempDirCheck(ctx, GetFileAttributesW(stale_dir) == INVALID_FILE_ATTRIBUTES, "The stale temp directory is deleted",
		"%S is still there", TEMPDIR_STALE_DIR);

	TempDirCheck(ctx, watching && w->Lost == false, "The watch on the test directory saw every change",
		"a read failed or changes were dropped");

	TempDirCheck(ctx, w->NumDlls == 0, "No DLL is copied into the temp directory (MsDisableIme copied imm32.dll there and loaded the copy)",
		"%u .dll files added, the first %S", w->NumDlls, w->FirstDll);

	Free(w);

	TempDirCleanChildCase(root, stale_dir, stale_link, nested_link, top_target, nested_target);
}

// tempdir: the temp directory has a 64-bit random name and a protected DACL; loading a string
// table writes no cache file to %TEMP%; stale temp directories go without a junction being
// followed, and no DLL is copied into the temp directory
RANZ_TEST("tempdir", tempdir_test, "Temp directory: 64-bit random name, protected DACL; loading a string table writes no cache file.");
void tempdir_test(UINT num, char **arg)
{
	TEMPDIR_CTX ctx;
	wchar_t sys_temp[MAX_PATH];
	PSECURITY_DESCRIPTOR sd = NULL;
	ACL *dacl = NULL;
	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	DWORD err;
	LIST *langs;
	char cur_table[MAX_SIZE];
	char other_table[MAX_SIZE];
	UINT lang_id;
	UINT before;
	UINT after;
	bool loaded;

	Zero(&ctx, sizeof(ctx));

	Print("Temp directory and string table test (MsGetMyTempDirW, LoadTable)\n");

	// (1) The name of the temp directory of the process
	wchar_t *dir = MsGetMyTempDirW();
	Print("  temp directory: %S\n", dir == NULL ? L"(none)" : dir);

	TempDirCheck(&ctx, TempDirNameOk(dir), "The temp directory name is VPN_ and 16 hex digits (64 random bits)",
		"name \"%S\"", dir == NULL ? L"" : dir);

	// (2) Its DACL: protected, nothing for Users, Authenticated Users or Everyone
	err = GetNamedSecurityInfoW(dir == NULL ? L"" : dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		NULL, NULL, &dacl, NULL, &sd);

	TempDirCheck(&ctx, err == ERROR_SUCCESS, "The DACL of the temp directory can be read", "error %u", err);

	if (err == ERROR_SUCCESS)
	{
		GetSecurityDescriptorControl(sd, &control, &revision);

		TempDirCheck(&ctx, (control & SE_DACL_PROTECTED) != 0, "The DACL is protected: nothing is inherited from %TEMP%",
			"control 0x%04X", (UINT)control);

		TempDirCheck(&ctx, TempDirAclGrants(dacl, WinBuiltinUsersSid) == false, "The DACL grants nothing to Users",
			"an allow entry for Users");

		TempDirCheck(&ctx, TempDirAclGrants(dacl, WinAuthenticatedUserSid) == false, "The DACL grants nothing to Authenticated Users",
			"an allow entry for Authenticated Users");

		TempDirCheck(&ctx, TempDirAclGrants(dacl, WinWorldSid) == false, "The DACL grants nothing to Everyone",
			"an allow entry for Everyone");
	}

	if (sd != NULL)
	{
		LocalFree(sd);
	}

	// (3) Loading a string table writes no cache file to %TEMP%
	StrToUni(sys_temp, sizeof(sys_temp), MsGetTempDir());

	before = TempDirCountCacheFiles(sys_temp, true);
	Print("  cache files removed before the reload: %u\n", before);

	lang_id = GetCurrentLangId();
	langs = LoadLangList();

	loaded = false;
	if (langs != NULL &&
		TempDirTableName(langs, lang_id, true, cur_table, sizeof(cur_table)) &&
		TempDirTableName(langs, lang_id, false, other_table, sizeof(other_table)))
	{
		// Another table first, so the current one is parsed again and not kept
		loaded = LoadTable(other_table) && LoadTable(cur_table);
	}

	FreeLangList(langs);

	TempDirCheck(&ctx, loaded, "Another string table and the current one load again", "LoadTable failed or fewer than two languages");

	TempDirCheck(&ctx, StrCmpi(_SS("STRTABLE_ID"), STRTABLE_ID) == 0 && _II("LANG") == lang_id,
		"The current string table is back in use", "STRTABLE_ID \"%s\", LANG %u, expected %u", _SS("STRTABLE_ID"), _II("LANG"), lang_id);

	after = TempDirCountCacheFiles(sys_temp, true);

	TempDirCheck(&ctx, after == 0, "Loading string tables writes no .unicode_cache_*.dat file to %TEMP%",
		"%u cache files written", after);

	// (4) and (5) Stale temp directories with junctions, and no DLL copy, in a child process
	TempDirChildCase(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("TEMPDIR TEST OK\n");
	}
	else
	{
		Print("TEMPDIR TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
