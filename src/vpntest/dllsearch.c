// dllsearch.c
// Named DLL search order test of vpntest ("dllsearch" command, FIX-4 #100)
//
// Pins the directories that a dynamic load of a DLL named without a path searches once the
// process has started: InitProcessCallOnce() sets the default DLL directories of the process to
// LOAD_LIBRARY_SEARCH_DEFAULT_DIRS. A DLL next to the executable, in System32 or in a directory
// added with AddDllDirectory is found; one in the current directory or in a directory of PATH is
// not. Each probe is a copy of System32\version.dll under a name of its own, so that no other
// file and no module already loaded answers for it. The former SetDllDirectory("") also kept the
// current directory out, but searched PATH and never the AddDllDirectory directories: two checks
// fail on it. Prints "DLLSEARCH TEST OK" only when every check passes, and frees everything it
// allocates. The [PASS] lines carry no values; the [FAIL] details do.

#include "testlist.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

// The probes: copies of DLLSEARCH_SOURCE (System32), one name per place that is searched or not
#define	DLLSEARCH_SOURCE		L"version.dll"
#define	DLLSEARCH_APP_DLL		L"ranz_dllsearch_app.dll"		// Next to the executable
#define	DLLSEARCH_CWD_DLL		L"ranz_dllsearch_cwd.dll"		// In the current directory
#define	DLLSEARCH_PATH_DLL		L"ranz_dllsearch_path.dll"		// In a directory of PATH
#define	DLLSEARCH_USER_DLL		L"ranz_dllsearch_user.dll"		// In a directory added with AddDllDirectory

// Directories of the probes in the temporary directory of the process (MsGetMyTempDirW)
#define	DLLSEARCH_CWD_DIR		L"dllsearch_cwd"
#define	DLLSEARCH_PATH_DIR		L"dllsearch_path"
#define	DLLSEARCH_USER_DIR		L"dllsearch_user"

// Run state of the test
typedef struct DLLSEARCH_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
	wchar_t Source[MAX_PATH];			// Full path of DLLSEARCH_SOURCE in System32
} DLLSEARCH_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static bool DllSearchCheck(DLLSEARCH_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
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

// Make the directory dir\sub (full path in dir_path) and copy the source DLL into it as name
// (full path in dll_path). False, with a [FAIL] line, when either step fails.
static bool DllSearchPlace(DLLSEARCH_CTX *ctx, wchar_t *dir_path, UINT dir_size, wchar_t *dll_path, UINT dll_size,
						   wchar_t *dir, wchar_t *sub, wchar_t *name)
{
	char what[MAX_SIZE];

	if (sub == NULL)
	{
		UniStrCpy(dir_path, dir_size, dir);
	}
	else
	{
		CombinePathW(dir_path, dir_size, dir, sub);
		MakeDirW(dir_path);
	}

	CombinePathW(dll_path, dll_size, dir_path, name);

	bool ok = (CopyFileW(ctx->Source, dll_path, FALSE) != FALSE);
	UINT err = GetLastError();
	if (ok)
	{
		return true;
	}

	Format(what, sizeof(what), "Copy %S to %S", DLLSEARCH_SOURCE, dll_path);
	DllSearchCheck(ctx, false, what, "error %u", err);

	return false;
}

// Load name, given without a path, the way the VPN code does (LoadLibraryW) and free it again.
// True when a module was loaded, with its file in found; false with the error in err otherwise.
static bool DllSearchLoad(wchar_t *name, wchar_t *found, UINT found_size, UINT *err)
{
	found[0] = 0;
	*err = 0;

	HMODULE h = LoadLibraryW(name);
	if (h == NULL)
	{
		*err = GetLastError();
		return false;
	}

	GetModuleFileNameW(h, found, found_size / sizeof(wchar_t));
	FreeLibrary(h);

	return true;
}

// Check that name, given without a path, is not found: the load fails with ERROR_MOD_NOT_FOUND
static void DllSearchCheckMissing(DLLSEARCH_CTX *ctx, wchar_t *name, char *what)
{
	wchar_t found[MAX_PATH];
	UINT err;
	bool loaded = DllSearchLoad(name, found, sizeof(found), &err);

	if (loaded)
	{
		DllSearchCheck(ctx, false, what, "loaded from %S", found);
	}
	else
	{
		DllSearchCheck(ctx, err == ERROR_MOD_NOT_FOUND, what, "error %u, expected %u", err, (UINT)ERROR_MOD_NOT_FOUND);
	}
}

// Check that name, given without a path, is found
static void DllSearchCheckFound(DLLSEARCH_CTX *ctx, wchar_t *name, char *what)
{
	wchar_t found[MAX_PATH];
	UINT err;
	bool loaded = DllSearchLoad(name, found, sizeof(found), &err);

	DllSearchCheck(ctx, loaded, what, "error %u", err);
}

// dllsearch: where a dynamic load of a DLL named without a path looks
RANZ_TEST("dllsearch", dllsearch_test, "DLL search order: next to the executable, System32 and AddDllDirectory, never the current directory or PATH.");
void dllsearch_test(UINT num, char **arg)
{
	DLLSEARCH_CTX ctx;
	wchar_t exe_dir[MAX_PATH];
	wchar_t dir[MAX_PATH];
	wchar_t dll[MAX_PATH];
	wchar_t old_cwd[MAX_PATH];
	wchar_t *old_path, *new_path;
	UINT len, old_path_len, new_path_size;
	DLL_DIRECTORY_COOKIE cookie;
	UINT err;
	bool ok;

	Zero(&ctx, sizeof(ctx));

	Print("DLL search order test\n");

	CombinePathW(ctx.Source, sizeof(ctx.Source), MsGetSystem32DirW(), DLLSEARCH_SOURCE);
	GetExeDirW(exe_dir, sizeof(exe_dir));

#ifdef	RANZ_ASAN
	// The ASan runtime DLL is a static import of every executable of this build
	// (cmake/RanzSanitizers.cmake): the loader resolved it from the directory of the executable
	// before main(), so the default DLL directories set at process start never apply to it
	DllSearchCheck(&ctx, GetModuleHandleW(L"clang_rt.asan_dynamic-x86_64.dll") != NULL || GetModuleHandleW(L"clang_rt.asan_dynamic.dll") != NULL ||
		GetModuleHandleW(L"clang_rt.asan_dynamic-i386.dll") != NULL,
		"The statically imported ASan runtime DLL is loaded", "no clang_rt.asan_dynamic module in the process");
#endif	// RANZ_ASAN

	// A DLL of System32, the way MsInit() loads msi.dll
	DllSearchCheckFound(&ctx, DLLSEARCH_SOURCE, "A System32 DLL named without a path is found");

	// A DLL next to the executable
	if (DllSearchPlace(&ctx, dir, sizeof(dir), dll, sizeof(dll), exe_dir, NULL, DLLSEARCH_APP_DLL))
	{
		DllSearchCheckFound(&ctx, DLLSEARCH_APP_DLL, "A DLL next to the executable is found");

		DllSearchCheck(&ctx, FileDeleteW(dll), "Delete the DLL next to the executable", "cannot delete %S", dll);
	}

	// A DLL in the current directory
	if (DllSearchPlace(&ctx, dir, sizeof(dir), dll, sizeof(dll), MsGetMyTempDirW(), DLLSEARCH_CWD_DIR, DLLSEARCH_CWD_DLL))
	{
		// GetCurrentDirectoryW returns the size it needs when old_cwd is too small
		len = GetCurrentDirectoryW(MAX_PATH, old_cwd);
		ok = (len != 0 && len < MAX_PATH && SetCurrentDirectoryW(dir) != FALSE);
		err = GetLastError();
		if (DllSearchCheck(&ctx, ok, "Make the directory of the DLL the current directory", "error %u", err))
		{
			DllSearchCheckMissing(&ctx, DLLSEARCH_CWD_DLL, "A DLL in the current directory is not found");

			SetCurrentDirectoryW(old_cwd);
		}

		FileDeleteW(dll);
		DeleteDirW(dir);
	}

	// A DLL in a directory of PATH (the former SetDllDirectory("") searched PATH)
	if (DllSearchPlace(&ctx, dir, sizeof(dir), dll, sizeof(dll), MsGetMyTempDirW(), DLLSEARCH_PATH_DIR, DLLSEARCH_PATH_DLL))
	{
		old_path_len = GetEnvironmentVariableW(L"PATH", NULL, 0);
		old_path = ZeroMalloc((old_path_len + 1) * sizeof(wchar_t));
		if (old_path_len != 0)
		{
			GetEnvironmentVariableW(L"PATH", old_path, old_path_len);
		}

		new_path_size = (UniStrLen(dir) + 1 + old_path_len + 1) * sizeof(wchar_t);
		new_path = ZeroMalloc(new_path_size);
		UniStrCpy(new_path, new_path_size, dir);
		UniStrCat(new_path, new_path_size, L";");
		UniStrCat(new_path, new_path_size, old_path);

		ok = (SetEnvironmentVariableW(L"PATH", new_path) != FALSE);
		err = GetLastError();
		if (DllSearchCheck(&ctx, ok, "Put the directory of the DLL first in PATH", "error %u", err))
		{
			DllSearchCheckMissing(&ctx, DLLSEARCH_PATH_DLL, "A DLL in a directory of PATH is not found");

			SetEnvironmentVariableW(L"PATH", old_path_len == 0 ? NULL : old_path);
		}

		Free(new_path);
		Free(old_path);

		FileDeleteW(dll);
		DeleteDirW(dir);
	}

	// A DLL in a directory added with AddDllDirectory (LOAD_LIBRARY_SEARCH_USER_DIRS, part of the
	// default directories; the former SetDllDirectory("") never searched it)
	if (DllSearchPlace(&ctx, dir, sizeof(dir), dll, sizeof(dll), MsGetMyTempDirW(), DLLSEARCH_USER_DIR, DLLSEARCH_USER_DLL))
	{
		cookie = AddDllDirectory(dir);
		err = GetLastError();
		if (DllSearchCheck(&ctx, cookie != NULL, "AddDllDirectory of the directory of the DLL", "error %u", err))
		{
			DllSearchCheckFound(&ctx, DLLSEARCH_USER_DLL, "A DLL in a directory added with AddDllDirectory is found");

			RemoveDllDirectory(cookie);
		}

		FileDeleteW(dll);
		DeleteDirW(dir);
	}

	if (ctx.NumFailed == 0)
	{
		Print("DLLSEARCH TEST OK\n");
	}
	else
	{
		Print("DLLSEARCH TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
