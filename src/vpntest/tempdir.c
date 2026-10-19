// tempdir.c
// Named temp directory and string table test of vpntest ("tempdir" command, SEC-8 #96)
//
// The temp directory of the process (MsGetMyTempDirW) used to be VPN_xxxx: two rand() bytes as
// the name, the access rights inherited from %TEMP%, which is C:\Windows\Temp for the service.
// The parsed string table was cached as .unicode_cache_<hash>.dat in %TEMP% and read back at the
// next start. The test pins the fix: the name holds 64 random bits, the DACL is protected and
// grants nothing to Users, Authenticated Users or Everyone, and loading a string table writes no
// cache file. Prints "TEMPDIR TEST OK" only when every check passes, and frees everything it
// allocates.

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

#define	TEMPDIR_PREFIX			L"VPN_"				// Prefix of the name of the temp directory
#define	TEMPDIR_RANDOM_CHARS	16					// Hex digits after the prefix: 64 random bits
#define	TEMPDIR_CACHE_PREFIX	L".unicode_cache_"	// Name prefix of the former string table cache
#define	TEMPDIR_CACHE_SUFFIX	L".dat"				// Name suffix of the former string table cache

// Run state of the test
typedef struct TEMPDIR_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} TEMPDIR_CTX;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void TempDirCheck(TEMPDIR_CTX *ctx, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	ctx->NumFailed++;
}

// True when the last part of the path is the prefix and TEMPDIR_RANDOM_CHARS hex digits
static bool TempDirNameOk(wchar_t *path)
{
	wchar_t *name;
	UINT i;

	if (path == NULL)
	{
		return false;
	}

	name = path;
	for (i = 0;path[i] != 0;i++)
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

	for (i = 0;i < TEMPDIR_RANDOM_CHARS;i++)
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
	UINT i;

	if (dacl == NULL)
	{
		// A NULL DACL grants everything to everyone
		return true;
	}

	if (CreateWellKnownSid(type, NULL, (PSID)sid_buf, &sid_size) == FALSE)
	{
		return true;
	}

	for (i = 0;i < dacl->AceCount;i++)
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
	DIRLIST *d;
	UINT i;
	UINT num = 0;

	d = EnumDirW(dir);
	if (d == NULL)
	{
		return 0;
	}

	for (i = 0;i < d->NumFiles;i++)
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
	UINT i;

	for (i = 0;i < LIST_NUM(o);i++)
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

// tempdir: the temp directory has a 64-bit random name and a protected DACL; loading a string
// table writes no cache file to %TEMP%
void tempdir_test(UINT num, char **arg)
{
	TEMPDIR_CTX ctx;
	wchar_t *dir;
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
	dir = MsGetMyTempDirW();
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

	if (ctx.NumFailed == 0)
	{
		Print("TEMPDIR TEST OK\n");
	}
	else
	{
		Print("TEMPDIR TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
