// registry.c
// Named registry test of vpntest ("registry" command, FND-64 #121)
//
// Pins the registry helpers of Microsoft.c on a key of its own under HKCU. MsRegReadStrEx2W tested
// ret[size / sizeof(wchar_t) - 1] for the terminator: for an empty REG_SZ (0 bytes) or a 1-byte one
// that is ret[-1], a read before the value, and the result was NULL or a buffer without a
// terminator. MsRegWriteValueEx2 and MsRegDeleteValueEx2 opened the key with KEY_ALL_ACCESS, so a
// key that grants only reading and setting values could be neither written nor cleaned up. The test
// makes a key whose DACL grants its owner only KEY_READ, KEY_SET_VALUE and DELETE (an OWNER RIGHTS
// entry, so the implicit READ_CONTROL and WRITE_DAC of the owner do not apply) and writes, reads and
// deletes values in it. A REG_MULTI_SZ reads as its first string, and a REG_SZ without a terminator
// reads as NULL. Prints "REGISTRY TEST OK" only when every check passes, deletes its keys and frees
// everything it allocates.

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

#include <windows.h>
#include <sddl.h>

#define	REGISTRY_BASE_KEY			"Software\\Ranz VPN vpntest"	// Under HKCU; deleted at the end when empty
#define	REGISTRY_RESTRICTED_NAME	"restricted"					// Subkey with the restricted DACL
#define	REGISTRY_INT_VALUE			0x12345678						// Written to and read from the keys

// The owner (OWNER RIGHTS) gets KEY_READ (0x20019), KEY_SET_VALUE (0x2) and DELETE (0x10000) only:
// no WRITE_DAC, WRITE_OWNER, KEY_CREATE_SUB_KEY or KEY_CREATE_LINK, so an open for KEY_ALL_ACCESS fails
#define	REGISTRY_RESTRICTED_SDDL	L"D:P(A;;0x3001B;;;OW)"

// Run state of the test
typedef struct REGISTRY_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} REGISTRY_CTX;

// Record one check: print [PASS] or [FAIL]
static bool RegistryCheck(REGISTRY_CTX *ctx, bool ok, char *what)
{
	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	Print("  [FAIL] %s\n", what);

	ctx->NumFailed++;

	return false;
}

// Delete the keys of the test: the restricted subkey first (RegDeleteKeyExA needs only its DELETE
// right), then the test key with what is left in it, then the base key when nothing else is in it
static void RegistryDeleteKeys(char *key, char *restricted)
{
	RegDeleteKeyExA(HKEY_CURRENT_USER, restricted, 0, 0);
	RegDeleteTreeA(HKEY_CURRENT_USER, key);
	RegDeleteKeyExA(HKEY_CURRENT_USER, key, 0, 0);
	RegDeleteKeyExA(HKEY_CURRENT_USER, REGISTRY_BASE_KEY, 0, 0);
}

// Set a value through the W API with the exact bytes given (RegSetValueExW keeps them as they are)
static bool RegistrySetRaw(char *key, wchar_t *name, UINT type, void *data, UINT size)
{
	HKEY h;
	wchar_t key_w[MAX_PATH];
	LSTATUS ret;

	StrToUni(key_w, sizeof(key_w), key);

	if (RegOpenKeyExW(HKEY_CURRENT_USER, key_w, 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS)
	{
		return false;
	}

	ret = RegSetValueExW(h, name, 0, type, (BYTE *)data, size);

	RegCloseKey(h);

	return ret == ERROR_SUCCESS;
}

// True when the wide string read is there and equals expected
static bool RegistryUniIs(wchar_t *s, wchar_t *expected)
{
	return s != NULL && UniStrCmp(s, expected) == 0;
}

// True when the string read is there and equals expected
static bool RegistryStrIs(char *s, char *expected)
{
	return s != NULL && StrCmp(s, expected) == 0;
}

// Make the restricted subkey with REGISTRY_RESTRICTED_SDDL as its security descriptor
static bool RegistryMakeRestricted(char *restricted)
{
	SECURITY_ATTRIBUTES sa;
	PSECURITY_DESCRIPTOR sd = NULL;
	wchar_t restricted_w[MAX_PATH];
	HKEY h;
	LSTATUS ret;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(REGISTRY_RESTRICTED_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
	{
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	StrToUni(restricted_w, sizeof(restricted_w), restricted);

	ret = RegCreateKeyExW(HKEY_CURRENT_USER, restricted_w, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, &sa, &h, NULL);

	LocalFree(sd);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

// registry: the registry helpers of Microsoft.c on short and odd REG_SZ values, a REG_MULTI_SZ and a
// key that grants no more than reading and setting values
void registry_test(UINT num, char **arg)
{
	REGISTRY_CTX ctx;
	char key[MAX_PATH];
	char restricted[MAX_PATH];
	wchar_t no_term[2] = {L'A', L'B'};
	wchar_t multi[] = L"first\0second\0";
	HKEY h;
	LSTATUS open_all;
	wchar_t *w;
	char *s;

	Zero(&ctx, sizeof(ctx));

	Print("Registry test (MsRegRead*, MsRegWrite*, MsRegDeleteValue on HKCU)\n");

	Format(key, sizeof(key), REGISTRY_BASE_KEY "\\registry_%u", MsGetCurrentProcessId());
	Format(restricted, sizeof(restricted), "%s\\" REGISTRY_RESTRICTED_NAME, key);

	RegistryDeleteKeys(key, restricted);

	// (1) A string and a number written and read back through the helpers
	RegistryCheck(&ctx, MsRegWriteStr(REG_CURRENT_USER, key, "str", "ranz"), "MsRegWriteStr makes the key and writes a REG_SZ");

	s = MsRegReadStr(REG_CURRENT_USER, key, "str");
	RegistryCheck(&ctx, RegistryStrIs(s, "ranz"), "MsRegReadStr reads it back");
	Free(s);

	w = MsRegReadStrEx2W(REG_CURRENT_USER, key, "str", false);
	RegistryCheck(&ctx, RegistryUniIs(w, L"ranz"), "MsRegReadStrEx2W reads it back");
	Free(w);

	RegistryCheck(&ctx, MsRegWriteInt(REG_CURRENT_USER, key, "int", REGISTRY_INT_VALUE) &&
		MsRegReadInt(REG_CURRENT_USER, key, "int") == REGISTRY_INT_VALUE, "MsRegWriteInt and MsRegReadInt round trip");

	// (2) An empty REG_SZ (0 bytes) and one of 1 byte: no whole character, read as an empty string
	RegistryCheck(&ctx, RegistrySetRaw(key, L"empty", REG_SZ, L"", 0) && RegistrySetRaw(key, L"onebyte", REG_SZ, "A", 1),
		"An empty and a 1-byte REG_SZ are written");

	w = MsRegReadStrEx2W(REG_CURRENT_USER, key, "empty", false);
	RegistryCheck(&ctx, RegistryUniIs(w, L""), "MsRegReadStrEx2W reads an empty REG_SZ as an empty string (was ret[-1])");
	Free(w);

	w = MsRegReadStrEx2W(REG_CURRENT_USER, key, "onebyte", false);
	RegistryCheck(&ctx, RegistryUniIs(w, L""), "MsRegReadStrEx2W reads a 1-byte REG_SZ as an empty string (was ret[-1])");
	Free(w);

	s = MsRegReadStr(REG_CURRENT_USER, key, "empty");
	RegistryCheck(&ctx, RegistryStrIs(s, ""), "MsRegReadStr reads an empty REG_SZ as an empty string");
	Free(s);

	// (3) A REG_SZ without a terminator reads as NULL; a REG_MULTI_SZ reads as its first string
	RegistryCheck(&ctx, RegistrySetRaw(key, L"noterm", REG_SZ, no_term, sizeof(no_term)) &&
		RegistrySetRaw(key, L"multi", REG_MULTI_SZ, multi, sizeof(multi)), "A REG_SZ without a terminator and a REG_MULTI_SZ are written");

	w = MsRegReadStrEx2W(REG_CURRENT_USER, key, "noterm", false);
	RegistryCheck(&ctx, w == NULL, "MsRegReadStrEx2W reads a REG_SZ without a terminator as NULL");
	Free(w);

	s = MsRegReadStr(REG_CURRENT_USER, key, "multi");
	RegistryCheck(&ctx, RegistryStrIs(s, "first"), "MsRegReadStr reads a REG_MULTI_SZ as its first string");
	Free(s);

	// (4) A key that grants its owner reading, setting values and DELETE only
	RegistryCheck(&ctx, RegistryMakeRestricted(restricted), "The restricted key is made (KEY_READ, KEY_SET_VALUE and DELETE for its owner)");

	h = NULL;
	open_all = RegOpenKeyExA(HKEY_CURRENT_USER, restricted, 0, KEY_ALL_ACCESS, &h);
	if (open_all == ERROR_SUCCESS)
	{
		RegCloseKey(h);
	}
	RegistryCheck(&ctx, open_all == ERROR_ACCESS_DENIED, "The restricted key refuses an open for KEY_ALL_ACCESS");

	RegistryCheck(&ctx, MsRegWriteInt(REG_CURRENT_USER, restricted, "int", REGISTRY_INT_VALUE),
		"MsRegWriteInt writes to the restricted key (was a KEY_ALL_ACCESS open)");

	RegistryCheck(&ctx, MsRegReadInt(REG_CURRENT_USER, restricted, "int") == REGISTRY_INT_VALUE, "MsRegReadInt reads it back");

	RegistryCheck(&ctx, MsRegWriteStr(REG_CURRENT_USER, restricted, "str", "ranz"), "MsRegWriteStr writes to the restricted key");

	RegistryCheck(&ctx, MsRegDeleteValue(REG_CURRENT_USER, restricted, "int") && MsRegDeleteValue(REG_CURRENT_USER, restricted, "str"),
		"MsRegDeleteValue deletes from the restricted key (was a KEY_ALL_ACCESS open)");

	RegistryCheck(&ctx, MsRegIsValue(REG_CURRENT_USER, restricted, "int") == false && MsRegIsValue(REG_CURRENT_USER, restricted, "str") == false,
		"The values of the restricted key are gone");

	// (5) Nothing left behind
	RegistryDeleteKeys(key, restricted);

	RegistryCheck(&ctx, MsRegIsKeyEx2(REG_CURRENT_USER, key, false) == false, "The keys of the test are deleted");

	if (ctx.NumFailed == 0)
	{
		Print("REGISTRY TEST OK\n");
	}
	else
	{
		Print("REGISTRY TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
