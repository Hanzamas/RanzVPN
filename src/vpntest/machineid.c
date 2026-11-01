// machineid.c
// Named machine identity test of vpntest ("machineid" command, FIX-5 #101)
//
// The machine identity (GenerateMachineUniqueHash) sets the MAC address and the 172.31.x.y address
// of every virtual hub and the unique_id of a Cascade login. The old identity hashed the host name,
// the host IP addresses and the OS version: it changed with a rename, a DHCP lease or an OS update,
// and two servers on cloned machines got the same one. FIX-5 hashes the MachineGuid of Windows with
// a random salt that the server configuration keeps (ComputeMachineUniqueHash). This test pins that
// hash with known answers and checks that the same MachineGuid with separate salts gives separate
// identities, that a server's identity has no other input (so a rename, an IP change or an OS update
// keeps it), and that the salt goes into the configuration text and back. Prints "MACHINEID TEST OK"
// only when every check passes, and frees everything it allocates.

#include "testlist.h"

#include "Cedar/Cedar.h"
#include "Cedar/Protocol.h"
#include "Cedar/Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <windows.h>

// Known answers: the first SHA1_SIZE bytes of SHA-256 over MACHINE_ID_LABEL, the MachineGuid and the
// salt, each string with its terminator (computed with Python hashlib)
#define	MACHINEID_KAT_GUID			"1b4e28ba-2fa1-11d2-883f-0016d3cca427"		// RFC 4122 example UUID
#define	MACHINEID_KAT_GUID_OTHER	"1b4e28ba-2fa1-11d2-883f-0016d3cca428"		// Last digit changed
#define	MACHINEID_KAT_HASH			"9F6F74F3D89211419781438C853716390BD576F1"	// KAT_GUID, salt 00 01 .. 1F
#define	MACHINEID_KAT_HASH_SALT2	"7CBC73BCBB4B3AC45A6A9CF8B43FD6A0893454A4"	// KAT_GUID, salt 01 02 .. 20
#define	MACHINEID_KAT_HASH_NOGUID	"0AE6D366A7401D5BAC75C281A59741D8652A22DB"	// Empty MachineGuid, salt 00 01 .. 1F
#define	MACHINEID_KAT_SALT_SIZE		32

// Run state of the test
typedef struct MACHINEID_CTX
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} MACHINEID_CTX;

// Record one check: print [PASS] or [FAIL]
static bool MachineIdCheck(MACHINEID_CTX *ctx, bool ok, char *what)
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

// Check an identity against its expected value in hex; a failure also prints the identity
static void MachineIdCheckHex(MACHINEID_CTX *ctx, const UCHAR *id, char *expect, char *what)
{
	char hex[SHA1_SIZE * 2 + 1];

	BinToStr(hex, sizeof(hex), id, SHA1_SIZE);

	if (MachineIdCheck(ctx, StrCmpi(hex, expect) == 0, what) == false)
	{
		Print("         got %s, expected %s\n", hex, expect);
	}
}

// Fill a known-answer salt: first, first + 1, ...
static void MachineIdKatSalt(UCHAR *salt, UCHAR first)
{
	for (UINT i = 0;i < MACHINEID_KAT_SALT_SIZE;i++)
	{
		salt[i] = (UCHAR)(first + i);
	}
}

// The hash: known answers, the form of the MachineGuid, and which inputs tell identities apart
static void MachineIdTestDerivation(MACHINEID_CTX *ctx)
{
	UCHAR salt1[MACHINEID_KAT_SALT_SIZE];
	UCHAR salt2[MACHINEID_KAT_SALT_SIZE];
	UCHAR a[SHA1_SIZE];
	UCHAR b[SHA1_SIZE];

	MachineIdKatSalt(salt1, 0x00);
	MachineIdKatSalt(salt2, 0x01);

	ComputeMachineUniqueHash(a, MACHINEID_KAT_GUID, salt1, sizeof(salt1));
	MachineIdCheckHex(ctx, a, MACHINEID_KAT_HASH, "known answer: MachineGuid and salt 00..1F");

	ComputeMachineUniqueHash(b, MACHINEID_KAT_GUID, salt1, sizeof(salt1));
	MachineIdCheck(ctx, Cmp(a, b, SHA1_SIZE) == 0, "the same MachineGuid and salt give the same identity");

	ComputeMachineUniqueHash(b, " 1B4E28BA-2FA1-11D2-883F-0016D3CCA427\t", salt1, sizeof(salt1));
	MachineIdCheck(ctx, Cmp(a, b, SHA1_SIZE) == 0, "the MachineGuid counts trimmed and in lower case");

	ComputeMachineUniqueHash(b, MACHINEID_KAT_GUID, salt2, sizeof(salt2));
	MachineIdCheckHex(ctx, b, MACHINEID_KAT_HASH_SALT2, "known answer: MachineGuid and salt 01..20");
	MachineIdCheck(ctx, Cmp(a, b, SHA1_SIZE) != 0,
		"the same MachineGuid with separate salts (cloned machines, separate configs) gives different identities");

	ComputeMachineUniqueHash(b, MACHINEID_KAT_GUID_OTHER, salt1, sizeof(salt1));
	MachineIdCheck(ctx, Cmp(a, b, SHA1_SIZE) != 0, "separate MachineGuids with the same salt give different identities");

	ComputeMachineUniqueHash(a, NULL, salt1, sizeof(salt1));
	MachineIdCheckHex(ctx, a, MACHINEID_KAT_HASH_NOGUID, "known answer: no MachineGuid, salt 00..1F (the salt alone)");

	ComputeMachineUniqueHash(b, "", salt1, sizeof(salt1));
	MachineIdCheck(ctx, Cmp(a, b, SHA1_SIZE) == 0, "an empty MachineGuid counts as none");
}

// Read the MachineGuid with the registry API, apart from the code under test
static bool MachineIdReadGuid(char *guid, UINT size)
{
	HKEY key;
	DWORD type = 0;
	DWORD bytes = size - 1;		// The zeroed last byte stays the terminator

	Zero(guid, size);

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
	{
		return false;
	}

	LONG ret = RegQueryValueExA(key, "MachineGuid", NULL, &type, (BYTE *)guid, &bytes);

	RegCloseKey(key);

	if (ret != ERROR_SUCCESS || type != REG_SZ)
	{
		Zero(guid, size);
		return false;
	}

	return guid[0] != 0;
}

// The identity of a CEDAR: the MachineGuid and the salt only, a salt per CEDAR, the same salt gives it back
static void MachineIdTestCedar(MACHINEID_CTX *ctx)
{
	char guid[MAX_SIZE];
	CEDAR *c1 = NewCedar(NULL, NULL);
	CEDAR *c2 = NewCedar(NULL, NULL);
	UCHAR id1[SHA1_SIZE];
	UCHAR id2[SHA1_SIZE];
	UCHAR expect[SHA1_SIZE];

	MachineIdCheck(ctx, MachineIdReadGuid(guid, sizeof(guid)),
		"MachineGuid read from HKLM\\SOFTWARE\\Microsoft\\Cryptography (64-bit view)");

	GenerateMachineUniqueHash(c1, id1);
	ComputeMachineUniqueHash(expect, guid, c1->MachineIdSalt, sizeof(c1->MachineIdSalt));
	MachineIdCheck(ctx, Cmp(id1, expect, SHA1_SIZE) == 0,
		"the identity hashes the MachineGuid and the salt only: a rename, an IP change or an OS update keeps it");

	GenerateMachineUniqueHash(c1, id2);
	MachineIdCheck(ctx, Cmp(id1, id2, SHA1_SIZE) == 0, "the identity is the same on every call");

	MachineIdCheck(ctx, Cmp(c1->MachineIdSalt, c2->MachineIdSalt, MACHINE_ID_SALT_SIZE) != 0,
		"each NewCedar draws a salt of its own");

	GenerateMachineUniqueHash(c2, id2);
	MachineIdCheck(ctx, Cmp(id1, id2, SHA1_SIZE) != 0,
		"two servers on one MachineGuid with their own salts have different identities (the old identity was the same)");

	SetCedarMachineIdSalt(c2, c1->MachineIdSalt);
	GenerateMachineUniqueHash(c2, id2);
	MachineIdCheck(ctx, Cmp(id1, id2, SHA1_SIZE) == 0, "the same salt gives the same identity back");

	ReleaseCedar(c1);
	ReleaseCedar(c2);
}

// Load a folder holding a MachineIdSalt item of the given size into c; true when the salt of c stayed
static bool MachineIdLoadKeeps(CEDAR *c, UINT size)
{
	UCHAR before[MACHINE_ID_SALT_SIZE];
	UCHAR item[MACHINE_ID_SALT_SIZE * 2];
	FOLDER *f = CfgCreateFolder(NULL, TAG_ROOT);

	Copy(before, c->MachineIdSalt, sizeof(before));
	Rand(item, sizeof(item));

	if (size != 0)
	{
		CfgAddByte(f, "MachineIdSalt", item, size);
	}

	SiLoadMachineIdCfg(c, f);

	bool ret = (Cmp(before, c->MachineIdSalt, sizeof(before)) == 0);

	CfgDeleteFolder(f);

	return ret;
}

// The salt in the config file: written, read back from the configuration text; a config file without it
// (an upgrade) or with a salt of another size keeps the salt of NewCedar
static void MachineIdTestCfg(MACHINEID_CTX *ctx)
{
	CEDAR *c1 = NewCedar(NULL, NULL);
	CEDAR *c2 = NewCedar(NULL, NULL);
	UCHAR id1[SHA1_SIZE];
	UCHAR id2[SHA1_SIZE];
	FOLDER *f = CfgCreateFolder(NULL, TAG_ROOT);

	MachineIdCheck(ctx, MachineIdLoadKeeps(c2, 0), "a config file without MachineIdSalt keeps the salt of NewCedar");
	MachineIdCheck(ctx, MachineIdLoadKeeps(c2, MACHINE_ID_SALT_SIZE / 2), "a MachineIdSalt of half the size is ignored");
	MachineIdCheck(ctx, MachineIdLoadKeeps(c2, MACHINE_ID_SALT_SIZE * 2), "a MachineIdSalt of twice the size is ignored");
	MachineIdCheck(ctx, MachineIdLoadKeeps(c2, MACHINE_ID_SALT_SIZE) == false, "a MachineIdSalt of the right size replaces the salt");

	SiWriteMachineIdCfg(f, c1);
	BUF *b = CfgFolderToBuf(f);
	SeekBufToBegin(b);
	FOLDER *f2 = CfgBufTextToFolder(b);

	if (MachineIdCheck(ctx, f2 != NULL && CfgIsItem(f2, "MachineIdSalt"), "SiWriteMachineIdCfg writes the MachineIdSalt item"))
	{
		SiLoadMachineIdCfg(c2, f2);
		GenerateMachineUniqueHash(c1, id1);
		GenerateMachineUniqueHash(c2, id2);
		MachineIdCheck(ctx, Cmp(id1, id2, SHA1_SIZE) == 0,
			"the salt read back from the configuration text gives the same identity (a restart keeps it)");
	}

	CfgDeleteFolder(f2);
	FreeBuf(b);
	CfgDeleteFolder(f);

	ReleaseCedar(c1);
	ReleaseCedar(c2);
}

// machineid: the machine identity of FIX-5
RANZ_TEST("machineid", machineid_test, "Machine identity: MachineGuid and the configuration salt, known answers, separate salts, the salt in the config.");
void machineid_test(UINT num, char **arg)
{
	MACHINEID_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("Machine identity test\n");

	MachineIdTestDerivation(&ctx);
	MachineIdTestCedar(&ctx);
	MachineIdTestCfg(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("MACHINEID TEST OK\n");
	}
	else
	{
		Print("MACHINEID TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
