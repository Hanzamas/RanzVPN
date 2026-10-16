// machineid.c
// Named machine identity test of vpntest ("machineid" command, FIX-5 #101)
//
// The machine identity (GenerateMachineUniqueHash) sets the MAC address and the 172.31.x.y address
// of every virtual hub and the unique_id of a Cascade login. The old identity hashed the host name,
// the host IP addresses and the OS version: it changed with a rename, a DHCP lease or an OS update,
// and two servers on cloned machines got the same one. FIX-5 hashes the MachineGuid of Windows with
// a random salt that the server configuration keeps (ComputeMachineUniqueHash). This test pins that
// hash with known answers and checks that the same MachineGuid with separate salts gives separate
// identities. Prints "MACHINEID TEST OK" only when every check passes, and frees everything it
// allocates.

#include "Cedar/Protocol.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

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
static void MachineIdCheckHex(MACHINEID_CTX *ctx, UCHAR *id, char *expect, char *what)
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
	UINT i;

	for (i = 0;i < MACHINEID_KAT_SALT_SIZE;i++)
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

// machineid: the machine identity of FIX-5
void machineid_test(UINT num, char **arg)
{
	MACHINEID_CTX ctx;

	Zero(&ctx, sizeof(ctx));

	Print("Machine identity test\n");

	MachineIdTestDerivation(&ctx);

	if (ctx.NumFailed == 0)
	{
		Print("MACHINEID TEST OK\n");
	}
	else
	{
		Print("MACHINEID TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
