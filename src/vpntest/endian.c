// endian.c
// Named byte-order test of vpntest ("endian" command, FND-152 #149)
//
// Endian16/32/64 were functions that probed the byte order of the host at each call, READ_* and
// WRITE_* assembled their values a byte at a time, and InitMayaqua set g_little_endian for the
// big-endian branches of Pack.c, Network.c, Internat.c and Microsoft.c. Ranz VPN builds for
// little-endian Windows only: Endian16/32/64 are now the _byteswap_* intrinsics, READ_* and
// WRITE_* one load or store plus a swap, and the branches are gone. The test pins the byte order:
// each swap must reverse the bytes (a swap that became an identity fails), match Winsock htons and
// htonl, the unaligned READ_* and WRITE_* must read and write big-endian bytes, and the former
// branches (a subnet mask, the UTF-8 length of a character) must give their old results.
// Prints "ENDIAN TEST OK" only when every check passes.

#include "testlist.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

static UINT endian_test_failed = 0;

// Record one check: print [PASS] or [FAIL] and the check
static void EndianTestCheck(bool ok, char *what)
{
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
	if (ok == false)
	{
		endian_test_failed++;
	}
}

RANZ_TEST("endian", endian_test, "Byte order: Endian16/32/64 reverse the bytes as htons and htonl do, READ_* and WRITE_* are big-endian at unaligned addresses.");
void endian_test(UINT num, char **arg)
{
	// One byte of slack in front, so the loads and stores run on an unaligned address
	UCHAR src[9] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	UCHAR dst[9];
	IP ip;

	endian_test_failed = 0;

	EndianTestCheck(Endian16(0x1234) == 0x3412, "Endian16 reverses the 2 bytes");
	EndianTestCheck(Endian32(0x12345678) == 0x78563412, "Endian32 reverses the 4 bytes");
	EndianTestCheck(Endian64(0x0102030405060708ULL) == 0x0807060504030201ULL, "Endian64 reverses the 8 bytes");
	EndianTestCheck(Endian16(0x1234) == htons(0x1234) && Endian32(0x12345678) == htonl(0x12345678), "Endian16 and Endian32 match htons and htonl");
	EndianTestCheck(Endian32(Endian32(0xA1B2C3D4)) == 0xA1B2C3D4 && Endian64(Endian64(0x1122334455667788ULL)) == 0x1122334455667788ULL, "a swap twice gives the value back");

	EndianTestCheck(READ_USHORT(src + 1) == 0x0102, "READ_USHORT reads big-endian at an unaligned address");
	EndianTestCheck(READ_UINT(src + 1) == 0x01020304, "READ_UINT reads big-endian at an unaligned address");
	EndianTestCheck(READ_UINT64(src + 1) == 0x0102030405060708ULL, "READ_UINT64 reads big-endian at an unaligned address");

	Zero(dst, sizeof(dst));
	WRITE_USHORT(dst + 1, 0x0102);
	EndianTestCheck(Cmp(dst, src, 3) == 0 && dst[3] == 0, "WRITE_USHORT writes 2 big-endian bytes at an unaligned address");
	Zero(dst, sizeof(dst));
	WRITE_UINT(dst + 1, 0x01020304);
	EndianTestCheck(Cmp(dst, src, 5) == 0 && dst[5] == 0, "WRITE_UINT writes 4 big-endian bytes at an unaligned address");
	Zero(dst, sizeof(dst));
	WRITE_UINT64(dst + 1, 0x0102030405060708ULL);
	EndianTestCheck(Cmp(dst, src, sizeof(src)) == 0, "WRITE_UINT64 writes 8 big-endian bytes at an unaligned address");

	IntToSubnetMask4(&ip, 24);
	EndianTestCheck(IPToUINT(&ip) == htonl(0xFFFFFF00) && IsSubnetMask4(&ip), "IntToSubnetMask4 24 is 255.255.255.0, a subnet mask");
	UINTToIP(&ip, htonl(0xFF00FF00));
	EndianTestCheck(IsSubnetMask4(&ip) == false, "255.0.255.0 is no subnet mask");

	EndianTestCheck(GetUniType(0x0041) == 1 && GetUniType(0x00E9) == 2 && GetUniType(0x0700) == 2 && GetUniType(0x3042) == 3, "GetUniType gives the UTF-8 length from the high byte");

	if (endian_test_failed == 0)
	{
		Print("ENDIAN TEST OK\n");
	}
	else
	{
		Print("ENDIAN TEST FAILED (%u checks failed)\n", endian_test_failed);
	}
}
