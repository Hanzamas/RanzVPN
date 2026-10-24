// selfint.c
// Named self-integrity test of vpntest ("selfintegrity" command, SEC-3 #281)
//
// The self-integrity check (MsCheckSelfIntegrity) and its degrade-or-deceive response
// (MsStartSelfIntegrity, ADR-0036 amendment of 2026-10-22) are Mayaqua code. This test runs them against
// the running test executable and reports the verdict. It is not in the default smoke list, because an
// unsigned build has no signature to verify: .github/scripts/self-integrity.ps1 signs vpntest, runs the
// test, then tampers a copy of the signed binary and runs it again.
//
// The argument chooses the expectation. With none the test expects an intact, signed binary
// (MS_INTEGRITY_OK). With "tampered" it expects a changed binary (MS_INTEGRITY_BAD_SIGNATURE or
// MS_INTEGRITY_TEXT_MISMATCH) and that the degrade response ran without crashing the process: the test
// reaching its last line proves the check degraded rather than crashed. With "unsigned" it expects an
// unsigned development build (MS_INTEGRITY_NO_SIGNATURE), for a run on a binary that was not signed.
// Prints "SELFINTEGRITY TEST OK" only when the verdict matches the expectation.

#include "testlist.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

RANZ_TEST("selfintegrity", selfint_test, "Self-integrity: WinVerifyTrust and the .text hash of the running binary; OK when signed and intact, the degrade-or-deceive response when changed (SEC-3; run on a signed binary by self-integrity.ps1).");
void selfint_test(UINT num, char **arg)
{
	char *expect = (num >= 1 && arg != NULL) ? arg[0] : "ok";
	UINT status = MsCheckSelfIntegrity();
	bool ok;

	Print("Self-integrity test (WinVerifyTrust and the .text hash)\n");
	Print("  status: %s\n", MsSelfIntegrityName(status));

	if (StrCmpi(expect, "tampered") == 0)
	{
		// A changed binary: either mechanism may catch it. The degrade response of ADR-0036 sets the
		// degraded flag and never crashes; the test reaching the end proves the process kept running.
		ok = (status == MS_INTEGRITY_BAD_SIGNATURE || status == MS_INTEGRITY_TEXT_MISMATCH);

		MsStartSelfIntegrity();

		if (ok && MsIsSelfIntegrityDegraded() == false)
		{
			ok = false;
		}

		if (ok)
		{
			Print("  [PASS] a changed binary is caught and the degrade response ran without a crash\n");
		}
		else
		{
			Print("  [FAIL] a changed binary was not caught, or the degrade response did not run\n");
		}
	}
	else if (StrCmpi(expect, "unsigned") == 0)
	{
		ok = (status == MS_INTEGRITY_NO_SIGNATURE);

		if (ok)
		{
			Print("  [PASS] an unsigned development build is reported, not treated as tampering\n");
		}
		else
		{
			Print("  [FAIL] expected NO_SIGNATURE on an unsigned build\n");
		}
	}
	else
	{
		ok = (status == MS_INTEGRITY_OK);

		// An intact signed binary must not be degraded by the startup response
		MsStartSelfIntegrity();

		if (ok && MsIsSelfIntegrityDegraded())
		{
			ok = false;
		}

		if (ok)
		{
			Print("  [PASS] an intact signed binary verifies and is not degraded\n");
		}
		else
		{
			Print("  [FAIL] expected OK on an intact signed binary\n");
		}
	}

	if (ok)
	{
		Print("SELFINTEGRITY TEST OK\n");
	}
	else
	{
		Print("SELFINTEGRITY TEST FAILED\n");
	}
}
