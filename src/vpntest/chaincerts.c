// chaincerts.c
// Named chain_certs cache test of vpntest ("chaincerts" command, FND-139 #145)
//
// A server presents the certificates of the chain_certs folder next to the exe after its own certificate.
// The deduplicated list is read once and cached: it is read again only when the folder changed (a change
// notification) or when TryGetRootCertChain saved a downloaded issuer (InvalidateChainCertCache). The test
// runs AddChainSslCertOnDirectory(), the call of every accepted connection, on fresh contexts:
// - N connections with an unchanged folder: no scan of the folder;
// - a certificate written into the folder is on the chain of the next connection, with one more scan;
// - the same certificate deleted is off the chain of the next connection;
// - InvalidateChainCertCache() makes the next connection scan.
// Prints "CHAINCERTS TEST OK" only when every check passes, and frees everything it allocates.

#include "Cedar/Cedar.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdarg.h>

#define	CHAINCERTS_CONNECTIONS		20		// Connections run with an unchanged folder
#define	CHAINCERTS_SETTLE_MAX		40		// Calls to wait for the change notifications of an earlier write to settle
#define	CHAINCERTS_WAIT_MAX			20		// Calls to wait for the notification of a write or delete of the test
#define	CHAINCERTS_WAIT_STEP		50		// Milliseconds between these calls
#define	CHAINCERTS_FILE_NAME		L"chaincerts_test.cer"

// Run state of the test
typedef struct CHAINCERTS_TEST
{
	UINT NumChecks;						// Checks run so far
	UINT NumFailed;						// Checks failed so far
} CHAINCERTS_TEST;

// Record one check: print [PASS], or [FAIL] with the formatted detail
static void ChainCertsTestCheck(CHAINCERTS_TEST *t, bool ok, char *what, char *detail_fmt, ...)
{
	char detail[MAX_SIZE];
	va_list args;

	t->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return;
	}

	va_start(args, detail_fmt);
	FormatArgs(detail, sizeof(detail), detail_fmt, args);
	va_end(args);

	Print("  [FAIL] %s (%s)\n", what, detail);

	t->NumFailed++;
}

// One connection: the certificates of the folder on the chain of a new context. Returns their number
static UINT ChainCertsConnection()
{
	struct ssl_ctx_st *ctx = NewSSLCtx(true);
	UINT ret;

	if (ctx == NULL)
	{
		return 0xFFFFFFFF;
	}

	ret = AddChainSslCertOnDirectory(ctx);

	FreeSSLCtx(ctx);

	return ret;
}

// Run connections until two in a row cause no scan: the change notifications of an earlier write are in
static void ChainCertsSettle()
{
	UINT stable = 0;

	for (UINT i = 0;i < CHAINCERTS_SETTLE_MAX && stable < 2;i++)
	{
		UINT before = GetChainCertScanCount();

		ChainCertsConnection();

		if (GetChainCertScanCount() == before)
		{
			stable++;
		}
		else
		{
			stable = 0;
		}

		SleepThread(CHAINCERTS_WAIT_STEP);
	}
}

// Run connections until one has want certificates on its chain, for at most CHAINCERTS_WAIT_MAX calls.
// Returns the number of the last one
static UINT ChainCertsWaitFor(UINT want)
{
	UINT ret = 0;

	for (UINT i = 0;i < CHAINCERTS_WAIT_MAX;i++)
	{
		ret = ChainCertsConnection();

		if (ret == want)
		{
			break;
		}

		SleepThread(CHAINCERTS_WAIT_STEP);
	}

	return ret;
}

// N connections with the folder unchanged: how many scans they caused
static UINT ChainCertsConnections(UINT *wrong_count, UINT expect)
{
	UINT before = GetChainCertScanCount();

	*wrong_count = 0;

	for (UINT i = 0;i < CHAINCERTS_CONNECTIONS;i++)
	{
		if (ChainCertsConnection() != expect)
		{
			(*wrong_count)++;
		}
	}

	return GetChainCertScanCount() - before;
}

// chaincerts: the chain_certs folder is scanned once for many connections and again when it changes
void chaincerts_test(UINT num, char **arg)
{
	CHAINCERTS_TEST t;
	wchar_t exedir[MAX_SIZE];
	wchar_t dir[MAX_SIZE];
	wchar_t file[MAX_SIZE];
	K *priv = NULL, *pub = NULL;
	NAME *name;
	DIRLIST *listing;
	X *x;
	UINT base;
	UINT scans;
	UINT wrong;
	UINT n;

	Zero(&t, sizeof(t));

	Print("chain_certs cache test (AddChainSslCertOnDirectory)\n");

	// The server creates the folder once, at its start
	PrepareChainCertDir();

	GetExeDirW(exedir, sizeof(exedir));
	CombinePathW(dir, sizeof(dir), exedir, L"chain_certs");
	CombinePathW(file, sizeof(file), dir, CHAINCERTS_FILE_NAME);
	FileDeleteW(file);

	listing = EnumDirW(dir);
	ChainCertsTestCheck(&t, listing != NULL, "PrepareChainCertDir: the folder exists", "no folder");
	FreeDir(listing);

	// The folder as it is: the certificates of earlier tests of this process directory
	base = ChainCertsConnection();
	ChainCertsSettle();

	scans = ChainCertsConnections(&wrong, base);
	ChainCertsTestCheck(&t, scans == 0 && wrong == 0, "unchanged folder: N connections, no scan, same chain",
		"%u scans, %u connections with another chain", scans, wrong);

	// A certificate written into the folder
	name = NewName(L"Ranz VPN chaincerts test", NULL, NULL, NULL, NULL, NULL);
	ChainCertsTestCheck(&t, RsaGen(&priv, &pub, 2048), "RSA-2048 key is made", "RsaGen failed");
	x = NewRootX(pub, priv, name, 365, NULL);
	ChainCertsTestCheck(&t, x != NULL && XToFileW(x, file, true), "certificate is written into chain_certs", "write failed");

	scans = GetChainCertScanCount();
	n = ChainCertsWaitFor(base + 1);
	ChainCertsTestCheck(&t, n == base + 1, "written certificate: on the chain of the next connection",
		"%u certificates on the chain, expected %u", n, base + 1);
	ChainCertsTestCheck(&t, GetChainCertScanCount() > scans, "written certificate: the folder was scanned again", "no scan");

	ChainCertsSettle();
	scans = ChainCertsConnections(&wrong, base + 1);
	ChainCertsTestCheck(&t, scans == 0 && wrong == 0, "folder with the certificate: N connections, no scan, same chain",
		"%u scans, %u connections with another chain", scans, wrong);

	// TryGetRootCertChain saved a file: the cache is out of date, whatever the notification says
	ChainCertsSettle();
	scans = GetChainCertScanCount();
	InvalidateChainCertCache();
	n = ChainCertsConnection();
	ChainCertsTestCheck(&t, GetChainCertScanCount() == scans + 1 && n == base + 1,
		"InvalidateChainCertCache: the next connection scans once, with the same chain",
		"%u scans, %u certificates on the chain", GetChainCertScanCount() - scans, n);

	// The certificate deleted
	ChainCertsTestCheck(&t, FileDeleteW(file), "certificate is deleted from chain_certs", "delete failed");

	scans = GetChainCertScanCount();
	n = ChainCertsWaitFor(base);
	ChainCertsTestCheck(&t, n == base, "deleted certificate: off the chain of the next connection",
		"%u certificates on the chain, expected %u", n, base);
	ChainCertsTestCheck(&t, GetChainCertScanCount() > scans, "deleted certificate: the folder was scanned again", "no scan");

	ChainCertsSettle();
	scans = ChainCertsConnections(&wrong, base);
	ChainCertsTestCheck(&t, scans == 0 && wrong == 0, "folder as at the start: N connections, no scan, same chain",
		"%u scans, %u connections with another chain", scans, wrong);

	FileDeleteW(file);
	FreeX(x);
	FreeK(priv);
	FreeK(pub);
	FreeName(name);

	if (t.NumFailed == 0)
	{
		Print("CHAINCERTS TEST OK\n");
	}
	else
	{
		Print("CHAINCERTS TEST FAILED (%u of %u checks failed)\n", t.NumFailed, t.NumChecks);
	}
}
