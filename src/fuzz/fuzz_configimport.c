// fuzz_configimport.c
// libFuzzer target: the config importer of the configuration store (Cedar/ConfigStoreImport.c, CORE-F5 #65; AUD1-DT-12
// #460), which imports the fork's Config file (ranz_server.config) into an empty store. Cfg parses the bytes of the file
// (CfgReadW, whose parser fuzz_cfg fuzzes), and CsImportForkConfig walks the parsed tree: the hubs with their CAs and
// users, the listeners, the server certificate with its chain and the administrators, each written into the store in one
// transaction, or left out when the store refuses it. Every input is written to a file of its own and imported into a new
// store in memory (CsOpen of SQLite's ":memory:"). An import that fails must leave the store empty and report that it
// carried nothing, as CsImportForkConfig promises; one that succeeds leaves the store not empty, and the store is then
// dumped as the CLI dumps one (CsDump), which reads back every row that the import wrote.
//
// The seeds (src/fuzz/seeds/fuzz_configimport.py) are the fork configuration of vpntest store
// (tests/golden/store/fork_server.config), the configuration without ServerConfiguration that the test refuses, the same
// fork configuration in the binary format, and the server configurations of fuzz_cfg.
//
// fuzz-max-len: 16384

#include "fuzz_common.h"

#include "Cedar/CedarType.h"
#include "Cedar/ConfigStore.h"

#include "Mayaqua/Memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// Largest input accepted (fuzz-max-len above, for run_fuzzers.ps1): longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		16384

// The file of each input, in the temporary directory, and the store in memory of each import
static wchar_t fuzz_configimport_path[MAX_PATH];
static wchar_t fuzz_configimport_memory[] = L":memory:";

// A property of the importer that does not hold: libFuzzer saves the input, with no abort message box and no Windows
// Error Reporting (as FuzzRun in fuzz_common.c)
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// At exit: the file of the inputs goes
static void FuzzConfigImportAtExit(void)
{
	DeleteFileW(fuzz_configimport_path);
}

// Write the input to its file: false when it cannot be written
static bool FuzzConfigImportWrite(const uint8_t *data, size_t size)
{
	wchar_t dir[MAX_PATH];
	wchar_t pid[16];
	DWORD written = 0;

	// %TEMP%\ranz_fuzz_configimport_<process id>.config, once
	if (fuzz_configimport_path[0] == 0)
	{
		DWORD n = GetTempPathW(MAX_PATH, dir);
		if (n == 0 || n >= MAX_PATH - 64 || _ultow_s(GetCurrentProcessId(), pid, 16, 10) != 0)
		{
			return false;
		}
		wcscpy_s(fuzz_configimport_path, MAX_PATH, dir);
		wcscat_s(fuzz_configimport_path, MAX_PATH, L"ranz_fuzz_configimport_");
		wcscat_s(fuzz_configimport_path, MAX_PATH, pid);
		wcscat_s(fuzz_configimport_path, MAX_PATH, L".config");
		atexit(FuzzConfigImportAtExit);
	}

	HANDLE h = CreateFileW(fuzz_configimport_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	bool ok = (size == 0 || (WriteFile(h, data, (DWORD)size, &written, NULL) && written == (DWORD)size));
	CloseHandle(h);

	return ok;
}

// One input: the file of a fork configuration, imported into a new store
static void FuzzConfigImport(const uint8_t *data, size_t size)
{
	CS_IMPORT r;
	CS_IMPORT none;

	if (size > FUZZ_MAX_INPUT_SIZE || FuzzConfigImportWrite(data, size) == false)
	{
		return;
	}

	CONFIG_STORE *s = CsOpen(fuzz_configimport_memory);
	if (s == NULL)
	{
		FuzzFail("a store in memory did not open");
	}

	UINT err = CsImportForkConfig(s, fuzz_configimport_path, &r);
	bool empty = CsIsEmpty(s);

	if (err == ERR_NO_ERROR)
	{
		if (empty)
		{
			FuzzFail("an import that succeeded left the store empty");
		}

		BUF *dump = CsDump(s);
		FreeBuf(dump);
	}
	else
	{
		// The file is there and the store is new and empty: the import fails only for a file that is no fork
		// configuration or for a store that failed, and then changes nothing
		memset(&none, 0, sizeof(none));
		if (err != ERR_INVALID_PARAMETER && err != ERR_INTERNAL_ERROR)
		{
			FuzzFail("an import into a new store failed with an error of neither a file that is no fork configuration nor a failed store");
		}
		if (empty == false || memcmp(&r, &none, sizeof(r)) != 0)
		{
			FuzzFail("an import that failed changed the store, or reported that it carried something");
		}
	}

	CsClose(s);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzConfigImport, data, size);

	return 0;
}
