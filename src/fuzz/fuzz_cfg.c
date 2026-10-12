// fuzz_cfg.c
// libFuzzer target: configuration loading from a buffer, text (CfgBufTextToFolder) and
// binary (CfgBufBinToFolder), chosen the way CfgReadW() chooses for vpn_server.config
//
// The binary parser (CfgReadNextFolderBin) trusts the input, which CfgReadW() only passes on
// after its hash check: folder and item counts are not bounded by the bytes left (up to 2^32
// iterations, a timeout or out-of-memory), ReadBufStr() failures are not checked (the item
// name stays uninitialised), an item size above MAX_MALLOC_MEM_SIZE reaches MallocEx(), which
// aborts by design (AbortExitEx), and a string size of 0xFFFFFFFF wraps "size + 1" to 0, so
// ReadBuf() writes past the block. Mutated binary inputs hit these within seconds, so they
// reach the binary parser only when the environment variable RANZ_FUZZ_CFG_BINARY is "1":
// run_fuzzers.ps1 sets it for the replay of the seed corpus (valid configurations), not for
// the timed run. Set it by hand to hunt these bugs. The hash is not checked either way, as
// libFuzzer's memcmp hooks can learn the expected hash and pass a hash check.
// Once CfgReadNextFolderBin() is hardened, drop the variable and fuzz binary input always.

#include "fuzz_common.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

// A binary configuration starts with TAG_BINARY (8 bytes) and the SHA-0 of the rest
#define	FUZZ_CFG_BIN_HEADER_SIZE	(8 + SHA1_SIZE)

// True when RANZ_FUZZ_CFG_BINARY is "1" (read once)
static bool FuzzCfgBinaryEnabled(void)
{
	static int enabled = -1;

	if (enabled < 0)
	{
		char value[16];

		enabled = (GetEnv("RANZ_FUZZ_CFG_BINARY", value, sizeof(value)) && StrCmp(value, "1") == 0) ? 1 : 0;
	}

	return (enabled == 1);
}

// One configuration input
static void FuzzCfg(const uint8_t *data, size_t size)
{
	BUF *b;
	FOLDER *f;

	if (size >= FUZZ_CFG_BIN_HEADER_SIZE && Cmp((void *)data, TAG_BINARY, 8) == 0)
	{
		if (FuzzCfgBinaryEnabled() == false)
		{
			// Binary input outside the seed replay (see above)
			return;
		}

		// Binary mode, as CfgReadW() does it after its hash check
		b = FuzzNewBuf(data, size);
		SeekBuf(b, FUZZ_CFG_BIN_HEADER_SIZE, 0);
		f = CfgBufBinToFolder(b);
	}
	else
	{
		// Text mode, from the first byte (CfgReadW() keeps the UTF-8 BOM and the banner)
		b = FuzzNewBuf(data, size);
		f = CfgBufTextToFolder(b);
	}

	if (f != NULL)
	{
		// Write the parsed tree back in both formats, as the server does when it saves
		BUF *text = CfgFolderToBuf(f, true);
		BUF *bin = CfgFolderToBuf(f, false);

		FreeBuf(text);
		FreeBuf(bin);
		CfgDeleteFolder(f);
	}

	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzCfg, data, size);

	return 0;
}
