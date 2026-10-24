// fuzz_cfg.c
// libFuzzer target: configuration loading from a buffer, text (CfgBufTextToFolder) and
// binary (CfgBufBinToFolder), chosen the way CfgReadW() chooses for vpn_server.config
//
// The binary parser (CfgReadNextFolderBin) checks every count and size against the bytes left
// and rejects a short or malformed input (SEC-3 #96), so mutated binary inputs are fuzzed as
// text inputs are. The hash is not checked: libFuzzer's memcmp hooks can learn the expected hash
// and pass a hash check, and CfgReadW() checks it before the parser runs.
//
// fuzz-max-len: 4096

#include "fuzz_common.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"

// A binary configuration starts with TAG_BINARY (8 bytes) and the SHA-0 of the rest
#define	FUZZ_CFG_BIN_HEADER_SIZE	(8 + SHA1_SIZE)

// One configuration input
static void FuzzCfg(const uint8_t *data, size_t size)
{
	BUF *b;
	FOLDER *f;

	if (size >= FUZZ_CFG_BIN_HEADER_SIZE && Cmp((void *)data, TAG_BINARY, 8) == 0)
	{
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
		// Write the parsed tree back as text, as the server does when it saves
		BUF *text = CfgFolderToBuf(f);

		FreeBuf(text);
		CfgDeleteFolder(f);
	}

	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzCfg, data, size);

	return 0;
}
