// fuzz_pack.c
// libFuzzer target: PACK deserialization (BufToPack / ReadPack), the decoder of every PACK
// received by the server, the client and the admin RPC

#include "fuzz_common.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"

// One PACK input
static void FuzzPack(const uint8_t *data, size_t size)
{
	BUF *b = FuzzNewBuf(data, size);
	PACK *p = BufToPack(b);

	if (p != NULL)
	{
		// Encode the decoded PACK and decode the result again. No equality check: the decoder trims
		// strings and ends names at a NUL byte, so the second encoding may differ from the input.
		// ReadElement() rejects an element with a value it cannot read (FND-42 #114), so no NULL
		// value is encoded.
		BUF *b2 = PackToBuf(p);

		SeekBufToBegin(b2);
		PACK *p2 = BufToPack(b2);

		FreePack(p2);
		FreeBuf(b2);
		FreePack(p);
	}

	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzPack, data, size);

	return 0;
}
