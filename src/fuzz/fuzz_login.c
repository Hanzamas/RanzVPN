// fuzz_login.c
// libFuzzer target: the client's "login" PACK as the server reads it before the authentication
// (BufToPack, then ParseLoginRequest, FND-196 #164)
//
// fuzz-max-len: 4096

#include "fuzz_common.h"

#include "Cedar/Protocol.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"

// One login PACK input
static void FuzzLogin(const uint8_t *data, size_t size)
{
	BUF *b = FuzzNewBuf(data, size);
	PACK *p = BufToPack(b);

	if (p != NULL)
	{
		LOGIN_REQ req;

		ParseLoginRequest(p, &req);

		FreePack(p);
	}

	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzLogin, data, size);

	return 0;
}
