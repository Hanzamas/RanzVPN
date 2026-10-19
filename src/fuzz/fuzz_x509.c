// fuzz_x509.c
// libFuzzer target: X.509 certificate loading from a buffer (BufToX), DER and PEM, PEM
// certificate bundles (BufToXList, as for a chain file), and the conversion of the parsed
// certificates into Mayaqua's X (X509ToX)

#include "fuzz_common.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Memory.h"

#include <string.h>

// True when the input contains "ENCRYPTED". A PEM block with "Proc-Type: 4,ENCRYPTED" makes
// OpenSSL ask for a pass phrase (BioToX() passes no callback, so PEM_def_callback() prompts),
// which opens the console and waits for a key until libFuzzer reports a timeout.
// https://github.com/openssl/openssl/blob/openssl-3.5.0/crypto/pem/pem_lib.c
static bool FuzzHasEncryptedTag(const uint8_t *data, size_t size)
{
	static const char tag[] = "ENCRYPTED";
	size_t tag_len = sizeof(tag) - 1;
	size_t i;

	for (i = 0;i + tag_len <= size;i++)
	{
		if (memcmp(data + i, tag, tag_len) == 0)
		{
			return true;
		}
	}

	return false;
}

// One certificate input
static void FuzzX509(const uint8_t *data, size_t size)
{
	BUF *b = FuzzNewBuf(data, size);
	UINT num_passes = FuzzHasEncryptedTag(data, size) ? 1 : 2;
	UINT i;

	// Callers pass text = false (DER) or text = IsBase64(b) (PEM); try both on every input,
	// except PEM when the input could hold an encrypted PEM header (see above).
	// BufToX() frees b only when it cannot allocate an OpenSSL BIO, which does not happen here.
	for (i = 0;i < num_passes;i++)
	{
		X *x = BufToX(b, i == 1);

		if (x != NULL)
		{
			// Encode the parsed certificate again in both forms
			BUF *der = XToBuf(x, false);
			BUF *pem = XToBuf(x, true);

			FreeBuf(der);
			FreeBuf(pem);
			FreeX(x);
		}

		// The PEM pass also reads the input as a bundle of certificates
		if (i == 1)
		{
			FreeXList(BufToXList(b, true));
		}
	}

	FreeBuf(b);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzX509, data, size);

	return 0;
}
