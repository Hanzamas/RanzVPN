// Cipher.c
// The RC4 CRYPT on CNG

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <bcrypt.h>

// Longest RC4 key (bytes) that CNG turns into real RC4. CNG accepts longer keys without an error
// but then produces a keystream that is not RC4, so NewCrypt() does not give it those.
#define	RC4_MAX_KEY_SIZE	64

// RC4 key: a CNG key object, which keeps the keystream position from one Encrypt() call to the next.
// Only keys of 1 to RC4_MAX_KEY_SIZE bytes get a key object: CNG refuses a 0-byte key, and it accepts
// a longer one without an error but then produces a keystream that is not RC4. With any other key,
// Rc4Key stays NULL and Encrypt() writes zeros.
CRYPT *NewCrypt(void *key, UINT size)
{
	CRYPT *c = ZeroMalloc(sizeof(CRYPT));
	BCRYPT_KEY_HANDLE k = NULL;

	CngInit();

	if (cng_rc4 != NULL && key != NULL && size >= 1 && size <= RC4_MAX_KEY_SIZE &&
		CNG_SUCCESS(BCryptGenerateSymmetricKey(cng_rc4, &k, NULL, 0, (PUCHAR)key, size, 0)))
	{
		c->Rc4Key = k;
	}

	return c;
}

void FreeCrypt(CRYPT *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->Rc4Key != NULL)
	{
		BCryptDestroyKey(c->Rc4Key);
	}

	Free(c);
}

// RC4 of size bytes; dst may be src. Should CNG fail, dst is all zero rather than left as it was,
// so that an in-place call never leaves the plain text in place.
void Encrypt(CRYPT *c, void *dst, void *src, UINT size)
{
	ULONG done = 0;
	if (c == NULL || dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	if (c->Rc4Key == NULL ||
		CNG_SUCCESS(BCryptEncrypt(c->Rc4Key, (PUCHAR)src, size, NULL, NULL, 0, (PUCHAR)dst, size, &done, 0)) == false ||
		done != size)
	{
		Zero(dst, size);
	}
}
