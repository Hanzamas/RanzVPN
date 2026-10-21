// Cipher.c
// Symmetric ciphers: the AEAD CIPHER on OpenSSL EVP and the RC4 CRYPT on CNG

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <bcrypt.h>

#include <openssl/evp.h>

// Longest RC4 key (bytes) that CNG turns into real RC4. CNG accepts longer keys without an error
// but then produces a keystream that is not RC4, so NewCrypt() does not give it those.
#define	RC4_MAX_KEY_SIZE	64

CIPHER *NewCipher(char *name)
{
	CIPHER *c;
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CIPHER));

	StrCpy(c->Name, sizeof(c->Name), name);

	c->Cipher = EVP_get_cipherbyname(c->Name);
	if (c->Cipher == NULL)
	{
		FreeCipher(c);
		return NULL;
	}

	c->Ctx = EVP_CIPHER_CTX_new();

	return c;
}

void SetCipherKey(CIPHER *c, void *key, bool enc)
{
	if (c == NULL || key == NULL)
	{
		return;
	}

	if (c->Ctx != NULL)
	{
		EVP_CipherInit(c->Ctx, c->Cipher, key, NULL, enc);
	}

	c->Encrypt = enc;
}

UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size)
{
	int r = src_size;
	int r2 = 0;
	if (c == NULL)
	{
		return 0;
	}
	else if (iv == NULL || tag == NULL || tag_size == 0 || dest == NULL || src == NULL || src_size == 0)
	{
		return 0;
	}

	if (EVP_CipherInit_ex(c->Ctx, NULL, NULL, NULL, iv, c->Encrypt) == false)
	{
		DrainCryptErrors("CipherProcessAead(): EVP_CipherInit_ex() failed");
		return 0;
	}

	if (c->Encrypt == false)
	{
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag) == false)
		{
			DrainCryptErrors("CipherProcessAead(): EVP_CTRL_AEAD_SET_TAG failed");
			return 0;
		}
	}

	if (aad != NULL && aad_size != 0)
	{
		if (EVP_CipherUpdate(c->Ctx, NULL, &r, aad, aad_size) == false)
		{
			DrainCryptErrors("CipherProcessAead(): EVP_CipherUpdate() failed");
			return 0;
		}
	}

	if (EVP_CipherUpdate(c->Ctx, dest, &r, src, src_size) == false)
	{
		DrainCryptErrors("CipherProcessAead(): EVP_CipherUpdate() failed");
		return 0;
	}

	if (EVP_CipherFinal_ex(c->Ctx, ((UCHAR *)dest) + (UINT)r, &r2) == false)
	{
		DrainCryptErrors("CipherProcessAead(): EVP_CipherFinal_ex() failed");
		return 0;
	}

	if (c->Encrypt)
	{
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag) == false)
		{
			DrainCryptErrors("CipherProcessAead(): EVP_CTRL_AEAD_GET_TAG failed");
			return 0;
		}
	}

	return r + r2;
}

void FreeCipher(CIPHER *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->Ctx != NULL)
	{
		EVP_CIPHER_CTX_free(c->Ctx);
	}

	Free(c);
}

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
