// Aead.c
// The AEAD CIPHER (ChaCha20-Poly1305 of the UDP acceleration) on OpenSSL EVP

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <openssl/evp.h>

CIPHER *NewCipher(char *name) {
	if (name == NULL)
		return NULL;

	CIPHER *c = ZeroMalloc(sizeof(CIPHER));

	StrCpy(c->Name, sizeof(c->Name), name);

	c->Cipher = EVP_get_cipherbyname(c->Name);
	if (c->Cipher == NULL) {
		FreeCipher(c);
		return NULL;
	}

	c->Ctx = EVP_CIPHER_CTX_new();

	return c;
}

void SetCipherKey(CIPHER *c, void *key, bool enc) {
	if (c == NULL || key == NULL)
		return;

	if (c->Ctx != NULL)
		EVP_CipherInit(c->Ctx, c->Cipher, key, NULL, enc);

	c->Encrypt = enc;
}

UINT CipherProcessAead(CIPHER *c, void *iv, void *tag, UINT tag_size, void *dest, void *src, UINT src_size, void *aad, UINT aad_size) {
	int r = src_size;
	int r2 = 0;
	if (c == NULL)
		return 0;
	else if (iv == NULL || tag == NULL || tag_size == 0 || dest == NULL || src == NULL || src_size == 0)
		return 0;

	if (EVP_CipherInit_ex(c->Ctx, NULL, NULL, NULL, iv, c->Encrypt) == false) {
		DrainCryptErrors("CipherProcessAead(): EVP_CipherInit_ex() failed");
		return 0;
	}

	if (c->Encrypt == false) {
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_SET_TAG, tag_size, tag) == false) {
			DrainCryptErrors("CipherProcessAead(): EVP_CTRL_AEAD_SET_TAG failed");
			return 0;
		}
	}

	if (aad != NULL && aad_size != 0) {
		if (EVP_CipherUpdate(c->Ctx, NULL, &r, aad, aad_size) == false) {
			DrainCryptErrors("CipherProcessAead(): EVP_CipherUpdate() failed");
			return 0;
		}
	}

	if (EVP_CipherUpdate(c->Ctx, dest, &r, src, src_size) == false) {
		DrainCryptErrors("CipherProcessAead(): EVP_CipherUpdate() failed");
		return 0;
	}

	if (EVP_CipherFinal_ex(c->Ctx, ((UCHAR *)dest) + (UINT)r, &r2) == false) {
		DrainCryptErrors("CipherProcessAead(): EVP_CipherFinal_ex() failed");
		return 0;
	}

	if (c->Encrypt) {
		if (EVP_CIPHER_CTX_ctrl(c->Ctx, EVP_CTRL_AEAD_GET_TAG, tag_size, tag) == false) {
			DrainCryptErrors("CipherProcessAead(): EVP_CTRL_AEAD_GET_TAG failed");
			return 0;
		}
	}

	return r + r2;
}

void FreeCipher(CIPHER *c) {
	if (c == NULL)
		return;

	if (c->Ctx != NULL)
		EVP_CIPHER_CTX_free(c->Ctx);

	Free(c);
}
