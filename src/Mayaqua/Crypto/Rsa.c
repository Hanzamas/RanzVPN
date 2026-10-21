// Rsa.c
// RSA keys on OpenSSL: generate, sign and verify; the K key object: clone and free

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

static BUF *RsaPublicToBuf(K *k) {
	const RSA *rsa;
	const BIGNUM *n;
	if (k == NULL || k->pkey == NULL)
		return NULL;

	rsa = EVP_PKEY_get0_RSA(k->pkey);
	if (rsa == NULL)
		return NULL;

	RSA_get0_key(rsa, &n, NULL, NULL);
	if (n == NULL)
		return NULL;

	BUF *b = BigNumToBuf(n);

	if (b == NULL)
		return NULL;

	return b;
}

static UINT RsaPublicSize(K *k) {
	BUF *b = RsaPublicToBuf(k);
	if (b == NULL)
		return 0;

	UINT ret = b->Size;

	FreeBuf(b);

	return ret;
}

BUF *BigNumToBuf(const BIGNUM *bn) {
	if (bn == NULL)
		return NULL;

	UINT size = BN_num_bytes(bn);
	UCHAR *tmp = ZeroMalloc(size);
	BN_bn2bin(bn, tmp);

	BUF *b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	SeekBuf(b, 0, 0);

	return b;
}

// The clone holds its own reference to the key, FreeK releases exactly one. A key is never changed
// after it is loaded or generated, so sharing the EVP_PKEY is safe across threads.
K *CloneK(K *k) {
	if (k == NULL || k->pkey == NULL)
		return NULL;

	if (EVP_PKEY_up_ref(k->pkey) != 1)
		return NULL;

	K *ret = ZeroMalloc(sizeof(K));
	ret->pkey = k->pkey;
	ret->private_key = k->private_key;

	return ret;
}

// Verifies the RSASSA-PKCS1-v1_5 signature with SHA-1 of a client certificate (over the server's
// random bytes). sign_size is the size received: a signature is exactly one modulus long, and
// OpenSSL accepts only the padding, the SHA-1 DigestInfo and the hash in the block, nothing after it.
bool RsaVerifyEx(void *data, UINT data_size, void *sign, UINT sign_size, K *k) {
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	int key_size;
	bool ret = false;
	if (data == NULL || data_size == 0 || sign == NULL || k == NULL || k->pkey == NULL || k->private_key != false ||
	    EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
		return false;

	key_size = EVP_PKEY_size(k->pkey);
	if (key_size <= 0 || sign_size != (UINT)key_size)
		return false;

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
		return false;

	if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha1(), NULL, k->pkey) == 1 &&
	    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) == 1 &&
	    EVP_DigestVerify(md_ctx, sign, sign_size, data, data_size) == 1)
		ret = true;

	EVP_MD_CTX_free(md_ctx);

	return ret;
}

// Makes the RSASSA-PKCS1-v1_5 signature with SHA-1 of src (the client certificate signature). The
// signature is EVP_PKEY_size() bytes long; a dst_size smaller than that is refused before anything
// is written.
bool RsaSignEx(void *dst, UINT dst_size, void *src, UINT src_size, K *k) {
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	size_t sign_size;
	int key_size;
	bool ret = false;
	if (dst == NULL || src == NULL || src_size == 0 || k == NULL || k->pkey == NULL ||
	    EVP_PKEY_base_id(k->pkey) != EVP_PKEY_RSA)
		return false;

	key_size = EVP_PKEY_size(k->pkey);
	if (key_size <= 0 || (UINT)key_size > dst_size)
		return false;

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL)
		return false;

	sign_size = (size_t)key_size;
	if (EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha1(), NULL, k->pkey) == 1 &&
	    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) == 1 &&
	    EVP_DigestSign(md_ctx, dst, &sign_size, src, src_size) == 1 &&
	    sign_size == (size_t)key_size)
		ret = true;

	EVP_MD_CTX_free(md_ctx);

	return ret;
}

// Generates an RSA key pair of the given size (RSA_KEY_SIZE for 0). On failure nothing is returned
// in *priv and *pub, and everything made so far is freed.
bool RsaGen(K **priv, K **pub, UINT bit) {
	int ret = 0;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	K *priv_key, *pub_key;
	BIO *bio;
	char errbuf[MAX_SIZE];
	UINT size = 0;
	if (priv == NULL || pub == NULL)
		return false;
	if (bit == 0)
		bit = RSA_KEY_SIZE;

	e = BN_new();
	if (e == NULL)
		return false;
	ret = BN_set_word(e, RSA_F4);
	if (ret == 0) {
		BN_free(e);
		Debug("BN_set_word: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		return false;
	}

	rsa = RSA_new();
	if (rsa != NULL)
		ret = RSA_generate_key_ex(rsa, bit, e, NULL);
	else
		ret = 0;
	BN_free(e);
	if (ret == 0) {
		Debug("RSA_generate_key_ex: err=%s\n", ERR_error_string(ERR_get_error(), errbuf));
		RSA_free(rsa);
		return false;
	}

	bio = BIO_new(BIO_s_mem());
	i2d_RSAPrivateKey_bio(bio, rsa);
	BIO_seek(bio, 0);
	priv_key = BioToK(bio, true, false, NULL);
	FreeBio(bio);

	bio = BIO_new(BIO_s_mem());
	i2d_RSA_PUBKEY_bio(bio, rsa);
	BIO_seek(bio, 0);
	pub_key = BioToK(bio, false, false, NULL);
	FreeBio(bio);

	RSA_free(rsa);

	if (priv_key == NULL || pub_key == NULL) {
		FreeK(priv_key);
		FreeK(pub_key);
		return false;
	}

	size = RsaPublicSize(pub_key);

	if (size != ((bit + 7) / 8)) {
		// The modulus came out shorter than asked for: generate again
		FreeK(priv_key);
		FreeK(pub_key);

		return RsaGen(priv, pub, bit);
	}

	*priv = priv_key;
	*pub = pub_key;

	return true;
}

void FreeK(K *k) {
	if (k == NULL)
		return;

	FreePKey(k->pkey);
	Free(k);
}

void FreePKey(EVP_PKEY *pkey) {
	if (pkey == NULL)
		return;

	EVP_PKEY_free(pkey);
}
