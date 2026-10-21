// Pem.c
// PEM and DER forms on OpenSSL: X and K to and from BIO, BUF and files

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

typedef struct CB_PARAM
{
	char *password;
} CB_PARAM;

X *FileToXW(wchar_t *filename)
{
	if (filename == NULL)
	{
		return NULL;
	}

	BUF *b = ReadDumpW(filename);
	bool text = IsBase64(b);

	X *x = BufToX(b, text);
	FreeBuf(b);

	return x;
}

bool XToFileW(X *x, wchar_t *filename, bool text)
{
	if (x == NULL || filename == NULL)
	{
		return false;
	}

	BUF *b = XToBuf(x, text);
	if (b == NULL)
	{
		return false;
	}

	bool ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

K *FileToKW(wchar_t *filename, bool private_key, char *password)
{
	K *k;
	if (filename == NULL)
	{
		return NULL;
	}

	BUF *b = ReadDumpW(filename);
	if (b == NULL)
	{
		return NULL;
	}

	bool text = IsBase64(b);
	if (text == false)
	{
		k = BufToK(b, private_key, false, NULL);
	}
	else
	{
		k = BufToK(b, private_key, true, NULL);
		if (k == NULL)
		{
			k = BufToK(b, private_key, true, password);
		}
	}

	FreeBuf(b);

	return k;
}

bool KToFileW(K *k, wchar_t *filename, bool text, char *password)
{
	if (k == NULL || filename == NULL)
	{
		return false;
	}

	BUF *b = KToBuf(k, text, password);
	if (b == NULL)
	{
		return false;
	}

	bool ret = DumpBufW(b, filename);
	FreeBuf(b);

	return ret;
}

BUF *KToBuf(K *k, bool text, char *password)
{
	if (k == NULL)
	{
		return NULL;
	}

	BIO *bio = KToBio(k, text, password);
	if (bio == NULL)
	{
		return NULL;
	}

	BUF *buf = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(buf, 0, 0);

	return buf;
}

BIO *KToBio(K *k, bool text, char *password)
{
	if (k == NULL)
	{
		return NULL;
	}

	BIO *bio = BIO_new(BIO_s_mem());

	if (k->private_key)
	{
		if (text == false)
		{
			i2d_PrivateKey_bio(bio, k->pkey);
		}
		else
		{
			if (password == 0 || StrLen(password) == 0)
			{
				PEM_write_bio_PrivateKey(bio, k->pkey, NULL, NULL, 0, NULL, NULL);
			}
			else
			{
				CB_PARAM cb;
				cb.password = password;
				PEM_write_bio_PrivateKey(bio, k->pkey, EVP_des_ede3_cbc(),
					NULL, 0, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			}
		}
	}
	else
	{
		if (text == false)
		{
			i2d_PUBKEY_bio(bio, k->pkey);
		}
		else
		{
			PEM_write_bio_PUBKEY(bio, k->pkey);
		}
	}

	return bio;
}

bool IsBase64(BUF *b)
{
	if (b == NULL)
	{
		return false;
	}

	if (SearchAsciiInBinary(b->Buf, b->Size, "-----BEGIN", false) != INFINITE)
	{
		return true;
	}

	for (UINT i = 0;i < b->Size;i++)
	{
		char c = ((char *)b->Buf)[i];
		bool b = false;
		if ('a' <= c && c <= 'z')
		{
			b = true;
		}
		else if ('A' <= c && c <= 'Z')
		{
			b = true;
		}
		else if ('0' <= c && c <= '9')
		{
			b = true;
		}
		else if (c == ':' || c == '.' || c == ';' || c == ',')
		{
			b = true;
		}
		else if (c == '!' || c == '&' || c == '#' || c == '(' || c == ')')
		{
			b = true;
		}
		else if (c == '-' || c == ' ')
		{
			b = true;
		}
		else if (c == 13 || c == 10 || c == EOF)
		{
			b = true;
		}
		else if (c == '\t' || c == '=' || c == '+' || c == '/')
		{
			b = true;
		}
		if (b == false)
		{
			return false;
		}
	}
	return true;
}

bool IsEncryptedK(BUF *b, bool private_key)
{
	if (b == NULL)
	{
		return false;
	}
	if (IsBase64(b) == false)
	{
		return false;
	}

	K *k = BufToK(b, private_key, true, NULL);
	if (k != NULL)
	{
		FreeK(k);
		return false;
	}

	return true;
}

K *OpensslEngineToK(char *key_file_name, char *engine_name)
{
#ifndef OPENSSL_NO_ENGINE
    ENGINE *engine = ENGINE_by_id(engine_name);
    ENGINE_init(engine);
    EVP_PKEY *pkey;
    pkey = ENGINE_load_private_key(engine, key_file_name, NULL, NULL);
   	K *k = ZeroMalloc(sizeof(K));
    k->pkey = pkey;
    k->private_key = true;
    return k;
#else
    return NULL;
#endif
}

K *BufToK(BUF *b, bool private_key, bool text, char *password)
{
	if (b == NULL)
	{
		return NULL;
	}

	BIO *bio = BufToBio(b);
	K *k = BioToK(bio, private_key, text, password);
	FreeBio(bio);

	return k;
}

K *BioToK(BIO *bio, bool private_key, bool text, char *password)
{
	EVP_PKEY *pkey;
	if (bio == NULL)
	{
		return NULL;
	}

	if (password != NULL && StrLen(password) == 0)
	{
		password = NULL;
	}

	if (private_key == false)
	{
		if (text == false)
		{
			pkey = d2i_PUBKEY_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			CB_PARAM cb;
			cb.password = password;
			pkey = PEM_read_bio_PUBKEY(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}
	else
	{
		if (text == false)
		{
			pkey = d2i_PrivateKey_bio(bio, NULL);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
		else
		{
			CB_PARAM cb;
			cb.password = password;
			pkey = PEM_read_bio_PrivateKey(bio, NULL, (pem_password_cb *)PKeyPasswordCallbackFunction, &cb);
			if (pkey == NULL)
			{
				return NULL;
			}
		}
	}

	K *k = ZeroMalloc(sizeof(K));
	k->pkey = pkey;
	k->private_key = private_key;

	return k;
}

int PKeyPasswordCallbackFunction(char *buf, int bufsize, int verify, void *param)
{
	if (buf == NULL || param == NULL || bufsize == 0)
	{
		return 0;
	}

	CB_PARAM *cb = (CB_PARAM *)param;
	if (cb->password == NULL)
	{
		return 0;
	}

	return StrCpy(buf, bufsize, cb->password);
}

BUF *XToBuf(X *x, bool text)
{
	if (x == NULL)
	{
		return NULL;
	}

	BIO *bio = XToBio(x, text);
	if (bio == NULL)
	{
		return NULL;
	}

	BUF *b = BioToBuf(bio);
	FreeBio(bio);

	SeekBuf(b, 0, 0);

	return b;
}

BIO *XToBio(X *x, bool text)
{
	if (x == NULL)
	{
		return NULL;
	}

	BIO *bio = BIO_new(BIO_s_mem());

	if (text == false)
	{
		i2d_X509_bio(bio, x->x509);
	}
	else
	{
		PEM_write_bio_X509(bio, x->x509);
	}

	return bio;
}

// The caller keeps b and frees it, also when this fails
X *BufToX(BUF *b, bool text)
{
	if (b == NULL)
	{
		return NULL;
	}

	BIO *bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	X *x = BioToX(bio, text);

	FreeBio(bio);

	return x;
}

// The caller keeps b and frees it, also when this fails
LIST *BufToXList(BUF *b, bool text)
{
	if (b == NULL)
	{
		return NULL;
	}

	BIO *bio = BufToBio(b);
	if (bio == NULL)
	{
		return NULL;
	}

	LIST *chain = BioToXList(bio, text);

	FreeBio(bio);

	return chain;
}

X *BioToX(BIO *bio, bool text)
{
	X509 *x509;
	if (bio == NULL)
	{
		return NULL;
	}

	if (text == false)
	{
		x509 = d2i_X509_bio(bio, NULL);
	}
	else
	{
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	}

	if (x509 == NULL)
	{
		return NULL;
	}

	X *x = X509ToX(x509);

	if (x == NULL)
	{
		FreeX509(x509);
		return NULL;
	}

	return x;
}

LIST *BioToXList(BIO *bio, bool text)
{
	X *x;
	STACK_OF(X509_INFO) *sk = NULL;
	X509_INFO *xi;
	LIST *chain;

	if (bio == NULL || text == false)
	{
		return NULL;
	}

	sk = PEM_X509_INFO_read_bio(bio, NULL, NULL, NULL);
	if (sk == NULL)
	{
		return NULL;
	}

	chain = NewList(NULL);

	while (sk_X509_INFO_num(sk))
	{
		xi = sk_X509_INFO_shift(sk);
		x = X509ToX(xi->x509);
		if (x != NULL)
		{
			// The X owns the certificate now
			xi->x509 = NULL;
			Add(chain, x);
		}
		// Also frees a certificate X509ToX refused, once
		X509_INFO_free(xi);
	}

	sk_X509_INFO_free(sk);

	return chain;
}

void FreeBio(BIO *bio)
{
	if (bio == NULL)
	{
		return;
	}

	BIO_free(bio);
}

BUF *BioToBuf(BIO *bio)
{
	if (bio == NULL)
	{
		return NULL;
	}

	BIO_seek(bio, 0);
	UINT size = (UINT)BIO_number_written(bio);
	void *tmp = Malloc(size);
	BIO_read(bio, tmp, size);

	BUF *b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);

	return b;
}

BIO *BufToBio(BUF *b)
{
	if (b == NULL)
	{
		return NULL;
	}

	BIO *bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		return NULL;
	}
	BIO_write(bio, b->Buf, b->Size);
	BIO_seek(bio, 0);

	return bio;
}
