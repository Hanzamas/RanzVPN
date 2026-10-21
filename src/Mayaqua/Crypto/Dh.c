// Dh.c
// Diffie-Hellman parameters on OpenSSL: a prime given in hex, or an RFC 2409 or RFC 3526 prime by size

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <openssl/dh.h>
#include <openssl/bn.h>

static BIGNUM *BinToBigNum(void *data, UINT size)
{
	BIGNUM *bn;
	if (data == NULL)
	{
		return NULL;
	}

	bn = BN_new();
	BN_bin2bn(data, size, bn);

	return bn;
}

// The DH parameters of the prime p and the generator g, which the result owns (p is freed on failure).
// A key is not generated here: TLS makes its own key from these parameters for each handshake.
static DH_CTX *DhNewFromPrime(BIGNUM *p, UINT g)
{
	DH_CTX *dh;
	BIGNUM *dhg;

	if (p == NULL)
	{
		return NULL;
	}

	dh = ZeroMalloc(sizeof(DH_CTX));
	dh->dh = DH_new();
	dhg = BN_new();
	if (dh->dh == NULL || dhg == NULL || BN_set_word(dhg, g) == false)
	{
		BN_free(dhg);
		BN_free(p);
		DhFree(dh);
		return NULL;
	}

	DH_set0_pqg(dh->dh, p, NULL, dhg);

	return dh;
}

DH_CTX *DhNewFromBits(UINT bits)
{
	BIGNUM *p;

	switch (bits)
	{
	case 160:
		return DhNew(DH_SIMPLE_160, 2);
	case 768:
		p = BN_get_rfc2409_prime_768(NULL);
		break;
	case 1024:
		p = BN_get_rfc2409_prime_1024(NULL);
		break;
	case 1536:
		p = BN_get_rfc3526_prime_1536(NULL);
		break;
	case 3072:
		p = BN_get_rfc3526_prime_3072(NULL);
		break;
	case 4096:
		p = BN_get_rfc3526_prime_4096(NULL);
		break;
	default:
		p = BN_get_rfc3526_prime_2048(NULL);
		break;
	}

	return DhNewFromPrime(p, 2);
}

DH_CTX *DhNew(char *prime, UINT g)
{
	BUF *buf;
	BIGNUM *p;
	if (prime == NULL || g == 0)
	{
		return NULL;
	}

	buf = StrToBin(prime);
	p = BinToBigNum(buf->Buf, buf->Size);
	FreeBuf(buf);

	return DhNewFromPrime(p, g);
}

void DhFree(DH_CTX *dh)
{
	if (dh == NULL)
	{
		return;
	}

	DH_free(dh->dh);

	Free(dh);
}
