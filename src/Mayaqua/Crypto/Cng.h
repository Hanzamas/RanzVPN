// Cng.h
// The CNG state that the Crypto files share: the algorithm providers that CngInit() opens, once
// per process, and the test of an NTSTATUS. Only the Crypto files include it.

#ifndef	CRYPTO_CNG_H
#define	CRYPTO_CNG_H

#include "../MayaType.h"

#include <bcrypt.h>

// Whether a CNG call succeeded: an NTSTATUS of 0 or more (success or information)
#define	CNG_SUCCESS(status)		(((NTSTATUS)(status)) >= 0)

// CNG algorithm providers of MD4, MD5, SHA-1, SHA-256 and RC4; NULL when a provider failed to open
extern BCRYPT_ALG_HANDLE cng_md4;
extern BCRYPT_ALG_HANDLE cng_md5;
extern BCRYPT_ALG_HANDLE cng_sha1;
extern BCRYPT_ALG_HANDLE cng_sha256;
extern BCRYPT_ALG_HANDLE cng_rc4;

void CngInit();

#endif
