// Init.c
// The crypto libraries of the process: the OpenSSL providers and the CNG algorithm providers,
// the OpenSSL error queue and the OpenSSL state of a thread

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Trace.h"

#include <bcrypt.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

#ifndef SKIP_OQS_PROVIDER
	extern OSSL_provider_init_fn oqs_provider_init;
#endif

static OSSL_PROVIDER *ossl_provider_legacy = NULL;
static OSSL_PROVIDER *ossl_provider_default = NULL;
static OSSL_PROVIDER *ossl_provider_oqsprovider = NULL;

// CNG algorithm providers of MD4, MD5, SHA-1, SHA-256 and RC4, which run on CNG instead of OpenSSL.
// They are opened once, on first use, and kept for the life of the process, as the CNG
// pseudo-handles are (MayaType.h selects the Vista SDK level, which does not declare those).
// A provider that failed to open stays NULL.
static INIT_ONCE cng_init_once = INIT_ONCE_STATIC_INIT;
BCRYPT_ALG_HANDLE cng_md4 = NULL;
BCRYPT_ALG_HANDLE cng_md5 = NULL;
BCRYPT_ALG_HANDLE cng_sha1 = NULL;
BCRYPT_ALG_HANDLE cng_sha256 = NULL;
BCRYPT_ALG_HANDLE cng_rc4 = NULL;

// Open one CNG algorithm provider; NULL on failure
static BCRYPT_ALG_HANDLE CngOpenAlg(LPCWSTR alg_id)
{
	BCRYPT_ALG_HANDLE h = NULL;

	if (CNG_SUCCESS(BCryptOpenAlgorithmProvider(&h, alg_id, NULL, 0)) == false)
	{
		return NULL;
	}

	return h;
}

// INIT_ONCE callback of CngInit(): open every provider
static BOOL CALLBACK CngOpenAll(PINIT_ONCE once, PVOID param, PVOID *context)
{
	cng_md4 = CngOpenAlg(BCRYPT_MD4_ALGORITHM);
	cng_md5 = CngOpenAlg(BCRYPT_MD5_ALGORITHM);
	cng_sha1 = CngOpenAlg(BCRYPT_SHA1_ALGORITHM);
	cng_sha256 = CngOpenAlg(BCRYPT_SHA256_ALGORITHM);
	cng_rc4 = CngOpenAlg(BCRYPT_RC4_ALGORITHM);

	return TRUE;
}

// Open the CNG providers, once per process; any thread, any time, also before InitCryptLibrary()
void CngInit()
{
	InitOnceExecuteOnce(&cng_init_once, CngOpenAll, NULL, NULL);
}

// Empties the OpenSSL error queue of this thread. The messages are formatted only while Debug() shows them
void DrainCryptErrors(char *what)
{
	UINT err;

	if (IsDebug() == false && IsTraceEnabled() == false)
	{
		ERR_clear_error();
		return;
	}

	while ((err = ERR_get_error()) != 0)
	{
		char tmp[256];

		ERR_error_string_n(err, tmp, sizeof(tmp));
		Debug("%s: %s\n", what, tmp);
	}
}

void FreeOpenSSLThreadState()
{
	OPENSSL_thread_stop();
}

void FreeCryptLibrary()
{
	if (ossl_provider_default != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_default);
		ossl_provider_default = NULL;
	}

	if (ossl_provider_legacy != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_legacy);
		ossl_provider_legacy = NULL;
	}

	if (ossl_provider_oqsprovider != NULL)
	{
		OSSL_PROVIDER_unload(ossl_provider_oqsprovider);
		ossl_provider_oqsprovider = NULL;
	}
}

void InitCryptLibrary()
{
	ossl_provider_legacy = OSSL_PROVIDER_load(NULL, "legacy");
	ossl_provider_default = OSSL_PROVIDER_load(NULL, "default");

	char *oqs_provider_name = "oqsprovider";
	#ifndef SKIP_OQS_PROVIDER
		// oqsprovider is linked in, so register it as a built-in provider
		OSSL_PROVIDER_add_builtin(NULL, oqs_provider_name, oqs_provider_init); 
	#endif
	ossl_provider_oqsprovider = OSSL_PROVIDER_load(NULL, oqs_provider_name);

	// Seeds OpenSSL's own generator, which TLS, RSA and DH still use; Rand() runs on CNG
	RAND_poll();

	// The CNG providers are opened here rather than on the first hash
	CngInit();

}
