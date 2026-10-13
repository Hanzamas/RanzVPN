#include "Key.h"

#include "Encrypt.h"
#include "Memory.h"
#include "Str.h"

#include <openssl/evp.h>

static int CryptoKeyTypeToID(const CRYPTO_KEY_TYPE type)
{
	switch (type)
	{
		case KEY_UNKNOWN:
			break;
		case KEY_X25519:
			return EVP_PKEY_X25519;
#if defined(EVP_PKEY_X448)
		case KEY_X448:
			return EVP_PKEY_X448;
#endif
		default:
			Debug("CryptoKeyTypeToID(): Unhandled type %u!\n", type);
	}

	return EVP_PKEY_NONE;
}

UINT CryptoKeyTypeSize(const CRYPTO_KEY_TYPE type)
{
	switch (type)
	{
		case KEY_UNKNOWN:
			break;
		case KEY_X25519:
			return KEY_X25519_SIZE;
		case KEY_X448:
			return KEY_X448_SIZE;
		default:
			Debug("CryptoKeyTypeSize(): Unhandled type %u!\n", type);
	}

	return 0;
}

CRYPTO_KEY_RAW *CryptoKeyRawNew(const void *data, const UINT size, const CRYPTO_KEY_TYPE type)
{
	if (size == 0 || size != CryptoKeyTypeSize(type))
	{
		return NULL;
	}

	CRYPTO_KEY_RAW *key = Malloc(sizeof(CRYPTO_KEY_RAW));
	key->Data = MallocEx(size, true);
	key->Size = size;
	key->Type = type;

	if (data == NULL)
	{
		Rand(key->Data, key->Size);
	}
	else
	{
		Copy(key->Data, data, key->Size);
	}

	return key;
}

void CryptoKeyRawFree(CRYPTO_KEY_RAW *key)
{
	if (key == NULL)
	{
		return;
	}

	Free(key->Data);
	Free(key);
}
