#include "Key.h"

#include "Encrypt.h"
#include "Memory.h"
#include "Str.h"

#include <openssl/evp.h>

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
