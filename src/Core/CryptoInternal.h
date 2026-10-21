// CryptoInternal.h
// The state that the Crypto files share: the CNG providers CryptoInit() opens, the ML-KEM entry
// points it resolves, and the CNG and NCrypt names that the API level of the new core
// (Windows Server 2022, NTDDI_WIN10_FE) does not declare. Only the Crypto files include it.

#ifndef CORE_CRYPTO_INTERNAL_H
#define CORE_CRYPTO_INTERNAL_H

#include "Core/Crypto.h"

#include <bcrypt.h>
#include <ncrypt.h>

// Whether a CNG call succeeded: an NTSTATUS of 0 or more (success or information)
#define CNG_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

// CNG blob of an X25519 key: BCRYPT_ECCKEY_BLOB, then X (the u-coordinate), Y (unused, zero) and,
// in a private blob, d (the clamped scalar), 32 bytes each
#define CRYPTO_X25519_PUBLIC_BLOB_SIZE  (sizeof(BCRYPT_ECCKEY_BLOB) + 2 * CRYPTO_X25519_SIZE)
#define CRYPTO_X25519_PRIVATE_BLOB_SIZE (sizeof(BCRYPT_ECCKEY_BLOB) + 3 * CRYPTO_X25519_SIZE)

// ML-KEM names of the Windows 11 24H2 SDK level (NTDDI_WIN11_GE), above the level of the new core:
// the module looks ML-KEM up at run time, so they are spelt out here
#define CRYPTO_MLKEM_ALGORITHM         L"ML-KEM"
#define CRYPTO_MLKEM_PARAMETER_SET     L"ParameterSetName" // BCRYPT_PARAMETER_SET_NAME
#define CRYPTO_MLKEM_PARAMETER_SET_768 L"768"
#define CRYPTO_MLKEM_PUBLIC_BLOB       L"MLKEMPUBLICBLOB"
#define CRYPTO_MLKEM_PUBLIC_MAGIC      0x504B4C4D // 'MLKP'

// BCryptEncapsulate and BCryptDecapsulate (bcrypt.dll of Windows 11 24H2 and later)
typedef NTSTATUS(WINAPI *CRYPTO_ENCAPSULATE_PROC)(BCRYPT_KEY_HANDLE key, PUCHAR secret, ULONG secret_size, ULONG *secret_result,
                                                   PUCHAR ciphertext, ULONG ciphertext_size, ULONG *ciphertext_result, ULONG flags);
typedef NTSTATUS(WINAPI *CRYPTO_DECAPSULATE_PROC)(BCRYPT_KEY_HANDLE key, PUCHAR ciphertext, ULONG ciphertext_size,
                                                   PUCHAR secret, ULONG secret_size, ULONG *secret_result, ULONG flags);

// Opened by CryptoInit(), once, for the life of the process; NULL when the provider is missing
extern BCRYPT_ALG_HANDLE crypto_x25519;                  // ECDH on curve25519
extern BCRYPT_ALG_HANDLE crypto_mlkem;                   // ML-KEM, NULL where the OS has none
extern CRYPTO_ENCAPSULATE_PROC crypto_encapsulate;       // NULL with crypto_mlkem
extern CRYPTO_DECAPSULATE_PROC crypto_decapsulate;

// CryptoX25519.c: the private and public CNG blobs of an X25519 key, in RFC 7748 byte order
void CryptoX25519PrivateBlob(UCHAR *blob, const UCHAR *priv);
void CryptoX25519PublicBlob(UCHAR *blob, const UCHAR *pub);
bool CryptoX25519FromRawSecret(UCHAR *shared, const UCHAR *raw);

#endif // CORE_CRYPTO_INTERNAL_H
