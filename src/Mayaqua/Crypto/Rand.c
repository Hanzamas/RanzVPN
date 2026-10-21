// Rand.c
// Random numbers from the system-preferred CNG generator

#include "Mayaqua/Encrypt.h"

#include "Mayaqua/Crypto/Cng.h"
#include "Mayaqua/Kernel.h"

#include <bcrypt.h>

// BCryptGenRandom() flag of Windows 7 and later, in case the Vista SDK level of MayaType.h hides it
#ifndef BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#endif // BCRYPT_USE_SYSTEM_PREFERRED_RNG

UINT64 Rand64() {
	UINT64 i;
	Rand(&i, sizeof(i));
	return i;
}

UINT Rand32() {
	UINT i;
	Rand(&i, sizeof(i));
	return i;
}

USHORT Rand16() {
	USHORT i;
	Rand(&i, sizeof(i));
	return i;
}

UCHAR Rand8() {
	UCHAR i;
	Rand(&i, sizeof(i));
	return i;
}

bool Rand1() {
	return (Rand32() % 2) == 0 ? false : true;
}

void Rand(void *buf, UINT size) {
	if (buf == NULL || size == 0) {
		return;
	}

	// The system-preferred generator needs no provider handle; it fails only on bad arguments.
	// Bytes that may not be random are never returned: the process stops instead.
	if (CNG_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) == false) {
		AbortExitEx("Rand(): BCryptGenRandom() failed");
	}
}
