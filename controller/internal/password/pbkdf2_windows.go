//go:build windows && (amd64 || arm64)

package password

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procDeriveKeyPBKDF2 is BCryptDeriveKeyPBKDF2 of bcrypt.dll in System32.
var procDeriveKeyPBKDF2 = windows.NewLazySystemDLL("bcrypt.dll").NewProc("BCryptDeriveKeyPBKDF2")

// hmacSHA256 is BCRYPT_HMAC_SHA256_ALG_HANDLE of bcrypt.h: the pseudo handle of the HMAC-SHA-256
// algorithm that Windows 10 and Windows Server 2016 and later give, so there is no provider to open
// and to close. The Configuration store of a Node derives with it too (CsPbkdf2 of ConfigStore.c).
const hmacSHA256 = 0xb1

// derive returns size bytes of PBKDF2-HMAC-SHA256 of secret and salt with iterations iterations, made
// by CNG. The secret and the salt are not empty. The iteration count is a ULONGLONG of the API, which
// a uintptr holds on the two architectures of this build.
func derive(secret string, salt []byte, iterations, size int) ([]byte, error) {
	if secret == "" || len(salt) == 0 || iterations < 1 || size < 1 {
		return nil, errors.New("password: a derivation needs a password, a salt, an iteration count and a size")
	}
	pw := []byte(secret)
	key := make([]byte, size)
	r, _, _ := procDeriveKeyPBKDF2.Call(hmacSHA256,
		uintptr(unsafe.Pointer(&pw[0])), uintptr(len(pw)),
		uintptr(unsafe.Pointer(&salt[0])), uintptr(len(salt)),
		uintptr(iterations),
		uintptr(unsafe.Pointer(&key[0])), uintptr(size), 0)
	if status := uint32(r); status != 0 {
		return nil, fmt.Errorf("password: BCryptDeriveKeyPBKDF2: %w", windows.NTStatus(status))
	}
	return key, nil
}
