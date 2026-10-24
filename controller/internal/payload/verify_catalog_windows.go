//go:build windows

package payload

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wintrustCatalogInfo is WINTRUST_CATALOG_INFO (wintrust.h): one file as a member of a signed
// catalog, in the field order and the natural alignment the struct has in the Windows SDK.
type wintrustCatalogInfo struct {
	cbStruct             uint32
	catalogVersion       uint32
	catalogFilePath      *uint16
	memberTag            *uint16
	memberFilePath       *uint16
	memberFile           windows.Handle
	calculatedFileHash   *byte
	cbCalculatedFileHash uint32
	catalogContext       uintptr
	catAdmin             uintptr
}

// The WTD_* value of wintrust.h this file adds to the ones of verify_windows.go, and the hash that
// the catalogs of Windows drivers carry for the files of a package.
const (
	wtdChoiceCatalog = 2        // WTD_CHOICE_CATALOG
	catalogHash      = "SHA256" // BCRYPT_SHA256_ALGORITHM
)

// The catalog functions of wintrust.dll: the catalog admin context hashes a file as a catalog
// records it.
var (
	procCryptCATAdminAcquireContext2         = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHandle2 = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminReleaseContext          = wintrust.NewProc("CryptCATAdminReleaseContext")
)

// verifyCatalogMember checks that the file at path is a member of the signed catalog at catalog, as
// Windows does when it installs a driver package (signtool verify /c): the file is hashed, the hash
// is looked up in the catalog, and the signature of the catalog must verify and chain to a trusted
// root. It is how a file of a driver package is trusted when the signature that it carries itself
// is not one that Windows trusts. No UI, and no revocation list fetched over the network, as
// verifyAuthenticode runs.
func verifyCatalogMember(catalog, path string) error {
	code, err := catalogVerdict(catalog, path, catalogHash)
	if err != nil {
		return err
	}
	return catalogError(code)
}

// catalogVerdict is the code that WinVerifyTrust gives for the file at path as a member of the
// catalog at catalog, hashed with alg (the name of a CNG hash algorithm). A call that fails before
// WinVerifyTrust is reached is the error.
func catalogVerdict(catalog, path, alg string) (uint32, error) {
	catalogPtr, err := windows.UTF16PtrFromString(catalog)
	if err != nil {
		return 0, fmt.Errorf("the catalog check: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("the catalog check: %w", err)
	}
	algPtr, err := windows.UTF16PtrFromString(alg)
	if err != nil {
		return 0, fmt.Errorf("the catalog check: %w", err)
	}

	var admin uintptr
	if r, _, callErr := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algPtr)), 0, 0); r == 0 {
		return 0, fmt.Errorf("the catalog check (CryptCATAdminAcquireContext2): %w", callErr)
	}
	defer procCryptCATAdminReleaseContext.Call(admin, 0)

	file, err := windows.CreateFile(pathPtr, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, fmt.Errorf("the catalog check: opening the file: %w", err)
	}
	defer windows.CloseHandle(file)

	hash := make([]byte, 64)
	size := uint32(len(hash))
	if r, _, callErr := procCryptCATAdminCalcHashFromFileHandle2.Call(admin, uintptr(file), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
		return 0, fmt.Errorf("the catalog check (CryptCATAdminCalcHashFromFileHandle2): %w", callErr)
	}
	hash = hash[:size]
	tag, err := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	if err != nil {
		return 0, fmt.Errorf("the catalog check: %w", err)
	}

	member := wintrustCatalogInfo{
		cbStruct:             uint32(unsafe.Sizeof(wintrustCatalogInfo{})),
		catalogFilePath:      catalogPtr,
		memberTag:            tag,
		memberFilePath:       pathPtr,
		memberFile:           file,
		calculatedFileHash:   &hash[0],
		cbCalculatedFileHash: size,
		catAdmin:             admin,
	}
	data := wintrustData{
		cbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceCatalog,
		file:             unsafe.Pointer(&member),
		stateAction:      wtdStateActionVerify,
		provFlags:        wtdCacheOnlyURLRetrieval,
	}
	action := actionGenericVerifyV2
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))

	// Release the state the verify allocated, whatever the result
	data.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))

	return uint32(r), nil
}

// catalogError is the verdict of WinVerifyTrust on a catalog member, code, as an error, nil for a
// file that is a member of a catalog whose signature verifies.
func catalogError(code uint32) error {
	switch code {
	case trustOK:
		return nil
	case certUntrustedRoot:
		return fmt.Errorf("the signature of its catalog does not verify: the certificate does not chain to a trusted root (WinVerifyTrust %#08x)", code)
	default:
		return fmt.Errorf("it is not a member of the signed catalog of its package (WinVerifyTrust %#08x)", code)
	}
}
