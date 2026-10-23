//go:build windows

package payload

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// guid is a Win32 GUID: here, WINTRUST_ACTION_GENERIC_VERIFY_V2 (wintrust.h), the action that
// checks a file's Authenticode signature.
type guid struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

var actionGenericVerifyV2 = guid{0xaac56b, 0xcd44, 0x11d0, [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

// wintrustFileInfo is WINTRUST_FILE_INFO (wintrust.h): the file to check, named by its path since
// hFile and pgKnownSubject are not used here.
type wintrustFileInfo struct {
	cbStruct     uint32
	filePath     *uint16
	hFile        windows.Handle
	knownSubject uintptr
}

// wintrustData is WINTRUST_DATA (wintrust.h): the one check this file runs, a WTD_CHOICE_FILE
// verify with no UI and no revocation check (dwProvFlags below keeps it offline), in the field
// order and the natural alignment the struct has in the Windows SDK, so WinVerifyTrust reads it
// correctly.
type wintrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	// file is the union of pFile/pCatalog/pBlob/pSgnr/pCert; only pFile is used. It is
	// unsafe.Pointer, not uintptr, so the garbage collector keeps tracking *wintrustFileInfo
	// through it: a uintptr here would let the collector move or free that struct out from under
	// WinVerifyTrust (the unsafe package's uintptr rule is for a Pointer converted in the call
	// expression itself, not for one kept in a field read later).
	file              unsafe.Pointer
	stateAction       uint32
	wvtStateData      windows.Handle
	urlReference      *uint16
	provFlags         uint32
	uiContext         uint32
	signatureSettings uintptr
}

// The WTD_* and TRUST_E_* values of wintrust.h this file uses, named as the Windows SDK names
// them.
const (
	wtdUINone                = 2      // WTD_UI_NONE: no user interface
	wtdRevokeNone            = 0      // WTD_REVOKE_NONE
	wtdChoiceFile            = 1      // WTD_CHOICE_FILE
	wtdStateActionVerify     = 1      // WTD_STATEACTION_VERIFY
	wtdStateActionClose      = 2      // WTD_STATEACTION_CLOSE
	wtdCacheOnlyURLRetrieval = 0x1000 // WTD_CACHE_ONLY_URL_RETRIEVAL: never fetch a revocation list over the network

	trustOK          = 0          // S_OK: the signature verifies and chains to a trusted root
	trustNoSignature = 0x800B0100 // TRUST_E_NOSIGNATURE
)

var (
	wintrust           = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
)

// verifyAuthenticode is MsVerifyAuthenticode (src/Mayaqua/Microsoft.c), the self-integrity check's
// own Authenticode verdict, run here on a payload before it is installed: no UI, no revocation
// check fetched over the network, cache only. A missing signature (TRUST_E_NOSIGNATURE) is
// refused here, unlike the self-integrity check's own development-build allowance, because a
// payload that ranz install writes out must carry a signature that verifies; the CI self-signed
// certificate counts once it is trusted on the machine that runs the check.
func verifyAuthenticode(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("the Authenticode check: %w", err)
	}
	file := wintrustFileInfo{
		cbStruct: uint32(unsafe.Sizeof(wintrustFileInfo{})),
		filePath: p,
	}
	data := wintrustData{
		cbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: wtdRevokeNone,
		unionChoice:      wtdChoiceFile,
		file:             unsafe.Pointer(&file),
		stateAction:      wtdStateActionVerify,
		provFlags:        wtdCacheOnlyURLRetrieval,
	}
	action := actionGenericVerifyV2
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))

	// Release the state the verify allocated, whatever the result (MsVerifyAuthenticode does the
	// same two-call verify-then-close)
	data.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))

	switch code := uint32(r); code {
	case trustOK:
		return nil
	case trustNoSignature:
		return errors.New("it carries no Authenticode signature")
	default:
		return fmt.Errorf("its Authenticode signature does not verify (WinVerifyTrust %#08x)", code)
	}
}
