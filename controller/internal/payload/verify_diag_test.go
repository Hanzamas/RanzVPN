//go:build windows

package payload

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Temporary (ONE-3, #312), removed with .github/workflows/diag-xdp-sign.yml: the verdict of WinVerifyTrust on the
// files of the pinned XDP runtime, for the settings of verifyAuthenticode and for the ones it does not use.
func winVerifyTrustWith(path string, revocation, provFlags uint32) uint32 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0xFFFFFFFF
	}
	file := wintrustFileInfo{cbStruct: uint32(unsafe.Sizeof(wintrustFileInfo{})), filePath: p}
	data := wintrustData{
		cbStruct:         uint32(unsafe.Sizeof(wintrustData{})),
		uiChoice:         wtdUINone,
		revocationChecks: revocation,
		unionChoice:      wtdChoiceFile,
		file:             unsafe.Pointer(&file),
		stateAction:      wtdStateActionVerify,
		provFlags:        provFlags,
	}
	action := actionGenericVerifyV2
	r, _, _ := procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	data.stateAction = wtdStateActionClose
	procWinVerifyTrust.Call(0, uintptr(unsafe.Pointer(&action)), uintptr(unsafe.Pointer(&data)))
	return uint32(r)
}

func TestDiagVerifyEachFile(t *testing.T) {
	dir := os.Getenv("DIAG_DIR")
	if dir == "" {
		t.Skip("DIAG_DIR names no folder")
	}
	for _, name := range []string{"xdp.sys", "xdpapi.dll", "xdp.cat"} {
		path := filepath.Join(dir, name)
		t.Logf("%s: verifyAuthenticode: %v", name, verifyAuthenticode(path))
		t.Logf("%s: no revocation check, cache only: %#08x", name, winVerifyTrustWith(path, wtdRevokeNone, wtdCacheOnlyURLRetrieval))
		t.Logf("%s: no revocation check, network allowed: %#08x", name, winVerifyTrustWith(path, wtdRevokeNone, 0))
		t.Logf("%s: whole chain revocation check, network allowed: %#08x", name, winVerifyTrustWith(path, 1, 0))
	}
}
