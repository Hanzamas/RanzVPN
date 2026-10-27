//go:build windows

package controllercmd

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The helpers of the Windows tests of the access lists and owners of the files of the Controller
// (AUD1-DT-10, #458): a thread that acts as a standard user, and the access list of a path as text.

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// disableMaxPrivilege is DISABLE_MAX_PRIVILEGE of CreateRestrictedToken: every privilege but
// SeChangeNotifyPrivilege is taken from the token, as the token of a standard user holds only that one.
const disableMaxPrivilege = 0x1

// requireAdministrator skips a test that needs the rights of an elevated Administrator, as the runner
// has. On a runner of GitHub Actions the test fails instead, since a skip there would pass a job that
// proved nothing.
func requireAdministrator(t *testing.T) {
	t.Helper()
	if err := adminRights(); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("this test needs an elevated Administrator, which a runner has: %v", err)
		}
		t.Skipf("this test needs an elevated Administrator: %v", err)
	}
}

// standardUserToken returns an impersonation token of the user of this process as a standard user would
// hold it: the token of the process with the Administrators group for deny only and no privilege but the
// bypass of the traverse check. What the Administrators group allows, it does not allow, and what the
// Users group allows, it does.
func standardUserToken(t *testing.T) windows.Token {
	t.Helper()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &process); err != nil {
		t.Fatalf("opening the token of the process: %v", err)
	}
	defer process.Close()
	deny := []windows.SIDAndAttributes{{Sid: admins}}
	var restricted windows.Token
	r, _, err := procCreateRestrictedToken.Call(uintptr(process), disableMaxPrivilege, uintptr(len(deny)), uintptr(unsafe.Pointer(&deny[0])),
		0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", err)
	}
	defer restricted.Close()
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatalf("DuplicateTokenEx: %v", err)
	}
	return impersonation
}

// asStandardUser runs fn on a thread that acts as a standard user (standardUserToken), so what fn opens,
// reads and writes is judged by the access lists as it would be for the account of a standard user. fn
// runs on a goroutine of its own and may not call t.Fatal or t.FailNow: it reports with t.Error.
func asStandardUser(t *testing.T, fn func()) {
	t.Helper()
	token := standardUserToken(t)
	defer token.Close()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			// The thread stays locked, and ends with the goroutine
			done <- fmt.Errorf("SetThreadToken: %w", err)
			return
		}
		fn()
		if err := windows.RevertToSelf(); err != nil {
			done <- fmt.Errorf("RevertToSelf: %w", err)
			return
		}
		runtime.UnlockOSThread()
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// setDACL replaces the access list of path with the one that sddl gives, protected, as the SDDL
// string of a DACL with the flag P.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("the access list %s: %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		t.Fatalf("setting the access list of %s to %s: %v", path, sddl, err)
	}
}

// securityOf returns the owner and the access list of path as an SDDL string: O:BAD:PAI(A;;FA;;;SY)...
func securityOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the access list of %s: %v", path, err)
	}
	return sd.String()
}
