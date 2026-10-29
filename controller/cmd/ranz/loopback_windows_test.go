//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The fingerprint file on Windows (AUD1-DT-14, #496): ranz trusts it only when no other account than SYSTEM, the
// Administrators and the account of the Controller service can have written it. The tests give a folder and its file
// the owner and the access list that a case needs, as an administrator of the host would, which takes an elevated
// Administrator, as the runner is.

// trustedFolder is the security of a folder whose fingerprint file ranz trusts, as the install leaves the data
// directory of the Controller: the Administrators own it, and its protected access list, which its file takes, is for
// SYSTEM and the Administrators.
const trustedFolder = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// requireAdministrator skips a test that needs an elevated Administrator, who may make the Administrators the owner of
// a file, and fails it on a runner of GitHub Actions, which is one: a skip there would pass a job that proved nothing.
func requireAdministrator(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal("this test needs an elevated Administrator, which a runner is")
	}
	t.Skip("this test needs an elevated Administrator")
}

// setSecurity gives path the owner of the SDDL text sddl, and its access list, protected, when it has one. An elevated
// Administrator may make the Administrators or its own account the owner without a privilege, and Windows gives the
// entries of a folder's list that its files take to the files in it.
func setSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("the security %s: %v", sddl, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION)
	dacl, _, err := sd.DACL()
	if err == nil {
		info |= windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		t.Fatalf("giving %s the security %s: %v", path, sddl, err)
	}
}

// trustFingerprint gives the folder dir and the fingerprint file in it the security that the install gives the data
// directory of the Controller, so that ranz trusts the file.
func trustFingerprint(t *testing.T, dir string) {
	t.Helper()
	requireAdministrator(t)
	setSecurity(t, dir, trustedFolder)
	setSecurity(t, filepath.Join(dir, servercert.FingerprintFile), "O:BA")
}

// TestRanzRefusesAFingerprintFileThatAnotherAccountMayHaveWritten is the first two criteria of AUD1-DT-14 (#496)
// through ranz. The fingerprint file holds the fingerprint of the very listener that answers, and ranz still refuses
// it when its folder lets the Users group add files, as the folders that a user makes in C:\ProgramData do, and when
// the file is owned by an account that is none of SYSTEM, the Administrators and the account of the Controller
// service: here the account that runs ranz, which a program of the same user that is not elevated leaves as the
// owner of what it writes. ranz then connects to nothing, sends no token, names the folder or the file and says why,
// and asks for -tls-fingerprint. The same file is taken once the folder and the file have the security of the install
// again.
func TestRanzRefusesAFingerprintFileThatAnotherAccountMayHaveWritten(t *testing.T) {
	requireAdministrator(t)
	ctx := context.Background()
	right, rightFP := answerer(t)
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte("ranz_ADMINSECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, servercert.FingerprintFile)
	if err := servercert.WriteFingerprint(dir, rightFP); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// whoami calls the listener with the data directory dir, and no fingerprint on the command line
	whoami := func() (string, error) {
		t.Helper()
		c, err := newClient(right.srv.URL, tokenFile, "", "", dir)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = do(ctx, c, []string{"whoami"}, &out)
		return out.String(), err
	}

	for _, c := range []struct {
		name, folder, file string
		says               string // what the refusal says of the folder or of the file
	}{
		// 0x116: add a file and a folder, write the attributes and the extended attributes, which C:\ProgramData gives the
		// Users group on the folders made in it
		{"a folder that the Users group may add files to", trustedFolder + "(A;;0x116;;;BU)", "O:BA", dir + ` may be written by BUILTIN\Users`},
		{"a file of the account that runs ranz", trustedFolder, "O:" + user.User.Sid.String(), file + " is owned by "},
	} {
		setSecurity(t, dir, c.folder)
		setSecurity(t, file, c.file)
		_, err := whoami()
		refusal := loopbackRefusal(err)
		var refused *unchecked
		var untrusted *controllercmd.UntrustedError
		if !errors.As(refusal, &refused) || !errors.As(err, &untrusted) {
			t.Errorf("%s: %v, want the refusal of a fingerprint file that another account may have written", c.name, err)
			continue
		}
		for _, want := range []string{"sends no token", right.srv.URL, "does not trust that file", c.says, "-tls-fingerprint"} {
			if !strings.Contains(refusal.Error(), want) {
				t.Errorf("%s: the refusal %q does not say %q", c.name, refusal, want)
			}
		}
		if conns, auth := right.seen(); conns != 0 || len(auth) != 0 {
			t.Errorf("%s: the listener got %d connections and %d requests, want none: ranz must not connect when it does not trust the file", c.name, conns, len(auth))
		}
	}

	// The same file with the security of the install is taken, and the token goes with the call
	trustFingerprint(t, dir)
	if out, err := whoami(); err != nil || !strings.Contains(out, `"name": "admin"`) {
		t.Fatalf("the fingerprint file of a folder of the Administrators gave %q, %v, want the answer of the listener", out, err)
	}
	if conns, auth := right.seen(); conns != 1 || len(auth) != 1 || auth[0] != "Bearer ranz_ADMINSECRET" {
		t.Errorf("the listener got %d connections and the headers %q, want one call with the token", conns, auth)
	}
}
