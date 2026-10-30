//go:build windows

package controllercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The fingerprint file that ranz trusts (AUD1-DT-14, #496; AP-2 of docs/threat-model.md): ReadFingerprint takes the
// file only when no other account than SYSTEM, the Administrators and the account of the service can have written
// it or its folder. checkWriters is tested on the security descriptors that SDDL texts make, which takes no right
// and no file. ReadFingerprint is tested on files, whose owner and access list an elevated Administrator sets, with
// the right to restore for an owner that no machine knows (giveTo).

// aFingerprint is a TLS fingerprint to write: the 64 hex digits of a SHA-256.
var aFingerprint = strings.Repeat("ab", 32)

// The SIDs of the accounts that may write a fingerprint file but the service, and of the Users group, which owns what a
// test hands to it.
const (
	systemSID = "S-1-5-18"
	adminsSID = "S-1-5-32-544"
	usersSID  = "S-1-5-32-545"
)

// wantUntrusted checks that err refuses path as a file that another account may have written, with a reason that
// holds each of says.
func wantUntrusted(t *testing.T, what string, err error, path string, says ...string) {
	t.Helper()
	var untrusted *UntrustedError
	if !errors.As(err, &untrusted) {
		t.Errorf("%s: %v, want the refusal of a file that another account may have written", what, err)
		return
	}
	if untrusted.Path != path {
		t.Errorf("%s: the refusal names %s, want %s", what, untrusted.Path, path)
	}
	for _, want := range says {
		if !strings.Contains(untrusted.Why, want) {
			t.Errorf("%s: the refusal says %q, not %q", what, untrusted.Why, want)
		}
	}
}

// The judgement of checkWriters on an owner and an access list, for each kind of entry. The accounts that may
// write are SYSTEM, the Administrators and the service, which owns the file that it writes; the entry for OWNER
// RIGHTS is for the owner, who is one of them by then. An entry that denies, one that only what is made in a folder
// takes and one with no right to write let nobody write, and any other account with a right to write is refused,
// whichever of the rights it is, with the account named.
func TestCheckWritersByTheOwnerAndTheAccessList(t *testing.T) {
	trusted, err := fingerprintTrustees()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	const (
		owned     = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
		usersCan  = owned + "(A;;%s;;;BU)"
		mayWrite  = `may be written by BUILTIN\Users`
		isOwnedBy = "is owned by "
		anyWriter = "may be written by "
	)
	cases := []struct {
		name, sddl, refusal string // refusal is what the reason says, empty for a file that is taken
	}{
		{"the access list that install makes, which its file takes", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FA;;;" + serviceSID + ")", ""},
		{"SYSTEM as the owner", "O:SYD:P(A;;FA;;;SY)", ""},
		{"the service as the owner of what it wrote", "O:" + serviceSID + "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + serviceSID + ")", ""},
		{"readers of every kind", owned + "(A;;FRFX;;;BU)(A;;FR;;;WD)(A;;FR;;;AU)", ""},
		{"an entry that denies the Users group", "O:BAD:P(D;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)", ""},
		{"an entry that only what is made in a folder takes", "O:BAD:P(A;OICIIO;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)", ""},

		{"the Users group as the owner", "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)", isOwnedBy + `BUILTIN\Users`},
		{"Everyone as the owner", "O:WDD:P(A;;FA;;;SY)(A;;FA;;;BA)", isOwnedBy},
		{"a standard user as the owner", "O:" + standardUserSID + "D:P(A;;FA;;;SY)(A;;FA;;;BA)", isOwnedBy + standardUserSID},
		{"no access list", "O:BA", "has no access list"},

		{"the Users group with the rights of a write", owned + "(A;;FW;;;BU)", mayWrite},
		{"a write to the file", fmt.Sprintf(usersCan, "0x2"), mayWrite},
		{"an append, which adds a folder to a folder", fmt.Sprintf(usersCan, "0x4"), mayWrite},
		{"a write to the extended attributes", fmt.Sprintf(usersCan, "0x10"), mayWrite},
		{"a delete of what a folder holds", fmt.Sprintf(usersCan, "0x40"), mayWrite},
		{"a write to the attributes", fmt.Sprintf(usersCan, "0x100"), mayWrite},
		{"a delete", fmt.Sprintf(usersCan, "SD"), mayWrite},
		{"a change of the access list", fmt.Sprintf(usersCan, "WD"), mayWrite},
		{"a change of the owner", fmt.Sprintf(usersCan, "WO"), mayWrite},
		{"the generic right to write", fmt.Sprintf(usersCan, "GW"), mayWrite},
		{"the generic right to everything", fmt.Sprintf(usersCan, "GA"), mayWrite},
		{"a read entry, and a write entry after it", fmt.Sprintf(usersCan, "0x1200a9") + "(A;;0x2;;;AU)", anyWriter},
		{"Everyone", owned + "(A;;FA;;;WD)", anyWriter},
		{"a standard user by its SID", owned + "(A;;FW;;;" + standardUserSID + ")", anyWriter + standardUserSID},
		{"CREATOR OWNER, which is no account of a file that exists", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;CO)", anyWriter},
		{"an entry that names an object, which ranz does not read", owned + "(OA;;0x2;bf967aba-0de6-11d0-a285-00aa00304900;;BU)", "of type 5"},
	}
	// The account that runs the test, unless it is one of the accounts that may write
	if !slices.ContainsFunc(trusted, user.User.Sid.Equals) {
		cases = append(cases, []struct{ name, sddl, refusal string }{
			{"the account of this process as the owner", "O:" + user.User.Sid.String() + "D:P(A;;FA;;;SY)(A;;FA;;;BA)", isOwnedBy},
			{"the account of this process", owned + "(A;;FA;;;" + user.User.Sid.String() + ")", anyWriter},
		}...)
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: the security %s: %v", c.name, c.sddl, err)
		}
		owner, _, err := sd.Owner()
		if err != nil {
			t.Fatalf("%s: the owner of %s: %v", c.name, c.sddl, err)
		}
		err = checkWriters(`C:\data\tls.fingerprint`, owner, sd, trusted)
		if c.refusal == "" {
			if err != nil {
				t.Errorf("%s: %v, want the file taken", c.name, err)
			}
			continue
		}
		wantUntrusted(t, c.name, err, `C:\data\tls.fingerprint`, c.refusal)
	}

	// An access list that is there and holds no entry lets nobody write, and a null one lets everybody: it is no list
	empty, err := windows.SecurityDescriptorFromString("O:BAD:P")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := empty.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkWriters(`C:\data`, owner, empty, trusted); err != nil {
		t.Errorf("an access list with no entry: %v, want it taken, since nobody may write", err)
	}
	null, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := null.SetOwner(owner, false); err != nil {
		t.Fatal(err)
	}
	if err := null.SetDACL(nil, true, false); err != nil {
		t.Fatal(err)
	}
	wantUntrusted(t, "a null access list", checkWriters(`C:\data`, owner, null, trusted), `C:\data`, "has no access list")
}

// fingerprintInstall makes a data directory as the install does, with the Administrators as its owner and the
// protected access list that its files inherit, writes the fingerprint file there as a process of this account does,
// and returns the folder and the file.
func fingerprintInstall(t *testing.T) (dir, file string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "Ranz", "controller")
	if err := takeOverDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := servercert.WriteFingerprint(dir, aFingerprint); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, servercert.FingerprintFile)
}

// wantTaken checks that ReadFingerprint takes the file of the folder dir.
func wantTaken(t *testing.T, what, dir string) {
	t.Helper()
	if got, err := ReadFingerprint(dir); err != nil || got != aFingerprint {
		t.Errorf("%s: %q, %v, want the fingerprint taken", what, got, err)
	}
}

// The file that the install and the service leave is taken, which is the third criterion of #496. The install makes
// the data directory for the Administrators, and the service writes the file as its own account, which is then its
// owner (here the owner is set, since a test cannot run as the virtual account); an Administrator or SYSTEM that
// wrote the file is as good, and what a reader of any kind may do changes nothing.
func TestReadFingerprintTakesTheFilesOfTheInstallAndTheService(t *testing.T) {
	requireAdministrator(t)
	dir, file := fingerprintInstall(t)
	for _, owner := range []struct{ name, sid string }{
		{"the service", serviceSID},
		{"the Administrators", adminsSID},
		{"SYSTEM", systemSID},
	} {
		giveTo(t, file, owner.sid)
		wantTaken(t, "a file that "+owner.name+" owns, in the folder of the install", dir)
	}

	// The same file once a reader of the Users group is in the access list of its folder, which the file takes
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	if got := securityOf(t, file); !hasTrustee(got, "BU") {
		t.Fatalf("the file has the security %s: it does not take the Users group from the folder, so this shows nothing", got)
	}
	wantTaken(t, "a folder and a file that the Users group may read", dir)
}

// The fingerprint file of a Controller that an administrator started by hand with a data directory of its own, as the
// tracers of CI do, is taken: what an elevated Administrator makes belongs to the Administrators, and the folder that
// the Controller made for itself has the protected access list of the data directory. A machine that makes the
// creator the owner instead leaves ranz asking for -tls-fingerprint, which is not what the test is for.
func TestReadFingerprintOfAControllerThatAnAdministratorStartedByHand(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := makeDataDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := servercert.WriteFingerprint(dir, aFingerprint); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, filepath.Join(dir, servercert.FingerprintFile)} {
		if got := securityOf(t, path); !strings.HasPrefix(got, "O:BA") {
			const why = "this machine does not make the Administrators the owner of what an elevated Administrator creates"
			if os.Getenv("GITHUB_ACTIONS") == "true" {
				t.Fatalf("%s, which a runner does: %s has the security %s", why, path, got)
			}
			t.Skipf("%s: %s has the security %s", why, path, got)
		}
	}
	wantTaken(t, "the data directory that a Controller made for itself", dir)
}

// ownedBy is what the reason of a refusal says of a file or a folder that the account with the SID sid owns, an account
// that no machine knows by name.
func ownedBy(sid string) string { return "is owned by " + sid }

// The first two criteria of #496. A folder that another account owns, one that the Users group may add files to and a
// file that another account owns or may write are refused, with the folder or the file named, whoever wrote the
// fingerprint in it. A link is refused as well.
func TestReadFingerprintRefusesWhatAnotherAccountMayHaveWritten(t *testing.T) {
	requireAdministrator(t)

	t.Run("a folder that a standard user made", func(t *testing.T) {
		// C:\ProgramData lets every user make a folder: the owner is the user, and the file in it, whoever owns it
		dir, file := fingerprintInstall(t)
		giveTo(t, dir, standardUserSID)
		giveTo(t, file, adminsSID)
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a folder of a standard user", err, dir, ownedBy(standardUserSID))
	})
	t.Run("a folder that the Users group may add files to", func(t *testing.T) {
		// 0x116: add a file and a folder, write the attributes and the extended attributes, which C:\ProgramData gives
		// the Users group on the folders made in it
		dir, file := fingerprintInstall(t)
		setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x116;;;BU)")
		giveTo(t, file, adminsSID)
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a folder that the Users group may write", err, dir, `may be written by BUILTIN\Users`)
		setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
		wantTaken(t, "the same folder with the access list of the install again", dir)
	})
	t.Run("a file that a standard user owns", func(t *testing.T) {
		dir, file := fingerprintInstall(t)
		giveTo(t, file, standardUserSID)
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a file of a standard user", err, file, ownedBy(standardUserSID))
		giveTo(t, file, serviceSID)
		wantTaken(t, "the same file owned by the service", dir)
	})
	t.Run("a file that the Users group owns", func(t *testing.T) {
		dir, file := fingerprintInstall(t)
		giveTo(t, file, usersSID)
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a file of the Users group", err, file, `is owned by BUILTIN\Users`)
	})
	t.Run("a file that a standard user may write", func(t *testing.T) {
		dir, file := fingerprintInstall(t)
		giveTo(t, file, adminsSID)
		setDACL(t, file, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;"+standardUserSID+")")
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a file that a standard user may write", err, file, "may be written by "+standardUserSID)
	})
	t.Run("a folder that is a junction", func(t *testing.T) {
		target, file := fingerprintInstall(t)
		giveTo(t, file, adminsSID)
		dir := filepath.Join(t.TempDir(), "controller")
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
			t.Fatalf("making a junction: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = os.Remove(dir) })
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a junction in place of the folder", err, dir, "is a link")
	})
	t.Run("a file that is a symbolic link", func(t *testing.T) {
		dir, file := fingerprintInstall(t)
		giveTo(t, file, adminsSID)
		moved := filepath.Join(dir, "moved.fingerprint")
		if err := os.Rename(file, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, file); err != nil {
			t.Skipf("this account cannot make a symbolic link: %v", err)
		}
		_, err := ReadFingerprint(dir)
		wantUntrusted(t, "a symbolic link in place of the file", err, file, "is a link")
	})
}

// A folder or a file that is not there is an error that says so and is no refusal of trust, and a file that holds no
// fingerprint says that: ranz asks for -tls-fingerprint in each case and connects to nothing, which is the fourth
// criterion of #496.
func TestReadFingerprintOfWhatIsNotThere(t *testing.T) {
	requireAdministrator(t)
	dir, file := fingerprintInstall(t)
	giveTo(t, file, serviceSID)
	wantTaken(t, "the file of the install", dir)

	var untrusted *UntrustedError
	gone := filepath.Join(dir, "none")
	got, err := ReadFingerprint(gone)
	if err == nil || got != "" || !errors.Is(err, fs.ErrNotExist) || errors.As(err, &untrusted) {
		t.Errorf("a folder that is not there gave %q, %v, want an error that says it is not there", got, err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	got, err = ReadFingerprint(dir)
	if err == nil || got != "" || !errors.Is(err, fs.ErrNotExist) || errors.As(err, &untrusted) {
		t.Errorf("a file that is not there gave %q, %v, want an error that says it is not there", got, err)
	}

	if err := os.WriteFile(file, []byte("not a fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveTo(t, file, serviceSID)
	got, err = ReadFingerprint(dir)
	if err == nil || got != "" || errors.As(err, &untrusted) || !strings.Contains(err.Error(), "no TLS fingerprint") || !strings.Contains(err.Error(), file) {
		t.Errorf("a file with no fingerprint gave %q, %v, want an error that names the file and says it holds none", got, err)
	}
}
