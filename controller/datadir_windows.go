//go:build windows

package controllercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The owner of the data directory (AUD1-DT-10, #458; ST-3 of docs/threat-model.md). C:\ProgramData lets
// every user make a folder, so a local user can make C:\ProgramData\Ranz\controller before the install, or put
// one in its place, and whoever owns a folder can change its access list and put files in it: the
// rqlited.exe that the service starts from it, and a store that holds a token that the user knows. So the data
// directory is the property of SYSTEM, the Administrators or the service's account. The install makes it
// with the Administrators as its owner, as NodeMakeDataDir does for the Node, and takes over one that
// exists only when one of them, or the administrator who runs the install, owns it. The service, and the
// commands that run on its host (reset-admin, backup and restore), refuse a data directory that any other
// account owns.

// installDataDirSDDL is dataDirSDDL with the Administrators as its owner, as NODE_DATA_DIR_SDDL of
// src/Cedar/Node.c is.
const installDataDirSDDL = "O:BA" + dataDirSDDL

// dataDirOwner returns the owner of the data directory dir. It refuses a link, a junction or a symbolic
// link, which whoever made it points anywhere, and what is no directory: the folder itself must be the
// data directory.
func dataDirOwner(dir string) (*windows.SID, error) {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return nil, fmt.Errorf("the data directory %s is a link (a junction or a symbolic link), which the controller does not follow: name the folder itself with -data", dir)
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return nil, fmt.Errorf("the data directory %s is not a directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("the owner of the data directory %s: %w", dir, err)
	}
	if sd == nil {
		// A volume with no access lists, such as a FAT drive, has none to protect the directory with
		return nil, fmt.Errorf("the data directory %s has no security descriptor: its volume has no access lists", dir)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, fmt.Errorf("the owner of the data directory %s: %w", dir, err)
	}
	if owner == nil {
		return nil, fmt.Errorf("the data directory %s has no owner", dir)
	}
	return owner, nil
}

// ownerIsTrusted reports whether owner may own a data directory: SYSTEM, the Administrators, the account
// of the service (the SID that Windows derives from its name, so that an administrator's command accepts
// a directory that the service made), or the account that runs this process.
func ownerIsTrusted(owner *windows.SID) (bool, error) {
	trusted := make([]*windows.SID, 0, 4)
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return false, fmt.Errorf("a well-known SID: %w", err)
		}
		trusted = append(trusted, sid)
	}
	service, err := windows.StringToSid(serviceSID)
	if err != nil {
		return false, fmt.Errorf("the SID of the service: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("the account of this process: %w", err)
	}
	trusted = append(trusted, service, user.User.Sid)
	for _, sid := range trusted {
		if owner.Equals(sid) {
			return true, nil
		}
	}
	return false, nil
}

// accountName returns the name of the account of sid as Windows knows it, or the SID as text.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// checkDataDirOwner refuses the data directory dir, which exists, when an account other than SYSTEM, the
// Administrators, the service's account or the one that runs this process owns it, and when it is a link.
// The service does not start in such a directory, and reset-admin, backup and restore do not run the
// rqlited of its payload folder as an administrator.
func checkDataDirOwner(dir string) error {
	owner, err := dataDirOwner(dir)
	if err != nil {
		return err
	}
	trusted, err := ownerIsTrusted(owner)
	if err != nil {
		return err
	}
	if !trusted {
		return fmt.Errorf("the data directory %s is owned by %s, and only SYSTEM, the Administrators and %s may own it: another account may have made it before the install, and what it holds would run as the controller. "+
			`Look at what it holds, then remove it, or, when you made it yourself, give it to the Administrators (takeown /F "%s" /A /R /D Y) and start again`, dir, accountName(owner), serviceAccount, dir)
	}
	return nil
}

// ownDataDir makes the Administrators the owner of the data directory dir and gives it the protected
// access list of dataDirSDDL, which the files and folders in it inherit.
func ownDataDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(installDataDirSDDL)
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("the owner and the access list of the data directory %s: %w", dir, err)
	}
	return nil
}

// makeOwnedDataDir makes the data directory dir, which is not there, and gives it to the Administrators.
// The last folder is made with Mkdir, which fails when the name was taken meanwhile, so that a directory
// that somebody else made in that moment is never taken for the one that this call made.
func makeOwnedDataDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return ownDataDir(dir)
}

// takeOverDataDir makes the data directory dir for the install, with the Administrators as its owner and
// the protected access list of dataDirSDDL, or takes over the one that exists:
//
//   - A directory that SYSTEM, the Administrators, the service's account or the account that runs the
//     install owns, a directory of an earlier install or one that an administrator made, is kept with what
//     it holds, and its owner and its access list are set.
//   - A directory that another account owns is not kept: it may hold anything, a store with a token that
//     the user knows or an rqlited.exe of its own, and the account that made it may hold it open, and so
//     keep a way to write into it after the access list changed. It is taken over by making it again:
//     an empty one is removed, which fails while anybody holds it open, and made anew. One that holds
//     anything, one that is a link, and one that cannot be read or removed is refused, with a message that
//     says what to do.
func takeOverDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return makeOwnedDataDir(dir)
	} else if err != nil {
		return err
	}
	owner, err := dataDirOwner(dir)
	if err != nil {
		return err
	}
	trusted, err := ownerIsTrusted(owner)
	if err != nil {
		return err
	}
	if trusted {
		return ownDataDir(dir)
	}
	if err := removeForeignDataDir(dir, owner); err != nil {
		return err
	}
	return makeOwnedDataDir(dir)
}

// removeForeignDataDir removes the data directory dir, which the account owner owns, when it is empty,
// and refuses it otherwise.
func removeForeignDataDir(dir string, owner *windows.SID) error {
	refuse := func(why string) error {
		return fmt.Errorf("the data directory %s is owned by %s, so the install did not take it over: %s. A user may have made it before the install, and what it holds would run as the controller. "+
			`Look at what it holds, then remove it, or give it to the Administrators (takeown /F "%s" /A /R /D Y), and run the install again`, dir, accountName(owner), why, dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return refuse("it could not be read (" + err.Error() + ")")
	}
	if len(entries) > 0 {
		return refuse("it is not empty")
	}
	if err := os.Remove(dir); err != nil {
		return refuse("it could not be removed, and somebody may hold it open (" + err.Error() + ")")
	}
	return nil
}
