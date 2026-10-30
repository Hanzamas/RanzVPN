//go:build windows

package controllercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"unsafe"

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
//
// The folder is made with its owner and its access list in the call that makes it (AUD1-DT-18, #503;
// makeProtectedDir), so that it never has the list of C:\ProgramData, which lets the Users group add files and
// folders, not even for a moment: a user that polls for the folder would open it with the right to add to it in
// that moment, the handle would keep the right after the list changed, and the user could make payload\ in it,
// which the list that the install passes down keeps open to its owner. And a folder that is kept is looked at
// down to its last file before the install changes it (checkDataDirChildren), since the same user could have
// made payload\ in it while it had that list.
//
// Two things are not closed, and #554 (AUD1-DT-18-R1) is for both; ST-3 of docs/threat-model.md says so. The new
// folder is changed by name after the call that makes it, so a user that owns the folder above it can put a folder
// of its own in its place in that moment (makeProtectedDir). And the look at a kept folder does not see a hard link,
// which can name a file outside the folder that the list of the install then reaches (checkDataDirChildren).

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

// dataDirTrustees returns the accounts that may own a data directory and what it holds: SYSTEM, the
// Administrators, the account of the service (the SID that Windows derives from its name, so that an
// administrator's command accepts a directory that the service made), and the account that runs this process.
func dataDirTrustees() ([]*windows.SID, error) {
	trusted := make([]*windows.SID, 0, 4)
	for _, kind := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return nil, fmt.Errorf("a well-known SID: %w", err)
		}
		trusted = append(trusted, sid)
	}
	service, err := windows.StringToSid(serviceSID)
	if err != nil {
		return nil, fmt.Errorf("the SID of the service: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("the account of this process: %w", err)
	}
	return append(trusted, service, user.User.Sid), nil
}

// ownerIsTrusted reports whether owner may own a data directory (dataDirTrustees).
func ownerIsTrusted(owner *windows.SID) (bool, error) {
	trusted, err := dataDirTrustees()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(trusted, owner.Equals), nil
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

// setDataDirSecurity sets the security that the text sddl gives to the folder dir, which is there: its protected
// access list and, when the text names one, its owner. SetNamedSecurityInfo passes the list down to what the folder
// holds, as an access list that is set on a folder with files in it must.
func setDataDirSecurity(dir, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
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
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("the owner and the access list of the data directory %s: %w", dir, err)
	}
	return nil
}

// ownDataDir makes the Administrators the owner of the data directory dir and gives it the protected
// access list of dataDirSDDL, which the files and folders in it inherit.
func ownDataDir(dir string) error {
	return setDataDirSecurity(dir, installDataDirSDDL)
}

// makeProtectedDir makes the folder dir, which is not there, with the security that sddl gives it, its owner
// when the text names one and its access list, in the call that makes the folder: CreateDirectory takes the
// security descriptor with the name. The folder never has the access list of its parent, which on
// C:\ProgramData lets the Users group add files and folders, so no handle that has the right to add to it can
// be opened before its own list is there, and a handle that is opened after is judged by that list (AUD1-DT-18,
// #503). A call that made the folder and set the list after, as os.Mkdir and ownDataDir did, leaves that gap.
// The path is cleaned first, so that no caller passes it as it was typed (createDataDir says why). A volume that
// keeps no access lists, such as a FAT drive, takes the folder and ignores the descriptor: the folder is removed
// again, and the error says so.
//
// The call fails when the name is taken when it runs, so a folder that exists is never taken for the one that this
// call made. It does not hold the new folder afterwards: the steps below read its owner and set its list by name, and
// whatever is at the name then gets them. A user that owns the folder above (a C:\ProgramData\Ranz that it made first)
// may delete the children of that folder, so it can rename the new folder away in that moment and put a folder of its
// own in its place, with payload\ inside and a handle held. The install then gives that folder to the Administrators,
// and the user keeps payload\ and what is in it. The start of the service, which makes a missing folder the same way,
// does not look at the owner of what it finds there either (dataDirOwner drops the owner that it reads), and only the
// next start refuses a folder of another owner (checkDataDirOwner). The install before AUD1-DT-18, a Mkdir and then
// ownDataDir, had the same gap. Setting the owner and the list through the handle that made the folder closes it:
// that is #554 (AUD1-DT-18-R1), and this change does not do it. ST-3 of docs/threat-model.md says so. It is reasoned,
// not tested: a test has to swap the folder between the two steps, which #554 adds.
//
// CreateDirectory gives the folder its list as a protected list and no more: the flag of a list that passes a change
// down to what the folder holds (auto-inherited, AI in the text of a descriptor) is not set, whatever the descriptor says,
// and a file that is made in the folder has a list without it too. When SetNamedSecurityInfo then gives such a file an
// owner, it turns the entries that the file inherited into entries of its own and protects its list, so a later change of
// the list of the folder no longer reaches the file (measured on the hosted runners, x64 and arm64, run 41066865697 of the
// throwaway workflow exp-datadir-sd.yml of #503). So the same list is set once more with SetNamedSecurityInfo, as the
// install sets it over a folder that is kept: the folder gets the flag, and its files take the list the way that the
// files of a folder of before did. The folder has its list at every moment, so this gives no handle a right that it did
// not have.
func makeProtectedDir(dir, sddl string) error {
	dir = filepath.Clean(dir)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	if _, err := dataDirOwner(dir); err != nil {
		_ = os.Remove(dir)
		return err
	}
	if err := setDataDirSecurity(dir, sddl); err != nil {
		_ = os.Remove(dir)
		return err
	}
	return nil
}

// makeOwnedDataDir makes the data directory dir, which is not there, with the Administrators as its owner and
// the protected access list of dataDirSDDL from the moment it exists (makeProtectedDir). The path is cleaned
// first, as createDataDir says.
func makeOwnedDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	return makeProtectedDir(dir, installDataDirSDDL)
}

// createDataDir makes the data directory dir, which is not there, for the start of the service and of a
// Controller that an administrator starts by hand: with the protected access list of dataDirSDDL from the
// moment it exists, and the account that makes it as its owner, since the account of the service cannot give
// the folder to the Administrators. The service makes it only when the install did not, or when it was removed.
//
// The path is cleaned first, since -data is kept as it was typed (`ranz controller install -data D:\RanzData\`
// registers the service with that text), and filepath.Dir of a path that ends in a separator is the folder itself:
// the step that makes the folder above it would make the data directory, with the access list of its own folder,
// and the call that makes it with its own list would then fail because the name was taken. The start would fail
// once, and the next start would keep the folder with that list, which its owner makes trusted (finding A of the
// read-only review of PR 541; TestNewDataDirWithATrailingSeparatorIsMadeWithItsOwnList).
func createDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	return makeProtectedDir(dir, dataDirSDDL)
}

// takeOverDataDir makes the data directory dir for the install, with the Administrators as its owner and
// the protected access list of dataDirSDDL, or takes over the one that exists:
//
//   - A directory that SYSTEM, the Administrators, the service's account or the account that runs the
//     install owns, a directory of an earlier install or one that an administrator made, is kept with what
//     it holds, and its owner and its access list are set, when what it holds is theirs too. A file or a
//     folder in it, at any depth, that another account owns, and a junction or a symbolic link, are refused
//     before anything is changed (checkDataDirChildren): a user made it while the folder had an access list
//     that let the Users group add to it, its owner has full control of it through the entry for OWNER RIGHTS
//     that the install passes down, and what it holds would run as the controller. It is not given to the
//     Administrators either, since a handle that its owner opened before the list changed still writes
//     after: the administrator looks at it, and removes it or gives it away. The look has two limits, and
//     both are open: it does not see a hard link, and it does not see a file that a user adds between the
//     look and the change of the list, which a folder that an administrator made by hand allows, since it
//     has the list that it inherits, and on C:\ProgramData that lets the Users group add files and folders.
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
		if err := checkDataDirChildren(dir); err != nil {
			return err
		}
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

// checkDataDirChildren refuses the data directory dir, whose owner is trusted, when a file or a folder in it, at
// any depth, is owned by an account that is not (dataDirTrustees), is a link (a junction or a symbolic link),
// or cannot be looked at (AUD1-DT-18, #503). A trusted owner of the folder says nothing of what is in it: a user
// that made payload\ while the folder had the list of C:\ProgramData owns it still, and the entry for OWNER RIGHTS
// that the install passes down gives that owner full control of it, so the user could swap the rqlited.exe that
// the service starts. A junction and a symbolic link are not followed, and the install does not pass its list
// down through one: the Controller makes none, and what a link points at is not the data directory. Nothing is
// changed: the check reads the owners and the attributes only, and runs before the owner and the list are set.
//
// What the look does not see is open, and #554 (AUD1-DT-18-R1) is for the first of the two; ST-3 of
// docs/threat-model.md says so:
//
//   - A hard link. It is one more name of a file, and the file has an owner, so a hard link to a file elsewhere on
//     the volume that SYSTEM or the Administrators own, which a user that may add files here could plant when it may
//     write that file, passes the look, and the list that ownDataDir passes down is then written to that file.
//   - A file that a user adds after the look and before the list is set. A folder that ranz made has a protected
//     list, which gives the Users group nothing, but a folder that an administrator made by hand in
//     C:\ProgramData\Ranz has the list that it inherits there, which lets the Users group add files and folders.
func checkDataDirChildren(dir string) error {
	trusted, err := dataDirTrustees()
	if err != nil {
		return err
	}
	return checkChildren(dir, dir, trusted)
}

// checkChildren checks what the folder holds, one after the other in the order of their names and the folders
// down to their last file, for the data directory dir that the folder is in or is.
func checkChildren(dir, folder string, trusted []*windows.SID) error {
	entries, err := os.ReadDir(folder)
	if err != nil {
		return refuseChild(dir, folder, "could not be read ("+err.Error()+")")
	}
	for _, entry := range entries {
		path := filepath.Join(folder, entry.Name())
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return refuseChild(dir, path, "could not be looked at ("+err.Error()+")")
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil {
			return refuseChild(dir, path, "could not be looked at ("+err.Error()+")")
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return refuseChild(dir, path, "is a link (a junction or a symbolic link), which the install does not follow")
		}
		owner, err := ownerOf(path)
		if err != nil {
			return refuseChild(dir, path, "has an owner that could not be read ("+err.Error()+")")
		}
		if !slices.ContainsFunc(trusted, owner.Equals) {
			return refuseChild(dir, path, "is owned by "+accountName(owner)+", and only SYSTEM, the Administrators, "+serviceAccount+" and the account that runs the install may own what a data directory holds")
		}
		if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			if err := checkChildren(dir, path, trusted); err != nil {
				return err
			}
		}
	}
	return nil
}

// ownerOf returns the owner of the file or folder path, which is not a link.
func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	if sd == nil {
		return nil, errors.New("it has no security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return nil, errors.New("it has no owner")
	}
	return owner, nil
}

// refuseChild is the refusal of the kept data directory dir, because of the file or folder path in it, which why
// says what is wrong with.
func refuseChild(dir, path, why string) error {
	return fmt.Errorf("the data directory %s is kept with what it holds, so the install did not take it over: %s %s. A user may have put it there before the install, and it would run as the controller. "+
		`Look at it, then remove it, or give the data directory and what it holds to the Administrators (takeown /F "%s" /A /R /D Y), and run the install again`, dir, path, why, dir)
}
