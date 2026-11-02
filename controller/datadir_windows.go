//go:build windows

package controllercmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
// A path whose last element ends in a period or a space is refused by every step that makes, takes over or looks at
// the data directory, and nothing is made (checkDataDirName): Windows takes those off the end of a path and
// filepath.Clean keeps them, so the folder above such a path is the data directory itself, and the step that makes the
// folder above it would make the data directory with the list of its own folder, as a trailing separator did.
//
// The install and the start of the service work on the folder through a handle, not by its name (AUD1-DT-18-R1, #554). The
// call that makes a new folder opens it, and the install opens a kept folder as itself, without following a link, before it
// looks at it. The owner and the list are set through that handle, so they go to the folder that was made or looked at, and
// to no folder or link that a user that may change the folder above it puts in its place in the meantime; and the data
// directory is refused when its name no longer names that folder afterwards. The look opens each file and folder once, by
// its exact name in its folder and as itself, and reads its attributes, its number of names, its owner and what a folder
// holds through that one handle. It looks again once the list is set. What is still open is in checkDataDirChildren and in
// ST-3.

// installDataDirSDDL is dataDirSDDL with the Administrators as its owner, as NODE_DATA_DIR_SDDL of
// src/Cedar/Node.c is.
const installDataDirSDDL = "O:BA" + dataDirSDDL

// The rights of the handles of the data directory (AUD1-DT-18-R1, #554). lookRights are those that the look reads a file or a
// folder through: its attributes and its number of names (FILE_READ_ATTRIBUTES), its owner (READ_CONTROL) and what a folder
// holds (FILE_LIST_DIRECTORY, which is the right to read the data of a file). setRights are those of the handle of the data
// directory itself, which its owner and its list are set through too, and newFolderRights those of the handle of the call that
// makes a new folder, which also removes the folder again when it is not used.
const (
	lookRights      = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE
	setRights       = lookRights | windows.FILE_TRAVERSE | windows.WRITE_DAC | windows.WRITE_OWNER
	newFolderRights = setRights | windows.DELETE
)

// shareAll lets every other handle of a file or a folder read it, write it, rename it and delete it while a handle of the
// data directory holds it: such a handle takes nothing from another program, and it holds the file or the folder that it
// opened wherever a rename takes it.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// The calls that the tests of the races replace (datadir_race_windows_test.go), each of which does nothing here.
// afterDataDirMade runs between the call that makes a new folder dir and the step that sets its owner and its list,
// afterDataDirLook between the look at a kept folder dir and the step that sets its owner and its list, and
// dataDirEntryOpened for each file and folder that the look opens, with its path. A test puts a folder or a junction in the
// place of the folder in such a moment, adds to it, or records what the look opened.
var (
	afterDataDirMade   = func(dir string) {}
	afterDataDirLook   = func(dir string) {}
	dataDirEntryOpened = func(path string) {}
)

// checkDataDirName refuses the path dir of a data directory when its last element, as filepath.Clean leaves it, ends in a
// period or a space (finding E of the read-only review of PR 541, at the head 8d282cf3). Windows takes trailing periods and
// spaces off the end of a path, and filepath.Clean takes off only a trailing separator and the elements `.` and `..`, so
// `D:\RanzData\ `, `D:\RanzData\...` and `D:\RanzData\. ` name D:\RanzData, and so does `D:\RanzData\ \` once filepath.Clean
// has taken its separator off. filepath.Dir of such a path is the folder itself, so the step that makes the folder above it
// (os.MkdirAll) would make the data directory with the access list of its own folder, which on C:\ProgramData lets the Users
// group add files and folders, as a trailing separator did before createDataDir cleaned the path (finding A). And the files
// of the controller, whose names are joined to the path, would not lie in the folder that was looked at. Nobody names a data
// directory so on purpose, so the path is refused, with nothing made. A last element of `.` or `..` is not one of these:
// Windows resolves it before it takes anything off.
func checkDataDirName(dir string) error {
	last := filepath.Base(filepath.Clean(dir))
	if last == "." || last == ".." {
		return nil
	}
	if strings.HasSuffix(last, ".") || strings.HasSuffix(last, " ") {
		return fmt.Errorf(`the data directory "%s" ends in a period or a space, which Windows takes off the end of a path, so the path names another folder than its text says. Name the data directory without them with -data`, dir)
	}
	return nil
}

// openFolder opens the file or folder path as itself, without following a link (FILE_FLAG_OPEN_REPARSE_POINT, and
// FILE_FLAG_BACKUP_SEMANTICS for a folder), with the rights access, and returns it as a File whose Fd is the handle. A link in
// the folders above the last element of path is followed, as Windows follows it in every path.
func openFolder(path string, access uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, access, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// openEntry opens the file or folder name of the folder that the handle folder holds open, by that exact name and as itself,
// without following a link, with the rights of the look, and returns it as a File named path. NtCreateFile looks the name up in
// that folder, with none of the rules of the paths of Windows: a name that ends in a period or a space, or that is the name of
// a device such as NUL or CON, opens the entry of that name and no other (findings of the third and the fourth read-only review
// of PR 541), and the folder is the one that the look opened, wherever a rename took it since.
func openEntry(folder windows.Handle, name, path string) (*os.File, error) {
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{RootDirectory: folder, ObjectName: object}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&h, lookRights, &attrs, &iosb, nil, 0, shareAll, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
		return nil, ntError(err)
	}
	return os.NewFile(uintptr(h), path), nil
}

// ntError is the error of Windows that the status err of a native call stands for, which says what went wrong in the words of
// the other calls.
func ntError(err error) error {
	if status, ok := err.(windows.NTStatus); ok {
		return status.Errno()
	}
	return err
}

// createFolder makes the folder dir, which is not there, with the security descriptor sd, and returns the handle of the call
// that made it as a File. NtCreateFile makes the folder and opens it in one call, where CreateDirectory makes it and opens
// nothing, so the folder that the handle holds is the one that the call made, wherever a rename takes it afterwards. The call
// fails when the name is taken when it runs, by a link too, which it does not follow. The folder above dir is opened by its
// path, as CreateDirectory opened it, and the name of dir is looked up in it as it is written.
func createFolder(dir string, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	above, err := windows.UTF16PtrFromString(filepath.Dir(dir))
	if err != nil {
		return nil, err
	}
	parent, err := windows.CreateFile(above, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(parent)
	object, err := windows.NewNTUnicodeString(filepath.Base(dir))
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: object, SecurityDescriptor: sd}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&h, newFolderRights, &attrs, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, shareAll, windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
		return nil, ntError(err)
	}
	return os.NewFile(uintptr(h), dir), nil
}

// folderOwner returns the owner of the data directory dir, which f holds open as itself. It refuses a link, a junction or a
// symbolic link, which whoever made it points anywhere, and what is no directory: the folder itself must be the data
// directory. And it refuses a folder on a volume that keeps no access lists, such as a FAT drive, which has none to protect
// the directory with: GetSecurityInfo is not asked there.
func folderOwner(f *os.File, dir string) (*windows.SID, error) {
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return nil, fmt.Errorf("the data directory %s is a link (a junction or a symbolic link), which the controller does not follow: name the folder itself with -data", dir)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return nil, fmt.Errorf("the data directory %s is not a directory", dir)
	}
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return nil, fmt.Errorf("the volume of the data directory %s: %w", dir, err)
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return nil, fmt.Errorf("the data directory %s has no security descriptor: its volume has no access lists", dir)
	}
	owner, err := ownerOf(h)
	if err != nil {
		return nil, fmt.Errorf("the owner of the data directory %s: %w", dir, err)
	}
	return owner, nil
}

// dataDirOwner returns the owner of the data directory dir, which it opens as itself and reads through that handle
// (folderOwner).
func dataDirOwner(dir string) (*windows.SID, error) {
	f, err := openFolder(dir, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("the data directory %s: %w", dir, err)
	}
	defer f.Close()
	return folderOwner(f, dir)
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
// rqlited of its payload folder as an administrator. It refuses a path that ends in a period or a space as well
// (checkDataDirName), since the folder that Windows finds by it is not the one that the files of the controller,
// joined to the path, are looked for in.
//
// The message says to remove the directory, and offers to give it to the Administrators only for what an administrator
// made, with a reset of its access list (takeownAdvice), and then to register the service again over it: the reset leaves
// the folder the list that it inherits from the folder above, which under C:\ProgramData lets the Users group read what
// it holds and add files and folders, and the start does not set the list of a folder that is there, while the install
// sets it after a look at what the folder holds (finding 2 of the third read-only review of PR 541).
func checkDataDirOwner(dir string) error {
	if err := checkDataDirName(dir); err != nil {
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
	if !trusted {
		return fmt.Errorf("the data directory %s is owned by %s, and only SYSTEM, the Administrators and %s may own it: another account may have made it before the install, and what it holds would run as the controller. "+
			"Look at what it holds, remove it, and start again. %s", dir, accountName(owner), serviceAccount,
			takeownAdvice(dir, "register the service again over it before it starts (ranz controller uninstall, then ranz controller install with the flags of the service), since the reset leaves it the access list of the folder above it, which only the install replaces"))
	}
	return nil
}

// setDataDirSecurity sets the security that sd gives to the folder that f holds open, the data directory dir: its protected
// access list and, when sd names one, its owner. SetSecurityInfo works on the folder that the handle holds, whatever name it has
// by then, and passes the list down to what the folder holds, as an access list that is set on a folder with files in it must.
func setDataDirSecurity(f *os.File, dir string, sd *windows.SECURITY_DESCRIPTOR) error {
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
	if err := windows.SetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("the owner and the access list of the data directory %s: %w", dir, err)
	}
	return nil
}

// ownDataDir makes the Administrators the owner of the data directory dir, which f holds open, and gives it the protected
// access list of dataDirSDDL, which the files and folders in it inherit.
func ownDataDir(f *os.File, dir string) error {
	sd, err := windows.SecurityDescriptorFromString(installDataDirSDDL)
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	return setDataDirSecurity(f, dir, sd)
}

// stillNamed returns nil when the path dir names the folder that f holds open, and says why not otherwise: the path is opened
// as itself, without following a link, and the two are compared by the numbers that the volume gives its files
// (os.SameFile). An account that may change the folder above dir can rename the folder that f holds away, through its right
// on the folder above, and put another folder, or a link, in its place; the handle holds the folder all the same.
func stillNamed(dir string, f *os.File) error {
	g, err := openFolder(dir, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("it could not be opened (%v)", err)
	}
	defer g.Close()
	held, err := f.Stat()
	if err != nil {
		return fmt.Errorf("the folder could not be looked at (%v)", err)
	}
	named, err := g.Stat()
	if err != nil {
		return fmt.Errorf("it could not be looked at (%v)", err)
	}
	if !os.SameFile(held, named) {
		return errors.New("it names another folder or a link now")
	}
	return nil
}

// makeProtectedDir makes the folder dir, which is not there, with the security that sddl gives it, its owner
// when the text names one and its access list, in the call that makes the folder: NtCreateFile takes the
// security descriptor with the name (createFolder). The folder never has the access list of its parent, which on
// C:\ProgramData lets the Users group add files and folders, so no handle that has the right to add to it can
// be opened before its own list is there, and a handle that is opened after is judged by that list (AUD1-DT-18,
// #503). A call that made the folder and set the list after, as os.Mkdir and ownDataDir did, leaves that gap.
// The path is cleaned first, so that no caller passes it as it was typed (createDataDir says why), and one that ends in
// a period or a space is refused before anything is made (checkDataDirName).
//
// The call that makes the folder also opens it, and every step after it works through that handle (AUD1-DT-18-R1, #554):
// the steps read the owner of the folder and set its owner and its list through the handle, and they then refuse the folder
// when its path names another folder or a link (stillNamed). A user that owns the folder above (a C:\ProgramData\Ranz that
// it made first), and any account under a folder whose list lets it change what is made in it, such as one that the step of
// the folder above makes in the root of a volume, can rename the new folder away while the handle holds it, and put a folder
// of its own in its place, with payload\ inside and a handle held, or a junction. The owner and the list then go to the
// folder that the call made, wherever it went, and to nothing that the user put in its place; the folder is removed again
// through its handle, and the step fails, so that neither the install nor the start of the service goes on in what the user
// put there. Before, the steps read the owner and set the list by name, and gave the folder of the user, or the folder that
// the junction names, to the Administrators.
//
// A volume that keeps no access lists, such as a FAT drive, takes the folder and ignores the descriptor: the folder is removed
// again, and the error says so (folderOwner).
//
// CreateDirectory gives the folder its list as a protected list and no more: the flag of a list that passes a change
// down to what the folder holds (auto-inherited, AI in the text of a descriptor) is not set, whatever the descriptor says,
// and a file that is made in the folder has a list without it too. When SetNamedSecurityInfo then gives such a file an
// owner, it turns the entries that the file inherited into entries of its own and protects its list, so a later change of
// the list of the folder no longer reaches the file (measured on the hosted runners, x64 and arm64, run 41066865697 of the
// throwaway workflow exp-datadir-sd.yml of #503). NtCreateFile, which CreateDirectory calls, does the same. So the same list
// is set once more through the handle, as the install sets it over a folder that is kept: the folder gets the flag, and its
// files take the list the way that the files of a folder of before did. The folder has its list at every moment, so this
// gives no handle a right that it did not have.
func makeProtectedDir(dir, sddl string) error {
	dir = filepath.Clean(dir)
	if err := checkDataDirName(dir); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	f, err := createFolder(dir, sd)
	if err != nil {
		return &fs.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	defer f.Close()
	afterDataDirMade(dir)
	if err := protectNewFolder(f, dir, sd); err != nil {
		removeNewFolder(f)
		return err
	}
	return nil
}

// protectNewFolder reads the owner of the new folder dir that f holds open, the one that createFolder made, which fails on a
// volume that keeps no access lists, sets the security that sd gives it through f, and refuses it when its path names another
// folder or a link by then.
func protectNewFolder(f *os.File, dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	if _, err := folderOwner(f, dir); err != nil {
		return err
	}
	if err := setDataDirSecurity(f, dir, sd); err != nil {
		return err
	}
	if err := stillNamed(dir, f); err != nil {
		return fmt.Errorf("the data directory %s was replaced while it was made: %v. The folder that was made for it got its owner and its access list through the handle of the call that made it, and is removed again, and what the path names now was not changed. "+
			"An account that may change %s can do that: look at what is there, remove what was not made for the controller, and try again", dir, err, filepath.Dir(dir))
	}
	return nil
}

// removeNewFolder removes the empty folder that f holds open, the one that createFolder made, through that handle: the folder
// goes when its last handle is closed, wherever a rename took it, and a folder that another account put in its place stays
// as it is. FileDispositionInfo takes a FILE_DISPOSITION_INFO, whose one field, DeleteFile, is a BOOLEAN.
func removeNewFolder(f *os.File) {
	deleteFile := byte(1)
	_ = windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &deleteFile, 1)
}

// makeOwnedDataDir makes the data directory dir, which is not there, with the Administrators as its owner and
// the protected access list of dataDirSDDL from the moment it exists (makeProtectedDir). The path is cleaned
// first, as createDataDir says, and one that ends in a period or a space is refused before the folder above it is
// made (checkDataDirName).
func makeOwnedDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if err := checkDataDirName(dir); err != nil {
		return err
	}
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
//
// A path whose last element ends in a period or a space is refused before the folder above it is made, and nothing is
// made (checkDataDirName says why; finding E, and the same test): filepath.Clean keeps the tail and Windows drops it, so
// the folder above the cleaned path is the data directory itself, as it was with a trailing separator.
func createDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if err := checkDataDirName(dir); err != nil {
		return err
	}
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
//     it holds, and its owner and its access list are set, when what it holds is theirs too (keepDataDir). A
//     file or a folder in it, at any depth, that another account owns, a reparse point such as a junction or a
//     symbolic link, and a file with more than one name (a hard link) are refused before anything is changed
//     (checkDataDirChildren): a user made it while the folder had an access list that let the Users group add
//     to it, its owner has full control of it through the entry for OWNER RIGHTS that the install passes down,
//     and what it holds would run as the controller. It is not given to the Administrators either: a handle
//     that its owner opened before the list changed still writes after, and an entry that its owner put on its
//     list stays, since the list that the install passes down replaces only the entries that came from the
//     folder. The message says to remove it, and offers to give it to the Administrators, with a reset of its
//     list, only for what an administrator made (refuseChild). The folder is opened as itself before the look,
//     and the look, the change of its owner and its list and a second look all go through that handle; the
//     install then refuses it when its path no longer names that folder (AUD1-DT-18-R1, #554).
//   - A directory that another account owns is not kept: it may hold anything, a store with a token that
//     the user knows or an rqlited.exe of its own, and the account that made it may hold it open, and so
//     keep a way to write into it after the access list changed. It is taken over by making it again:
//     an empty one is removed, which fails while anybody holds it open, and made anew. One that holds
//     anything, and one that cannot be read or removed, is refused with a message that says to remove it,
//     and offers to give it to the Administrators, with a reset of its list, only for what an administrator
//     made (removeForeignDataDir). One that is a link is refused before its owner counts (folderOwner).
//
// A path whose last element ends in a period or a space is refused first, whether the folder is there or not, and
// nothing is changed (checkDataDirName): it names the folder without the tail, and the files of the controller, which
// are joined to the path, would not lie in the folder that the install took over.
func takeOverDataDir(dir string) error {
	dir = filepath.Clean(dir)
	if err := checkDataDirName(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return makeOwnedDataDir(dir)
	} else if err != nil {
		return err
	}
	f, err := openFolder(dir, setRights)
	if err != nil {
		return fmt.Errorf("the data directory %s: %w", dir, err)
	}
	owner, err := folderOwner(f, dir)
	if err != nil {
		f.Close()
		return err
	}
	trusted, err := ownerIsTrusted(owner)
	if err != nil {
		f.Close()
		return err
	}
	if trusted {
		defer f.Close()
		return keepDataDir(f, dir)
	}
	// The folder of another account is removed by its name, and Windows deletes a folder only once its last handle is closed
	f.Close()
	if err := removeForeignDataDir(dir, owner); err != nil {
		return err
	}
	return makeOwnedDataDir(dir)
}

// keepDataDir takes over the kept data directory dir, which f holds open as itself and a trusted account owns, through that
// handle (AUD1-DT-18-R1, #554): it looks at what the folder holds (checkDataDirChildren), gives the folder to the
// Administrators with the protected list (ownDataDir), looks at what it holds once more, and refuses it when its path no
// longer names the folder that f holds (stillNamed).
//
// The owner and the list go to the folder that the look read, wherever a rename took it: a user that owns the folder above it
// can put a folder of its own, or a junction, in its place between the look and the change, and the install then gives
// nothing of the user, and not the folder that the junction names, to the Administrators. The second look refuses what was
// added to the folder while the install looked, which a folder whose list lets the Users group add files and folders allows
// (finding 1 of the fourth read-only review of PR 541): the install has given the folder to the Administrators by then and
// says so, and undoes nothing, since what it changed is the data directory and what was added is not the install's.
func keepDataDir(f *os.File, dir string) error {
	if err := checkDataDirChildren(f, dir); err != nil {
		return err
	}
	afterDataDirLook(dir)
	if err := ownDataDir(f, dir); err != nil {
		return err
	}
	if err := checkDataDirChildren(f, dir); err != nil {
		return fmt.Errorf("the install gave the data directory %s to the Administrators with its protected access list, after a look at what it holds found nothing to refuse, and then looked again and found what was added to it in the meantime, so the install stops here and registers no service: %w", dir, err)
	}
	if err := stillNamed(dir, f); err != nil {
		return fmt.Errorf("the data directory %s was replaced while the install took it over: %v. The folder that the install looked at got the Administrators as its owner and the protected access list through the handle that the look read it through, wherever it is now, and what the path names now was not changed. "+
			"An account that may change %s can do that: look at what is there and where the folder went, and run the install again", dir, err, filepath.Dir(dir))
	}
	return nil
}

// removeForeignDataDir removes the data directory dir, which the account owner owns, when it is empty,
// and refuses it otherwise. The message says to remove it, and offers to give it to the Administrators only for what
// an administrator made, with a reset of its access list (takeownAdvice): after takeown alone, the look of the next
// install would pass the folder, whose owners are then trusted, and an entry that the user put on the list of payload\
// would stay and pass down to the rqlited.exe that the service writes there (finding 2 of the third read-only review
// of PR 541).
func removeForeignDataDir(dir string, owner *windows.SID) error {
	refuse := func(why string) error {
		return fmt.Errorf("the data directory %s is owned by %s, so the install did not take it over: %s. A user may have made it before the install, and what it holds would run as the controller. "+
			"Look at what it holds, remove it, and run the install again. %s", dir, accountName(owner), why, takeownAdvice(dir, "run the install again"))
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

// checkDataDirChildren refuses the data directory dir, which f holds open and whose owner is trusted, when a file or a folder
// in it, at any depth, is owned by an account that is not (dataDirTrustees), is a reparse point (a junction or a symbolic
// link, for example), is a file with more than one name (a hard link), or cannot be looked at (AUD1-DT-18, #503, and
// AUD1-DT-18-R1, #554). A trusted owner of the folder says nothing of what is in it: a user that made payload\ while the folder
// had the list of C:\ProgramData owns it still, and the entry for OWNER RIGHTS that the install passes down gives that owner
// full control of it, so the user could swap the rqlited.exe that the service starts. A reparse point is refused, and the look
// does not go into it: the Controller makes none, and what a link points at is not the data directory. A hard link is one
// more name of a file that may lie anywhere on the volume, and a file has one owner and one list whatever name it is reached
// by, so the list that the install passes down would reach that file outside the data directory, and the planted name would
// stay a file that the user can still write. Nothing is changed: the check reads the attributes, the numbers of names and the
// owners only.
//
// Each file and folder is opened once, by its exact name in the folder that the look holds open and as itself, without
// following a link (openEntry), and its attributes, its number of names (GetFileInformationByHandle), its owner
// (GetSecurityInfo) and what a folder holds are read through that handle. So an entry that its owner switches between a folder
// and a junction is one of the two for all that the look reads of it, what a junction points at is never looked at as a
// part of the data directory, and an entry whose name ends in a period or a space, or is the name of a device such as NUL, is
// that entry and not another one that Windows would read by the name (findings of the third and the fourth read-only review
// of PR 541).
//
// What is still open; ST-3 of docs/threat-model.md says so:
//
//   - What a user adds between the look and the change of the list, to a kept folder whose list lets it, which a folder that
//     an administrator made by hand in C:\ProgramData\Ranz allows: the list of the install is passed down to it before the
//     second look refuses it. For a hard link, that is the list of the file that it names, outside the data directory. The
//     list that is passed down does not go through a junction (TestTheListThatTheInstallPassesDownStopsAtAJunction).
//   - A handle that a user opened in a kept folder before it had its list, on a file or a folder that the Administrators own.
//   - What a user changes in a folder whose list lets it after the install, until the service is registered again over it.
func checkDataDirChildren(f *os.File, dir string) error {
	trusted, err := dataDirTrustees()
	if err != nil {
		return err
	}
	return checkChildren(dir, f, dir, trusted)
}

// checkChildren checks what the folder that the File folder holds open holds, the folder path of the data directory dir or dir
// itself: one entry after the other in the order of their names, as the handle of the folder lists them, and the folders down
// to their last file (checkEntry). The list starts at the first entry, whatever an earlier look read through the same File:
// a File goes on from where its last list ended, and Seek starts it again.
func checkChildren(dir string, folder *os.File, path string, trusted []*windows.SID) error {
	if _, err := folder.Seek(0, io.SeekStart); err != nil {
		return refuseChild(dir, path, "could not be read ("+err.Error()+")")
	}
	names, err := folder.Readdirnames(-1)
	if err != nil {
		return refuseChild(dir, path, "could not be read ("+err.Error()+")")
	}
	slices.Sort(names)
	for _, name := range names {
		if err := checkEntry(dir, folder, name, filepath.Join(path, name), trusted); err != nil {
			return err
		}
	}
	return nil
}

// checkEntry looks at the file or folder name of the folder that the File folder holds open, the entry path of the data
// directory dir, through the one handle that opens it (openEntry), and goes into a folder through that handle too.
func checkEntry(dir string, folder *os.File, name, path string, trusted []*windows.SID) error {
	f, err := openEntry(windows.Handle(folder.Fd()), name, path)
	if err != nil {
		return refuseChild(dir, path, "could not be looked at ("+err.Error()+")")
	}
	defer f.Close()
	dataDirEntryOpened(path)
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return refuseChild(dir, path, "could not be looked at ("+err.Error()+")")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return refuseReparsePoint(dir, path)
	}
	isFolder := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if !isFolder && info.NumberOfLinks > 1 {
		return refuseHardLink(dir, path, info.NumberOfLinks)
	}
	owner, err := ownerOf(h)
	if err != nil {
		return refuseChild(dir, path, "has an owner that could not be read ("+err.Error()+")")
	}
	if !slices.ContainsFunc(trusted, owner.Equals) {
		return refuseChild(dir, path, "is owned by "+accountName(owner)+", and only SYSTEM, the Administrators, "+serviceAccount+" and the account that runs the install may own what a data directory holds")
	}
	if isFolder {
		return checkChildren(dir, f, path, trusted)
	}
	return nil
}

// ownerOf returns the owner of the file or folder that the handle h holds open. The volume of the data directory keeps
// access lists (folderOwner), and what the look opens is on that volume, since it goes into no link.
func ownerOf(h windows.Handle) (*windows.SID, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
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

// deviceName matches the names that Windows reads as a device in the last element of a path, whatever their case: CON, PRN,
// AUX, NUL, CONIN$, CONOUT$, and COM and LPT with a digit, or with a superscript one, two or three.
var deviceName = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9\x{00B9}\x{00B2}\x{00B3}]|LPT[0-9\x{00B9}\x{00B2}\x{00B3}])$`)

// literalNameNote is what a refusal adds for the file or folder path when Windows reads its name as another one in a path
// that does not start with \\?\, which a user that may add to a folder can make with such a path: a name that ends in a
// period or a space, which Windows takes off, or the name of a device, which it reads as the device (with an extension too, on
// some versions of Windows). The commands of the advice need \\?\ before the full path then. It is empty for any other name.
func literalNameNote(path string) string {
	name := filepath.Base(path)
	stem, _, _ := strings.Cut(name, ".")
	if !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ") && !deviceName.MatchString(strings.TrimRight(stem, " ")) {
		return ""
	}
	return ` Windows reads its name as another one, since it ends in a period or a space or is the name of a device: put \\?\ before its full path in each command that names it.`
}

// refuseChild is the refusal of the kept data directory dir, because of the file or folder path in it, which why
// says what is wrong with. The path is in quotes, so that a period or a space at its end shows. The message says to remove
// it, and offers to give it to the Administrators only for what an administrator made, with a reset of its access list
// (takeownAdvice; finding B2 of the second read-only review of PR 541).
func refuseChild(dir, path, why string) error {
	return fmt.Errorf(`the data directory %s is kept with what it holds, so the install did not take it over: "%s" %s. A user may have put it there before the install, and it would run as the controller. `+
		"Look at it, remove it, and run the install again.%s %s", dir, path, why, literalNameNote(path), takeownAdvice(path, "run the install again"))
}

// takeownAdvice is the part of a refusal that offers to give the file or folder path, which an untrusted account owns, to
// the Administrators: only when an administrator made it and all that it holds, and always with a reset of its access list
// and of every list below it, and then to do what then says. takeown changes only the owner, and the list that the install
// passes down replaces only the entries that came from the folder, so an entry that a user put on the list of what it
// made, or a protected list, would stay, and so would a handle that the user holds. What a user made is removed instead,
// as the message says before this part.
func takeownAdvice(path, then string) string {
	return fmt.Sprintf(`Only when an administrator made it and all that it holds, give it to the Administrators and reset its access list instead (takeown /F "%s" /A /R /D Y, then icacls "%s" /reset /T), and %s: takeown alone changes only the owner, and keeps an entry that a user put on the list`, path, path, then)
}

// refuseReparsePoint is the refusal of the kept data directory dir, because the file or folder path in it is a
// reparse point. Most are links, a junction or a symbolic link, which point anywhere, so the message says to remove
// the link itself, and never to give it to the Administrators, which would leave it a link. A reparse point of
// another kind, a file that Data Deduplication or a cloud sync made one, is refused the same way, and the advice is
// then for a link: the message names it a reparse point and says to look at it first.
func refuseReparsePoint(dir, path string) error {
	return fmt.Errorf(`the data directory %s is kept with what it holds, so the install did not take it over: "%s" is a reparse point, such as a junction or a symbolic link. A link points anywhere, so the install does not look into one and does not keep one. `+
		`Look at it, remove the link itself, and run the install again: rmdir "%s" removes a junction or a link to a folder, del "%s" removes a link to a file, and neither touches what it points at. Do not give it to the Administrators: it would stay a link.%s`, dir, path, path, path, literalNameNote(path))
}

// refuseHardLink is the refusal of the kept data directory dir, because the file path in it has links names in all, this one
// and more (AUD1-DT-18-R1, #554): a hard link, which is one more name of a file that may lie anywhere on the volume. A file has
// one owner and one access list, whatever name it is reached by, so the list that the install passes down would reach the
// file under its other names too, and giving it to the Administrators would give them that file. The message says to remove
// this name of it, which leaves the file under its other names as it is, and never to give it to the Administrators. The
// Controller makes no hard link.
func refuseHardLink(dir, path string, links uint32) error {
	return fmt.Errorf(`the data directory %s is kept with what it holds, so the install did not take it over: "%s" is a hard link, one of %d names of one file, and the other names may be outside the data directory. A file has one owner and one access list whatever name it is reached by, so the install would change the file outside too. `+
		`Look at it, remove this name of it, and run the install again: del "%s" removes this name and leaves the file under its other names. Do not give it to the Administrators: they would own the file under every name.%s`, dir, path, links, path, literalNameNote(path))
}
