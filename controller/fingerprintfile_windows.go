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

	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// fileDeleteChild is FILE_DELETE_CHILD of winnt.h, which golang.org/x/sys/windows does not name.
const fileDeleteChild = 0x40

// writeRights are the rights of an access entry that let its account change what a file says or what a
// folder holds: write or append to it (add a file or a folder to a folder), write its extended attributes
// or its attributes, delete it or what a folder holds, change its access list or its owner, and the
// generic rights that hold those.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | fileDeleteChild |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// ReadFingerprint returns the TLS fingerprint in servercert.FingerprintFile of the data directory dir, as
// servercert.ReadFingerprint reads it, for ranz on this host, and refuses the file with an *UntrustedError
// when another account than SYSTEM, the Administrators and the account of the service can have written it:
// such an account owns the file or its folder, or an access entry lets it write one of them, or the file is
// a link. The account that runs ranz is not trusted for being that account, as ownerIsTrusted trusts it
// with a data directory: a program of the same user that is not elevated could have made the folder, and
// the token that ranz sends may be one that such a program cannot read.
//
// The file is opened first and is checked and read through that handle, so what is read is what was
// checked. The handle shares the right to read alone: while it is open no handle may write the file, nor
// delete or replace it, and the folder that holds it cannot be renamed, so the folder that is checked by
// its name is that one.
func ReadFingerprint(dir string) (string, error) {
	trusted, err := fingerprintTrustees()
	if err != nil {
		return "", err
	}
	file := filepath.Join(dir, servercert.FingerprintFile)
	name, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return "", &fs.PathError{Op: "open", Path: file, Err: err}
	}
	// A link is opened as itself, not followed, and refused below
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", &fs.PathError{Op: "open", Path: file, Err: err}
	}
	f := os.NewFile(uintptr(h), file)
	defer f.Close()
	if err := checkFingerprintFolder(dir, trusted); err != nil {
		return "", err
	}
	if err := checkFingerprintFile(h, file, trusted); err != nil {
		return "", err
	}
	return servercert.ReadFingerprintFile(f)
}

// fingerprintTrustees returns the accounts that may own a fingerprint file and its folder, and write them:
// SYSTEM, the Administrators and the account of the service, which writes the file at every start.
func fingerprintTrustees() ([]*windows.SID, error) {
	trusted := make([]*windows.SID, 0, 3)
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
	return append(trusted, service), nil
}

// checkFingerprintFolder refuses the folder dir of a fingerprint file when it is a link or on a volume that
// keeps no access lists, and as checkWriters does. Another account that owns the folder can change its access
// list and replace the file in it, and one that may add a file to it can do the second.
func checkFingerprintFolder(dir string, trusted []*windows.SID) error {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &fs.PathError{Op: "stat", Path: dir, Err: err}
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return &fs.PathError{Op: "stat", Path: dir, Err: err}
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &UntrustedError{Path: dir, Why: "is a link (a junction or a symbolic link), which ranz does not follow"}
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("the owner and the access list of %s: %w", dir, err)
	}
	if sd == nil {
		return &UntrustedError{Path: dir, Why: "is on a volume that keeps no access lists, so every account may write it"}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("the owner of %s: %w", dir, err)
	}
	if owner == nil {
		return &UntrustedError{Path: dir, Why: "has no owner"}
	}
	return checkWriters(dir, owner, sd, trusted)
}

// checkFingerprintFile refuses the fingerprint file that the handle h holds open, whose name is file, when it
// is a link or on a volume that keeps no access lists, and as checkWriters does.
func checkFingerprintFile(h windows.Handle, file string, trusted []*windows.SID) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &fs.PathError{Op: "stat", Path: file, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return &UntrustedError{Path: file, Why: "is a link (a symbolic link or a junction), which ranz does not follow"}
	}
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return fmt.Errorf("the volume of %s: %w", file, err)
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return &UntrustedError{Path: file, Why: "is on a volume that keeps no access lists, so every account may write it"}
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("the owner and the access list of %s: %w", file, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("the owner of %s: %w", file, err)
	}
	if owner == nil {
		return &UntrustedError{Path: file, Why: "has no owner"}
	}
	return checkWriters(file, owner, sd, trusted)
}

// checkWriters refuses the file or folder path, whose owner is owner and whose access list sd holds, when
// owner is none of trusted, which the owner of an object can always change the access list of, and when an
// access entry lets an account that is none of them write it. An entry for OWNER RIGHTS is for the owner.
// An entry that denies, one that only what is made in a folder takes, and one with no right to write let
// nobody write it.
func checkWriters(path string, owner *windows.SID, sd *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID) error {
	if !slices.ContainsFunc(trusted, owner.Equals) {
		return &UntrustedError{Path: path, Why: "is owned by " + accountName(owner)}
	}
	dacl, _, err := sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil) {
		return &UntrustedError{Path: path, Why: "has no access list, so every account may write it"}
	}
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", path, err)
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return fmt.Errorf("a well-known SID: %w", err)
	}
	for i := range dacl.AceCount {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("the access list of %s: %w", path, err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&writeRights == 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			// An object entry, a compound one or one with a condition: its account is not where it is in an
			// entry that allows, and its right to write is enough to refuse it
			return &UntrustedError{Path: path, Why: fmt.Sprintf("has an access entry of type %d that gives a right to write it, which ranz does not read", ace.Header.AceType)}
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(ownerRights) && !slices.ContainsFunc(trusted, sid.Equals) {
			return &UntrustedError{Path: path, Why: "may be written by " + accountName(sid)}
		}
	}
	return nil
}
