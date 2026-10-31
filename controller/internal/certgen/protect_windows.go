//go:build windows

package certgen

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// keyFileSDDL is the ACL of a file that holds a private key: full control for SYSTEM, the
// Administrators and the owner of the file, not inherited, and nothing for anyone else.
const keyFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"

// protectFile replaces the ACL of the file path with keyFileSDDL, as the controller does for its
// data directory.
func protectFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString(keyFileSDDL)
	if err != nil {
		return fmt.Errorf("certgen: the ACL of a key file: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("certgen: the ACL of a key file: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("certgen: the ACL of %s: %w", path, err)
	}
	return nil
}

// ErrStream is why CheckKeyFileName refuses a name (SDN-82-R2).
var ErrStream = errors.New("its name has a colon in its last element, which makes a stream of a file on Windows, and a stream has the access list of that file, not the protected list of a key file")

// CheckKeyFileName refuses the name path for a file that holds a secret, when a file under that name could
// not get the protected ACL of keyFileSDDL. A colon in the last element of a name, as in
// C:\temp\notes.txt:phone.conf, names a stream of the file notes.txt. When that file exists, CREATE_NEW makes
// the stream inside it, since only the stream is new, and the ACL that a call gives is for a new file: the
// stream has the ACL of notes.txt, which other accounts may read. So no name with such a colon is a name for
// keys, whether the file exists or not. A colon of the drive, as in C:phone.conf, is no such colon. The error
// wraps ErrStream. ranz device create asks before it makes a Device, and CreateKeyFile asks again.
func CheckKeyFileName(path string) error {
	if strings.Contains(filepath.Base(path), ":") {
		return &fs.PathError{Op: "create", Path: path, Err: ErrStream}
	}
	return nil
}

// CreateKeyFile makes the file path for a secret, such as the keys of a WireGuard Device, with the
// protected ACL of keyFileSDDL from the moment it exists, and opens it for writing by this process
// alone until it is closed. Windows checks the ACL of a file when a handle is opened, not at each read:
// a file that took the ACL of its folder first and got its own after would leave a handle that another
// account opened in between, and that handle would read what is written after. The mode 0600 of
// os.OpenFile means nothing to Windows. A file that exists is refused with an error that wraps
// fs.ErrExist, and so is a link that is there, which it does not follow (CREATE_NEW). A name that makes a
// stream of a file is refused with an error that wraps ErrStream (CheckKeyFileName). It reports whether
// the volume keeps ACLs: one that has none, such as a FAT drive, ignores the ACL, and the file there is
// as readable as the volume.
func CreateKeyFile(path string) (*os.File, bool, error) {
	if err := CheckKeyFileName(path); err != nil {
		return nil, false, err
	}
	sd, err := windows.SecurityDescriptorFromString(keyFileSDDL)
	if err != nil {
		return nil, false, fmt.Errorf("certgen: the ACL of a key file: %w", err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, &fs.PathError{Op: "create", Path: path, Err: err}
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, false, &fs.PathError{Op: "create", Path: path, Err: err}
	}
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		_ = windows.CloseHandle(h)
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("certgen: the volume of %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), flags&windows.FILE_PERSISTENT_ACLS != 0, nil
}
