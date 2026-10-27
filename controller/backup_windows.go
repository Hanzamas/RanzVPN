//go:build windows

package controllercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// backupFileSDDL is the access list of a backup: full control for SYSTEM and the Administrators,
// protected, and nothing for anyone else. A file that is made in a folder takes the access list of the
// folder, and the folder that an administrator names may let the Users group read what is in it (the
// folders of a drive that is not C:, a share): a backup holds the hashes of the tokens and of the
// passwords, the licence key and the secrets of the targets (AUD1-DT-10, #458, ST-4).
const backupFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// backupAccess says in the message of backup who may read the file.
const backupAccess = "for SYSTEM and the Administrators only"

// createBackupFile makes the file path, which a backup is written to before it gets its name, with the
// protected access list of backupFileSDDL from the moment it exists, and opens it for this process
// alone. Windows checks the access list of a file when a handle is opened, and not at each read: a file
// that took the access list of its folder first and got its own list after would leave a handle that a
// member of the Users group opened in between, and that handle would read every byte of the backup. The
// mode 0600 of os.OpenFile means nothing to Windows. A file of that name that an earlier backup left is
// removed first, and a file that is made in its place meanwhile is refused (CREATE_NEW), since whoever
// made it may hold it open; a link that is put there is not followed, as os.OpenFile does not follow one
// with O_EXCL. It reports whether the volume keeps access lists: one that has none, such as a FAT drive,
// ignores the list, and the backup there is as readable as the volume.
func createBackupFile(path string) (*os.File, bool, error) {
	sd, err := windows.SecurityDescriptorFromString(backupFileSDDL)
	if err != nil {
		return nil, false, fmt.Errorf("the access list of a backup: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
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
		return nil, false, fmt.Errorf("the volume of %s: %w", path, err)
	}
	return os.NewFile(uintptr(h), path), flags&windows.FILE_PERSISTENT_ACLS != 0, nil
}
