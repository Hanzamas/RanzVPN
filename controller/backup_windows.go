//go:build windows

package controllercmd

import (
	"errors"
	"fmt"

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

// protectBackupFile replaces the access list of the backup file path with backupFileSDDL, protected, so
// that it takes nothing from its folder. The mode 0600 of the call that made the file means nothing to
// Windows. It returns errNoAccessList for a volume that has no access lists.
func protectBackupFile(path string) error {
	sd, err := windows.SecurityDescriptorFromString(backupFileSDDL)
	if err != nil {
		return fmt.Errorf("the access list of a backup: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("the access list of a backup: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return errNoAccessList
	}
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", path, err)
	}
	return nil
}
