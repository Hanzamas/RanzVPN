//go:build windows

package certgen

import (
	"fmt"

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
