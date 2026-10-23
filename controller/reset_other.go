//go:build !windows

package controllercmd

import (
	"errors"
	"os"
)

// errNoAdminRights refuses a reset-admin, a backup or a restore by anyone but root.
var errNoAdminRights = errors.New("this command needs root on the controller's host")

// adminRights returns nil when the process runs as root.
func adminRights() error {
	if os.Geteuid() != 0 {
		return errNoAdminRights
	}
	return nil
}

// noteReset does nothing: there is no Application log outside Windows, and the output of
// reset-admin names the token it created.
func noteReset(string) error {
	return nil
}
