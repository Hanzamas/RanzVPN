//go:build !windows

package main

import (
	"errors"
	"os"
)

// errNoAdminRights refuses a reset-admin by anyone but root.
var errNoAdminRights = errors.New("reset-admin needs root on the controller's host")

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
