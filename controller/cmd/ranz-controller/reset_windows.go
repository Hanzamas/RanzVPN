//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
)

// errNoAdminRights refuses a reset-admin, a backup or a restore by anyone but a local
// administrator.
var errNoAdminRights = errors.New("this command needs a local Administrator of the controller's host: run it from an elevated prompt (Run as administrator)")

// adminRights returns nil when the process holds the rights of a local administrator: its token
// is a member of BUILTIN\Administrators and elevated. A token that UAC filtered holds the group
// for deny only, so a non-elevated prompt of an administrator is refused as well.
func adminRights() error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("the SID of BUILTIN\\Administrators: %w", err)
	}
	member, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return fmt.Errorf("the membership of BUILTIN\\Administrators: %w", err)
	}
	if !member || !windows.GetCurrentProcessToken().IsElevated() {
		return errNoAdminRights
	}
	return nil
}

// noteReset writes msg to the Application log as a warning (eventReset) of the service's event
// source.
func noteReset(msg string) error {
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return err
	}
	defer elog.Close()
	return elog.Warning(eventReset, msg)
}
