//go:build !windows

package install

import "errors"

var errNotWindows = errors.New("install: the Ranz VPN Node and Controller install as Windows services; there is nothing to install on this OS")

// Install is Install: there is no Windows service on this OS.
func Install(bool) error { return errNotWindows }

// Uninstall is Uninstall: there is no Windows service on this OS.
func Uninstall() error { return errNotWindows }
