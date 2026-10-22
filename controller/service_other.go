//go:build !windows

package main

import "errors"

// serviceName is the name of the Windows service.
const serviceName = "ranz-controller"

var errNotWindows = errors.New("the Windows service exists only on Windows; on Linux run ranz-controller under the init system, for example as a systemd unit")

func defaultDataDir() string {
	return "/var/lib/ranz-controller"
}

// protectDir does nothing: MkdirAll created the directory with mode 0700.
func protectDir(string) error {
	return nil
}

func isService() bool {
	return false
}

func runService(config) error {
	return errNotWindows
}

func install([]string, config) error {
	return errNotWindows
}

func uninstall() error {
	return errNotWindows
}
