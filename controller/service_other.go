//go:build !windows

package controllercmd

import "errors"

// serviceName is the name of the Windows service.
const serviceName = "ranz-controller"

var errNotWindows = errors.New("the Windows service exists only on Windows; on Linux run `ranz controller` under the init system, for example as a systemd unit")

func defaultDataDir() string {
	return "/var/lib/ranz-controller"
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

// Install is install: there is no Windows service on this OS (ONE-2, #311).
func Install(string) error {
	return install(nil, config{})
}

// InstallAdminFrom is install: there is no Windows service on this OS (AUD1-DT-6, #454).
func InstallAdminFrom(string, string) error {
	return install(nil, config{})
}

// Uninstall is uninstall: there is no Windows service on this OS (ONE-2, #311).
func Uninstall() error {
	return uninstall()
}
