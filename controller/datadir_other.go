//go:build !windows

package controllercmd

import "os"

// checkDataDirOwner does nothing: the owner check of the data directory is the one of Windows, where
// C:\ProgramData lets every user make a folder (ST-3 of docs/threat-model.md). Elsewhere MkdirAll made the
// directory with mode 0700, and the init system that runs the controller owns it.
func checkDataDirOwner(string) error {
	return nil
}

// createDataDir makes the data directory dir, which is not there, with the mode 0700 from the moment it exists:
// there is no access list of a folder to set after it, as on Windows (makeProtectedDir).
func createDataDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}
