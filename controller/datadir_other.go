//go:build !windows

package controllercmd

// checkDataDirOwner does nothing: the owner check of the data directory is the one of Windows, where
// C:\ProgramData lets every user make a folder (ST-3 of docs/threat-model.md). Elsewhere MkdirAll made the
// directory with mode 0700, and the init system that runs the controller owns it.
func checkDataDirOwner(string) error {
	return nil
}
