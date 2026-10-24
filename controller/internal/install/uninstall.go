package install

// UninstallOptions are the choices of Uninstall.
type UninstallOptions struct {
	// KeepRanz leaves ranz.exe and the Ranz folder where they are, for the caller to remove once this
	// process has ended. The thin MSI (ONE-5, #314) asks for it: Windows Installer owns the ranz.exe
	// in the Ranz folder, which runs this uninstall as one of its actions, and removes that file and
	// the folder itself after the action. Without it a ranz.exe that runs from the Ranz folder cannot
	// delete itself, so Uninstall has Windows remove it and the folder at the next restart, and that
	// would take away a ranz.exe that an install had put there in between, as an upgrade does.
	KeepRanz bool
}
