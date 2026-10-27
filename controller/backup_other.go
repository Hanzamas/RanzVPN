//go:build !windows

package controllercmd

import "os"

// backupAccess says in the message of backup who may read the file.
const backupAccess = "readable by its owner only"

// protectBackupFile makes the backup file path readable by its owner only. OpenFile made the file with
// that mode, but a file that existed keeps the mode it had.
func protectBackupFile(path string) error {
	return os.Chmod(path, 0o600)
}
