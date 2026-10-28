//go:build !windows

package controllercmd

import (
	"errors"
	"io/fs"
	"os"
)

// backupAccess says in the message of backup who may read the file.
const backupAccess = "readable by its owner only"

// createBackupFile makes the file path, which a backup is written to before it gets its name, readable
// by its owner only from the moment it exists. A file of that name that an earlier backup left keeps the
// mode it had, so it is removed first, and a file that is made in its place meanwhile is refused
// (O_EXCL), since whoever made it may hold it open. The mode is the access list here, so it reports that
// the file has one.
func createBackupFile(path string) (*os.File, bool, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	return f, true, nil
}
