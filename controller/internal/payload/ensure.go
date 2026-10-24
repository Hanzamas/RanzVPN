package payload

import (
	"fmt"
	"os"
	"path/filepath"
)

// Ensure puts the file of p in dir unless it is there already, and returns its path (ONE-4, #313:
// ranz controller writes its rqlite member under its data directory at every start that finds it
// missing). A file with the name of p whose SHA-256 is the one recorded for p stays as it is: it is
// the file that an earlier Ensure or Install wrote after its checks, byte for byte. A file that is
// missing, or that differs in a single byte, is written from p by Install, which checks p's hash
// and its Authenticode signature before anything reaches dir. So deleting the file between two
// starts does not break the next one, and a file that someone changed is replaced by the one that
// the executable carries. dir is created if it does not exist.
//
// Install asks for a directory that only SYSTEM and the Administrators can write. The directory of
// Ensure is the one under the data directory of the program that runs the file, which only the
// accounts that may run it can write too (the ACL of the data directory): a program that could not
// write its own file could not write it again at its next start.
func Ensure(dir string, p Payload) (string, error) {
	if len(p.Data) == 0 {
		return "", fmt.Errorf("payload: %s carries no data (a build without the real payload embedded)", p.Name)
	}
	dest := filepath.Join(dir, p.Name)
	if sum, err := fileSHA256(dest); err == nil && sum == p.SHA256 {
		return dest, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("payload: %s: %w", p.Name, err)
	}
	if err := Install(dir, p); err != nil {
		return "", err
	}
	return dest, nil
}
