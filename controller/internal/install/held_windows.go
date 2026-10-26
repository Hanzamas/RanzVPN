//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/windows"
)

// waitUnheld waits until no process holds the file path open, for at most timeout, and reports to w
// when it gives up. Windows Installer removes ranz.exe once, right after ranz uninstall -keep-ranz
// ends (the uninstall and the rollback of a failed install of the thin MSI, ONE-5 #314). A file that
// a scanner or another process still holds then stays in the Ranz folder and is removed only at the
// next restart, which would take away the ranz.exe that a later install puts there. The probe opens
// the file with no sharing, which fails with a sharing violation while any other handle to it is
// open; the image of a ranz.exe that runs from it holds no handle. A file that is not there is free.
func waitUnheld(w io.Writer, path string, timeout time.Duration) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			_ = windows.CloseHandle(h)
			return
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(w, "uninstall: %s is still held by another process after %s, so Windows Installer may remove it only at the next restart\n", path, timeout)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
