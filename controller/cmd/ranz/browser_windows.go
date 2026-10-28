//go:build windows

package main

import "golang.org/x/sys/windows"

// browse opens the page url in the default browser of the user, through the shell (ShellExecuteW, the
// verb open), as Windows opens a link.
func browse(url string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(url)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
