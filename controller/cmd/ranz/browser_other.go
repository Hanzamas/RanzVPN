//go:build !windows

package main

import "os/exec"

// browse opens the page url in the browser of the user through xdg-open, the opener of the desktop.
func browse(url string) error {
	return exec.Command("xdg-open", url).Start()
}
