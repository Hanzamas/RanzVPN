//go:build !windows

package main

import "io"

// consoleColours reports that the terminal shows the colour codes of the QR code of ranz device create -qr,
// as the terminals of Linux and macOS do, and has no mode to give back.
func consoleColours(io.Writer) (bool, func()) {
	return true, func() {}
}
