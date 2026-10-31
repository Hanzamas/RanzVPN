//go:build windows

package main

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// consoleColours turns on the colour codes of the console that w is, for the QR code of ranz device create
// -qr, and reports whether w shows them, with the function that gives the console its mode back after
// (SDN-82-R1). A console of Windows prints colour codes as text unless its mode has
// ENABLE_VIRTUAL_TERMINAL_PROCESSING, which the classic console has not by default: the codes would come
// before each line, and the code would show inverted, which many scanners do not read. A console that
// refuses that mode, an old one, gets the code without colour codes (qrText). What is no console, a file or
// a pipe, takes the codes as they are.
func consoleColours(w io.Writer) (bool, func()) {
	f, ok := w.(*os.File)
	if !ok {
		return true, func() {}
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil || mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true, func() {}
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false, func() {}
	}
	return true, func() { _ = windows.SetConsoleMode(h, mode) }
}
