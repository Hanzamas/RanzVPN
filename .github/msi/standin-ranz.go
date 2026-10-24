// A stand-in for ranz.exe in the MSI job that needs no C build (windows.yml, msi_standin; ONE-5, #314).
// The thin MSI only runs `ranz.exe install` and `ranz.exe uninstall -keep-ranz`, so what Windows
// Installer does with those two actions (the order of an upgrade, the refusal of a downgrade, the
// rollback, what an uninstall leaves) is proved in minutes with this program in the place of ranz.exe,
// before the signed ranz-node.exe of the C build exists. The job that follows the C build proves the
// real ranz.exe the same way (msi, .github/scripts/msi-install.ps1).
//
// It is built with the file named on the command line, as a program of its own, never as a package
// of the Go module (go build -ldflags "-X main.id=prev" -o ranz.exe standin-ranz.go).
//
// Each run appends one line to calls.log in %ProgramData%\Ranz MSI stand-in: the id that the build
// gave it (prev, cur) and its arguments, which tells the job which package's ranz.exe ran which
// action. install writes ranz-node.exe beside this program, as the real one writes the Node, and
// uninstall removes it. A file fail-install in that folder makes install exit 1, so that the MSI
// rolls back.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// id names the build, so that the log shows which package's ranz.exe ran.
var id = "unset"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "stand-in ranz: install or uninstall")
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stand-in ranz:", err)
		os.Exit(1)
	}
	work := filepath.Join(os.Getenv("ProgramData"), "Ranz MSI stand-in")
	if err := os.MkdirAll(work, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "stand-in ranz:", err)
		os.Exit(1)
	}
	calls, err := os.OpenFile(filepath.Join(work, "calls.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stand-in ranz:", err)
		os.Exit(1)
	}
	_, werr := fmt.Fprintf(calls, "%s %s\n", id, strings.Join(os.Args[1:], " "))
	if cerr := calls.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintln(os.Stderr, "stand-in ranz:", werr)
		os.Exit(1)
	}

	node := filepath.Join(filepath.Dir(self), "ranz-node.exe")
	switch os.Args[1] {
	case "install":
		if _, err := os.Stat(filepath.Join(work, "fail-install")); err == nil {
			fmt.Fprintln(os.Stderr, "stand-in ranz: install fails, as fail-install asks")
			os.Exit(1)
		}
		if err := os.WriteFile(node, []byte("the Node of "+id), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "stand-in ranz:", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := os.Remove(node); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "stand-in ranz:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "stand-in ranz: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
