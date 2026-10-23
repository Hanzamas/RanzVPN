// Package doctor is the system check of ranz (SDN-53, #246): `ranz doctor` runs the six checks that
// the Check command of vpncmd ran, to tell whether Ranz can run on a host. Each check works the
// part of the system that Ranz depends on: the clock, memory, text, the file system, threads and
// TLS over the network. They are the checks of vpncmd (the kernel, memory, strings, file system,
// thread and network procedures of Command.c) written for the Go program that ranz is: a check
// that vpncmd made of the runtime of its own, such as its allocator, is made of the memory of the
// process, and the network check serves TLS on the loopback address with a certificate that it
// makes with certgen.
package doctor

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// The titles of the checks, as the Check command of vpncmd named them.
const (
	TitleKernel     = "Kernel System"
	TitleMemory     = "Memory Operation System"
	TitleStrings    = "ANSI / Unicode string processing system"
	TitleFileSystem = "File system"
	TitleThread     = "Thread processing system"
	TitleNetwork    = "Network system"
)

const (
	// Heading is what the report starts with: its title, and the note that tells what a pass means.
	Heading = "Ranz operation environment check\n\n" +
		"If this check passes on a system, Ranz can most likely run on it. The check takes a few seconds.\n\n"
	// ResultPass is the verdict when every check passed.
	ResultPass = "All checks passed. It is most likely that Ranz can operate normally on this system."
	// ResultFail is the verdict when a check failed.
	ResultFail = "Some checks failed. Please check the operation environment of this system. If Ranz were to run on this system, troubles may occur."
)

// Check is one check of the system: its title and the run, which returns nil when the check
// passes and the reason when it fails.
type Check struct {
	Title string
	Run   func(ctx context.Context) error
}

// Checks returns the six checks of the Check command of vpncmd, in its order.
func Checks() []Check {
	return []Check{
		{TitleKernel, checkKernel},
		{TitleMemory, checkMemory},
		{TitleStrings, checkStrings},
		{TitleFileSystem, checkFileSystem},
		{TitleThread, checkThreads},
		{TitleNetwork, checkNetwork},
	}
}

// Run runs the checks in order and writes the report to w: a line for each check, with the reason
// under one that failed, and the verdict. It runs every check, also after one that failed, and
// reports whether all of them passed. A ctx that ends stops the run.
func Run(ctx context.Context, w io.Writer, checks []Check) bool {
	io.WriteString(w, Heading)
	failed := 0
	for _, c := range checks {
		if ctx.Err() != nil {
			fmt.Fprintf(w, "\nInterrupted before '%s'.\n", c.Title)
			return false
		}
		fmt.Fprintf(w, "Checking '%s'... ", c.Title)
		if err := c.Run(ctx); err != nil {
			failed++
			fmt.Fprintf(w, "Fail\n    %s\n", strings.ReplaceAll(err.Error(), "\n", "\n    "))
			continue
		}
		fmt.Fprintln(w, "Pass")
	}
	fmt.Fprintln(w)
	if failed > 0 {
		fmt.Fprintln(w, ResultFail)
		return false
	}
	fmt.Fprintln(w, ResultPass)
	return true
}
