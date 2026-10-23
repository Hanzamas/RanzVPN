package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
)

// notice is the NOTICE file of this directory: the licence text of each component inside ranz that
// asks for a copy of it with the program (ONE-1, #310; section 4 of the Apache License of GoBGP
// asks). It is part of the executable, so whoever has ranz.exe has the text.
//
//go:embed NOTICE
var notice string

func init() {
	register("notice", func(args []string) int { return runNotice(args, os.Stdout, os.Stderr) })
}

// runNotice is `ranz notice`: it prints the NOTICE to stdout and returns the exit code, 2 for
// arguments, which the command does not take.
func runNotice(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "ranz notice: unexpected arguments: %q\n", args)
		return 2
	}
	if _, err := io.WriteString(stdout, notice); err != nil {
		fmt.Fprintln(stderr, "ranz notice:", err)
		return 1
	}
	return 0
}
