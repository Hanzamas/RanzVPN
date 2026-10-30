package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ranz tray is the tray icon of a laptop (SDN-55, #248; ADR-0011 amendment of 2026-10-22: the tray is a subcommand of
// the one ranz.exe, and a server does not start it):
//
//	ranz tray [flags]                    the icon in the notification area of the logged-in user: its colour and its
//	                                     tooltip show the status of the Node of this PC, and its menu signs the user in at the
//	                                     Controller in the browser, turns Ranz on and off and chooses the exit node
//	ranz tray [flags] status             print what the icon shows and what its menu lists, and exit with 3 when the
//	                                     Node service does not answer
//	ranz tray [flags] login [-device]    do what the menu item Sign in does, with the page of the browser, or with a device
//	                                     code that the user types on another device
//	ranz tray [flags] up | down          turn the client role of the Node on or off
//	ranz tray [flags] exit NAME [VRF]    choose the exit node NAME (in the VRF, when it is one in several)
//	ranz tray [flags] exit none          send the traffic of this PC out directly again
//
// The tray is only a face of the Node service ranzvpnserver, which servers run too. It talks to it on the pipe of the
// logged-in user (\\.\pipe\ranz-node-client, or the pipe that the Client setting names), which the interactive users may
// open and no one on the network: the commands are status, up, down, exit, key and enrol (src/Cedar/NodeClient.c). The
// sign-in is the browser login of SDN-32 (login.go): the tray takes the public half of the static key of the Node, the
// user signs in on the authorization page, the Controller makes the Node a device of the user, and the Node takes the
// keys of the Controller, as ranz node login gives them, but through enrol, which the Node takes only while it has no
// Controller settings, so a user without administrator rights cannot move a Node that an administrator joined. Without the
// Node service the tray says so, with the way to start it, and fails in no other way. The verbs are what the tests and the
// tracer of the CI run, since a window cannot be clicked there.
//
// Flags:
//
//	-server URL           the Controller to sign in at, RANZ_SERVER by default; without it, the Controller of the Node
//	-tls-fingerprint HEX  the TLS fingerprint of its certificate, RANZ_TLS_FINGERPRINT by default; without it, the one
//	                      in the Controller settings of the Node, and a certificate that the system trusts for another
//	-controller-dir DIR   the data directory of a Controller on this host, as for ranz login
//	-pipe NAME            the pipe of the logged-in user of the Node, ranz-node-client by default
//
// RANZ_BROWSER holds a command line that runs in place of the default browser, with the page as its last argument,
// for a host where no one sits at a browser (the tracer of the CI has a script sign in).
func init() {
	register("tray", func(args []string) int { return runTray(args, os.Stdout, os.Stderr) })
}

const trayUsage = `usage: ranz tray [-server URL] [-tls-fingerprint HEX] [-controller-dir DIR] [-pipe NAME] [status | login [-device] | up | down | exit NAME [VRF] | exit none]`

// The exit codes of the verbs: the Node service does not answer, as ranz node state says for a stopped service
const trayNoService = 3

// runTray runs ranz tray with the arguments that follow its name, and returns the exit code
func runTray(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz tray", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", os.Getenv("RANZ_SERVER"), "the Controller to sign in at; without it, the Controller of the Node")
	fingerprint := flags.String("tls-fingerprint", os.Getenv("RANZ_TLS_FINGERPRINT"), "accept only the Controller's certificate with this TLS fingerprint (ranz status prints it)")
	controllerDir := flags.String("controller-dir", os.Getenv("RANZ_CONTROLLER_DIR"), "the data directory of the Controller on this host, which holds the TLS fingerprint that a loopback address is checked by")
	pipe := flags.String("pipe", "", "the pipe of the logged-in user of the Node: a name, or \\\\.\\pipe\\name; ranz-node-client when it is left out")
	flags.Usage = func() {
		fmt.Fprintln(stderr, trayUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if command := os.Getenv("RANZ_BROWSER"); strings.TrimSpace(command) != "" {
		openBrowser = browserCommand(command)
	}
	a := newTrayApp(newClientPipe(*pipe), nodeServiceState)
	a.server, a.fingerprint, a.controllerDir = *server, *fingerprint, *controllerDir
	return a.run(flags.Args(), stdout, stderr)
}

// browserCommand returns an openBrowser that runs the command line command with the page as its last argument
func browserCommand(command string) func(string) error {
	return func(page string) error {
		fields := strings.Fields(command)
		c := exec.Command(fields[0], append(fields[1:], page)...)
		if err := c.Start(); err != nil {
			return err
		}
		go func() { _ = c.Wait() }()
		return nil
	}
}

// run does what the arguments after the flags say: the window of the tray when there are none, else a verb
func (a *trayApp) run(verb []string, stdout, stderr io.Writer) int {
	switch {
	case len(verb) == 0:
		return trayWindowRun(a, stderr)
	case verb[0] == "status" && len(verb) == 1:
		return a.printStatus(stdout, a.refresh())
	case verb[0] == "login":
		return a.runLogin(verb[1:], stdout, stderr)
	case (verb[0] == "up" || verb[0] == "down") && len(verb) == 1:
		return a.runCommand(verb[0], stdout, stderr)
	case verb[0] == "exit" && len(verb) == 2 && verb[1] == "none":
		return a.runCommand("exit none", stdout, stderr)
	case verb[0] == "exit" && (len(verb) == 2 || len(verb) == 3) && verb[1] != "none":
		if len(verb) == 3 {
			if _, err := strconv.ParseUint(verb[2], 10, 32); err != nil {
				break
			}
		}
		return a.runCommand(strings.Join(verb, " "), stdout, stderr)
	}
	fmt.Fprintln(stderr, trayUsage)
	return 2
}

// printStatus prints what the tray shows for v: its title, the lines under it and the exit nodes of its menu. It
// returns trayNoService when the Node service did not answer.
func (a *trayApp) printStatus(stdout io.Writer, v trayView) int {
	fmt.Fprintln(stdout, v.Title)
	for _, line := range v.Detail {
		fmt.Fprintln(stdout, line)
	}
	for _, e := range v.Exits {
		mark := " "
		if e.Chosen {
			mark = "*"
		}
		fmt.Fprintf(stdout, "%s %s: %s\n", mark, trayText("exitmenu"), e.Label)
	}
	if !v.Reachable {
		return trayNoService
	}
	return 0
}

// runCommand sends one of up, down and exit to the Node and prints the status that it answers
func (a *trayApp) runCommand(command string, stdout, stderr io.Writer) int {
	st, err := a.command(command)
	if err != nil {
		return a.fail(err, stderr)
	}
	return a.printStatus(stdout, statusView(st))
}

// fail says why a command did not work: the Node service that does not answer as the tray says it, any other error as it is
func (a *trayApp) fail(err error, stderr io.Writer) int {
	if errors.Is(err, errClientPipeMissing) || errors.Is(err, errClientPipeDenied) {
		v := a.viewOf(clientStatus{}, err)
		fmt.Fprintln(stderr, "ranz tray: "+v.Title)
		for _, line := range v.Detail {
			fmt.Fprintln(stderr, line)
		}
		return trayNoService
	}
	fmt.Fprintln(stderr, "ranz tray:", err)
	return 1
}

// runLogin signs the user in, with the browser or with -device a device code, and says how it went
func (a *trayApp) runLogin(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz tray login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	device := flags.Bool("device", false, "sign in with a device code, on any other device: for a PC without a browser")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, trayUsage)
		return 2
	}
	res, err := a.signIn(context.Background(), *device, stderr)
	if err != nil {
		return a.fail(err, stderr)
	}
	fmt.Fprintln(stdout, res.message())
	return 0
}
