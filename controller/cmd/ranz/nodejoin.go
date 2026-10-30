package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/install"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// ranz node join (SDN-58, #251) enrols this Node as a device of the user who made a join token in the portal:
//
//	ranz node join [-server URL] [-tls-fingerprint HEX] [-controller-dir DIR] [-token-file FILE] [-name NAME]
//
// A user makes the join token on the page Join tokens of the portal of the Controller, for a device that cannot
// sign in itself, such as a Node without a browser, and the portal shows the command with the secret, once:
// `echo SECRET | ranz node join -server URL`. The verb reads the secret from -token-file, from standard input when
// the flag is left out, and never from an argument, so that no process list and no history of a shell holds it.
// Like ranz node login it takes the public half of the static key of the Node from the Node service, and takes it
// with the secret to the Controller at -server (POST /api/v1/login/join), where no user signs in: the Controller
// makes the Node resource of the key, a device of the user of the token, under -name, the name that the token
// carries or a name that it draws, and spends the token. The answer holds the keys of the Controller: with the host
// and the port of -server they become the Controller settings of the Node (as ranz node controller set makes
// them), and the service restarts to take them, so the Node joins on its next control stream. The secret works
// once and ends a day after it was made. The verb needs administrator rights, as every verb of ranz node does, and
// it asks the Node service for its key before it uses the secret, so a host where it cannot work leaves the token
// to be used elsewhere.

const nodeJoinUsage = `usage: ranz node join [-server URL] [-tls-fingerprint HEX] [-controller-dir DIR] [-token-file FILE] [-name NAME]`

// maxJoinTokenFile bounds what is read of the file or the pipe that holds a join token, which is one short line.
const maxJoinTokenFile = 4096

// nodeJoin runs ranz node join with the arguments that follow join, and returns the exit code. The join token
// comes from stdin, or from the file of -token-file. It prints what ranz node login prints (nodeLoginAnswer).
func nodeJoin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, agent nodeAgent) int {
	flags := flag.NewFlagSet("ranz node join", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server, fingerprint, controllerDir := connectionFlags(flags)
	tokenFile := flags.String("token-file", "-", "the file that holds the join token, one line; - for standard input")
	name := flags.String("name", "", "the name of the Node resource of this Node; the name of the join token, or one that the Controller draws, when it is left out")
	flags.Usage = func() {
		fmt.Fprintln(stderr, nodeJoinUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return 2
	}
	address, err := controlAddress(*server)
	if err != nil {
		fmt.Fprintln(stderr, "ranz node join:", err)
		return 2
	}
	secret, err := readJoinToken(stdin, *tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, "ranz node join:", err)
		return 1
	}
	key, err := nodeStaticKey(agent)
	if err != nil {
		fmt.Fprintln(stderr, "ranz node join:", err)
		return 1
	}
	lc, err := loginClient(*server, *fingerprint, *controllerDir)
	if err != nil {
		fmt.Fprintln(stderr, "ranz node join:", err)
		return 1
	}
	res, err := lc.Join(ctx, secret, login.Device{Key: key, Name: *name})
	if err != nil {
		fmt.Fprintln(stderr, "ranz node join:", err)
		return 1
	}
	if res.Controller == nil {
		fmt.Fprintf(stderr, "ranz node join: the Controller enrolled the Node as %s, and gave none of its keys\n", res.Node)
		return 1
	}
	fp := res.Controller.TLSFingerprint
	if fp == "" {
		fp = *fingerprint
	}
	s, err := nodecontroller.Parse(address, res.Controller.PublicKey, fp)
	if err != nil {
		fmt.Fprintf(stderr, "ranz node join: the Node is enrolled as %s, and its Controller settings cannot be made: %v\n", res.Node, err)
		return 1
	}
	var a nodeControllerAnswer
	if err := askNode(agent, "controller set "+s.Address+" "+s.PublicKey+" "+s.TLSFingerprint, &a); err != nil {
		fmt.Fprintf(stderr, "ranz node join: the Node is enrolled as %s, and it did not take its Controller settings: %v\n", res.Node, err)
		return 1
	}
	if a.Error != "" {
		fmt.Fprintf(stderr, "ranz node join: the Node is enrolled as %s, and it refused its Controller settings: %s\n", res.Node, a.Error)
		return 1
	}
	if err := agent.restart(); err != nil {
		fmt.Fprintf(stderr, "ranz node join: the settings are stored, but the Node service %s did not restart, and takes them at its next start: %v\n", install.NodeServiceName, err)
		return 1
	}
	fmt.Fprintf(stderr, "ranz node join: the Node is enrolled as %s of user %s, and the Node service %s restarted to join\n", res.Node, res.User, install.NodeServiceName)
	return printNodeJSON(stdout, stderr, "ranz node join", nodeLoginAnswer{Node: res.Node, User: res.User, Revision: res.Revision, Controller: a.Controller})
}

// readJoinToken reads the secret of a join token, one line, from the file name, or from in for "-", and checks
// that it has the form of one, so that a wrong paste is told before the Node service or the Controller is asked
// anything. The secret is in none of the errors.
func readJoinToken(in io.Reader, name string) (string, error) {
	r := in
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return "", fmt.Errorf("the join token: %w", err)
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxJoinTokenFile))
	if err != nil {
		return "", fmt.Errorf("the join token: %w", err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	secret := strings.TrimSpace(line)
	switch {
	case secret == "":
		return "", errors.New("no join token: pipe its secret in, or give the file that holds it with -token-file (the portal shows the secret once, when the token is made)")
	case !controller.ValidJoinToken(secret):
		return "", fmt.Errorf("that is not the secret of a join token, which starts with %s: make a join token in the portal, and give its secret", controller.JoinTokenPrefix)
	}
	return secret, nil
}

// nodeStaticKey asks the Node service for the public half of the static key of the Node, and returns its bytes.
func nodeStaticKey(agent nodeAgent) ([]byte, error) {
	var k nodeKeyAnswer
	if err := askNode(agent, "key", &k); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if k.Error != "" || err != nil || len(key) != nodecontroller.KeySize {
		return nil, fmt.Errorf("the Node gave no static key: %q %s", k.PublicKey, k.Error)
	}
	return key, nil
}
