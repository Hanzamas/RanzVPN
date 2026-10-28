package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// ranz node login (SDN-32, #226) enrols this Node as a device of the user who signs in:
//
//	ranz node login [-server URL] [-tls-fingerprint HEX] [-device] [-name NAME]
//
// The Node service gives the public half of its static key (as ranz node key does), and a browser login,
// or with -device a device code login that the user finishes on another device, takes the key to the
// Controller at -server. The user signs in there, and the Controller makes the Node resource of the key,
// a device of that user, under -name or a name that it draws. The answer of the login holds the keys of
// the Controller: with the host and the port of -server they become the Controller settings of the Node
// (as ranz node controller set makes them), and the service restarts to take them, so the Node joins on
// its next control stream. The verb needs administrator rights, as every verb of ranz node does.

const nodeLoginUsage = `usage: ranz node login [-server URL] [-tls-fingerprint HEX] [-device] [-name NAME]`

// nodeLoginAnswer is what ranz node login prints: the Node resource of the enrolment, its user and the
// revision that holds it, and the Controller settings of the Node.
type nodeLoginAnswer struct {
	Node       string                  `json:"node"`
	User       string                  `json:"user"`
	Revision   uint64                  `json:"revision"`
	Controller *nodeControllerSettings `json:"controller"`
}

// nodeLogin runs ranz node login with the arguments that follow login, and returns the exit code.
func nodeLogin(ctx context.Context, args []string, stdout, stderr io.Writer, agent nodeAgent) int {
	flags := flag.NewFlagSet("ranz node login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server, fingerprint := connectionFlags(flags)
	device := flags.Bool("device", false, "sign in with a device code, on any other device: for a Node without a browser")
	name := flags.String("name", "", "the name of the Node resource of this Node; the Controller draws one when it is left out")
	flags.Usage = func() {
		fmt.Fprintln(stderr, nodeLoginUsage)
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
		fmt.Fprintln(stderr, "ranz node login:", err)
		return 2
	}
	var k nodeKeyAnswer
	if err := askNode(agent, "key", &k); err != nil {
		fmt.Fprintln(stderr, "ranz node login:", err)
		return 1
	}
	key, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if k.Error != "" || err != nil || len(key) != nodecontroller.KeySize {
		fmt.Fprintf(stderr, "ranz node login: the Node gave no static key: %q %s\n", k.PublicKey, k.Error)
		return 1
	}
	lc, err := loginClient(*server, *fingerprint)
	if err != nil {
		fmt.Fprintln(stderr, "ranz node login:", err)
		return 1
	}
	d := &login.Device{Key: key, Name: *name}
	var res login.Result
	if *device {
		res, err = deviceLogin(ctx, lc, d, stderr)
	} else {
		res, err = browserLogin(ctx, lc, d, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ranz node login:", err)
		return 1
	}
	if res.Controller == nil {
		fmt.Fprintf(stderr, "ranz node login: the Controller enrolled the Node as %s, and gave none of its keys\n", res.Node)
		return 1
	}
	fp := res.Controller.TLSFingerprint
	if fp == "" {
		fp = *fingerprint
	}
	s, err := nodecontroller.Parse(address, res.Controller.PublicKey, fp)
	if err != nil {
		fmt.Fprintf(stderr, "ranz node login: the Node is enrolled as %s, and its Controller settings cannot be made: %v\n", res.Node, err)
		return 1
	}
	var a nodeControllerAnswer
	if err := askNode(agent, "controller set "+s.Address+" "+s.PublicKey+" "+s.TLSFingerprint, &a); err != nil {
		fmt.Fprintf(stderr, "ranz node login: the Node is enrolled as %s, and it did not take its Controller settings: %v\n", res.Node, err)
		return 1
	}
	if a.Error != "" {
		fmt.Fprintf(stderr, "ranz node login: the Node is enrolled as %s, and it refused its Controller settings: %s\n", res.Node, a.Error)
		return 1
	}
	if err := agent.restart(); err != nil {
		fmt.Fprintf(stderr, "ranz node login: the settings are stored, but the Node service %s did not restart, and takes them at its next start: %v\n", install.NodeServiceName, err)
		return 1
	}
	fmt.Fprintf(stderr, "ranz node login: the Node is enrolled as %s of user %s, and the Node service %s restarted to join\n", res.Node, res.User, install.NodeServiceName)
	return printNodeJSON(stdout, stderr, "ranz node login", nodeLoginAnswer{Node: res.Node, User: res.User, Revision: res.Revision, Controller: a.Controller})
}

// controlAddress returns the address that the Node opens its control stream to: the host and the port
// of the URL server, where the control stream shares the TLS port with the API (ADR-0035), 443 when the
// URL names none.
func controlAddress(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("-server %q is not the https URL of a Controller", server)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}
