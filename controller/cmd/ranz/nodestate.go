package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
)

// ranz node state shows what the Node service of this PC does now (SDN-91, #396):
//
//	ranz node state [-o json|table]
//
// It asks the running service with the command state on its admin pipe, the local channel that only
// SYSTEM, the Administrators and the service itself may open (NodeState.c answers it): its Roles, its
// control stream (the Controller, since when it is connected and the acknowledged Generation, or why
// it is not), its Wintun adapters with their VRFs and addresses, the Noise sessions of its peers
// with their transport and age, and its listeners. JSON, the default, is the answer of the service
// with the field service; a table is a few lines for a person. For a stopped service the verb says
// that the service is stopped, with the exit code 3, as the status of a stopped service is in
// scripts.

// errNodeStopped is the error of the admin pipe when the Node service does not run
var errNodeStopped = errors.New("the Node service " + install.NodeServiceName + " is stopped")

// nodeStateStopped is the exit code of ranz node state for a stopped service
const nodeStateStopped = 3

// nodeStateAnswer is the answer of the Node service to the command state, and the field service:
// running, or stopped when no service answered.
type nodeStateAnswer struct {
	Service       string             `json:"service"`
	Running       bool               `json:"running"`
	Roles         string             `json:"roles"`
	Name          string             `json:"name"`
	ControlStream nodeControlStream  `json:"controlStream"`
	Adapters      []nodeStateAdapter `json:"adapters"`
	Sessions      []nodeStateSession `json:"sessions"`
	NumPeers      int                `json:"numPeers"`
	Listeners     nodeStateListeners `json:"listeners"`
	Error         string             `json:"error,omitempty"`
}

// nodeControlStream is the control stream of a Node: its Controller and since when it is connected
// at which Generation, or why it is not and when it tries again.
type nodeControlStream struct {
	Set              bool   `json:"set"`
	Controller       string `json:"controller"`
	Connected        bool   `json:"connected"`
	ConnectedSeconds uint64 `json:"connectedSeconds"`
	Generation       uint64 `json:"generation"`
	Why              string `json:"why"`
	NextRetryMs      uint64 `json:"nextRetryMs"`
}

// nodeStateAdapter is one Wintun adapter of a Node: its VRF and the addresses of the Node in it.
type nodeStateAdapter struct {
	VRF            uint32   `json:"vrf"`
	Name           string   `json:"name"`
	InterfaceIndex uint32   `json:"interfaceIndex"`
	Addresses      []string `json:"addresses"`
}

// nodeStateSession is one peer of a Node and its Noise session.
type nodeStateSession struct {
	Peer       string `json:"peer"`
	Up         bool   `json:"up"`
	Transport  string `json:"transport"`
	AgeSeconds uint64 `json:"ageSeconds"`
}

// nodeStateListeners are the listeners of a Node: the data transport of its overlay, the front door
// and QUIC of its Listener, and the UDP port of the relay role, 0 for one that does not run.
type nodeStateListeners struct {
	Overlay   string `json:"overlay"`
	FrontDoor struct {
		Listener string `json:"listener"`
		Running  bool   `json:"running"`
		TCPPort  int    `json:"tcpPort"`
		QUICPort int    `json:"quicPort"`
		Fallback bool   `json:"fallback"`
		Error    string `json:"error"`
	} `json:"frontDoor"`
	RelayUDPPort int `json:"relayUdpPort"`
}

// nodeState runs ranz node state with args, the arguments after state.
func nodeState(args []string, stdout, stderr io.Writer, agent nodeAgent) int {
	flags := flag.NewFlagSet("node state", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("o", "json", "the form of the answer: json, as the Node service answers, or table")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || (*format != "json" && *format != "table") {
		fmt.Fprintln(stderr, nodeUsage)
		return 2
	}
	var a nodeStateAnswer
	err := askNode(agent, "state", &a)
	switch {
	case errors.Is(err, errNodeStopped):
		a = nodeStateAnswer{Service: "stopped"}
		if *format == "table" {
			fmt.Fprintf(stdout, "The Node service %s is stopped: start it with Start-Service %s\n", install.NodeServiceName, install.NodeServiceName)
		} else if code := printNodeJSON(stdout, stderr, "ranz node state", a); code != 0 {
			return code
		}
		return nodeStateStopped
	case err != nil:
		fmt.Fprintf(stderr, "ranz node state: %v\n", err)
		return 1
	case a.Error != "":
		fmt.Fprintf(stderr, "ranz node state: the Node refused it: %s\n", a.Error)
		return 1
	}
	a.Service = "running"
	if *format == "json" {
		return printNodeJSON(stdout, stderr, "ranz node state", a)
	}
	if err := nodeStateTable(stdout, a); err != nil {
		fmt.Fprintf(stderr, "ranz node state: %v\n", err)
		return 1
	}
	return 0
}

// nodeStateTable prints the state of a Node for a person.
func nodeStateTable(out io.Writer, a nodeStateAnswer) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	name := a.Name
	if name == "" {
		name = "(no name: no desired state yet)"
	}
	fmt.Fprintf(tw, "Node\t%s\n", name)
	fmt.Fprintf(tw, "Service\t%s\n", install.NodeServiceName+" running")
	fmt.Fprintf(tw, "Roles\t%s\n", a.Roles)
	cs := a.ControlStream
	switch {
	case cs.Connected:
		fmt.Fprintf(tw, "Control stream\tconnected to %s for %ds, Generation %d\n", cs.Controller, cs.ConnectedSeconds, cs.Generation)
	case cs.Set:
		fmt.Fprintf(tw, "Control stream\tnot connected to %s: %s; the next attempt in %d ms\n", cs.Controller, cs.Why, cs.NextRetryMs)
	default:
		fmt.Fprintf(tw, "Control stream\tnone: %s\n", cs.Why)
	}
	l := a.Listeners
	fmt.Fprintf(tw, "Listeners\toverlay %s; front door %s; relay %s\n", orNone(l.Overlay), frontDoor(l), portOrNone("UDP", l.RelayUDPPort))
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VRF\tADAPTER\tINTERFACE\tADDRESSES")
	for _, ad := range a.Adapters {
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\n", ad.VRF, ad.Name, ad.InterfaceIndex, orNone(strings.Join(ad.Addresses, ", ")))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tSESSION\tTRANSPORT\tAGE")
	for _, s := range a.Sessions {
		if s.Up {
			fmt.Fprintf(tw, "%s\tup\t%s\t%ds\n", s.Peer, s.Transport, s.AgeSeconds)
		} else {
			fmt.Fprintf(tw, "%s\tdown\t-\t-\n", s.Peer)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if a.NumPeers > len(a.Sessions) {
		_, err := fmt.Fprintf(out, "and %d peers more\n", a.NumPeers-len(a.Sessions))
		return err
	}
	return nil
}

// frontDoor is the front door and QUIC of the Listener of a Node, in the words of the table.
func frontDoor(l nodeStateListeners) string {
	f := l.FrontDoor
	switch {
	case f.Running:
		s := portOrNone("TCP", f.TCPPort) + " and QUIC " + portOrNone("UDP", f.QUICPort)
		if f.Fallback {
			s += " (TCP 443 was taken)"
		}
		return s
	case f.Error != "":
		return "not running: " + f.Error
	}
	return "none"
}

func portOrNone(protocol string, port int) string {
	if port == 0 {
		return "none"
	}
	return protocol + " " + strconv.Itoa(port)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
