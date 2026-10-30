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
// with their transport and age, how it reaches each peer (on its stream session or through a Relay)
// with the datagrams each way, its datagram path with the Upgrades and the Fallbacks of its Paths
// and its port mapping (CORE-S5-6, #412) and its punches (CORE-S5-7, #413), and its listeners. JSON, the default, is the answer of the service
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
	// DatagramPath is nil for a Node service from before the field (CORE-S5-6, #412)
	DatagramPath *nodeStateDatagramPath `json:"datagramPath,omitempty"`
	Listeners    nodeStateListeners     `json:"listeners"`
	Error        string                 `json:"error,omitempty"`
}

// nodeStateDatagramPath is the peer agent of a Node (CORE-S5-5, #411; CORE-S5-6, #412): whether its
// peer layer runs, with ICE or without, and on which UDP port; the Relays of its state; the Upgrades
// of its Paths to the direct path that ICE validated or a punch met and their Fallbacks to the Relay
// since the Node started; the port mapping of its home gateway (off, asking, mapped or failed) with
// the public address that the gateway granted; and its punches (CORE-S5-7, #413): its NAT as the
// answers of its binds show it (unknown, cone, sequential or random), and its attempts at a direct
// path to a peer behind a symmetric NAT, the ones that met, and the ones whose prediction failed. The
// punches are nil for a Node service from before them.
type nodeStateDatagramPath struct {
	Running        bool    `json:"running"`
	ICE            bool    `json:"ice"`
	UDPPort        int     `json:"udpPort"`
	Relays         int     `json:"relays"`
	Upgrades       uint64  `json:"upgrades"`
	Fallbacks      uint64  `json:"fallbacks"`
	PortMapping    string  `json:"portMapping"`
	MappedAddress  string  `json:"mappedAddress"`
	NAT            string  `json:"nat,omitempty"`
	PunchAttempts  *uint64 `json:"punchAttempts,omitempty"`
	PunchSuccesses *uint64 `json:"punchSuccesses,omitempty"`
	PunchFailures  *uint64 `json:"punchFailures,omitempty"`
}

// punches is the NAT and the punches of a Node in the words of the table, and false for a Node
// service from before them.
func (d nodeStateDatagramPath) punches() (string, bool) {
	if d.PunchAttempts == nil || d.PunchSuccesses == nil || d.PunchFailures == nil {
		return "", false
	}
	return fmt.Sprintf("NAT %s; %d attempts, %d met, %d failed", d.NAT, *d.PunchAttempts, *d.PunchSuccesses, *d.PunchFailures), true
}

// words is the datagram path of a Node in the words of the table.
func (d nodeStateDatagramPath) words() string {
	if !d.Running {
		return "not running: no desired state names a Relay"
	}
	ice := "without ICE"
	if d.ICE {
		ice = "with ICE"
	}
	mapping := d.PortMapping
	if d.MappedAddress != "" {
		mapping += " to " + d.MappedAddress
	}
	return fmt.Sprintf("%s, %s, %d Relays; %d Upgrades and %d Fallbacks; port mapping %s", portOrNone("UDP", d.UDPPort), ice, d.Relays, d.Upgrades, d.Fallbacks, mapping)
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

// nodeStateSession is one peer of a Node and its Noise session, and how the Node reaches it
// (CORE-S5-5, #411): its path, stream while its session is up, relay or direct on the datagram path
// of the peer agent, or none, with the records of the overlay that went each way on that path.
type nodeStateSession struct {
	Peer         string `json:"peer"`
	Up           bool   `json:"up"`
	Transport    string `json:"transport"`
	AgeSeconds   uint64 `json:"ageSeconds"`
	Path         string `json:"path"`
	DatagramsOut uint64 `json:"datagramsOut"`
	DatagramsIn  uint64 `json:"datagramsIn"`
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
		Decoy    string `json:"decoy"`
		Error    string `json:"error"`
		// Refused is what the limits for a source of the two listeners refused since the Node started
		// (AUD1-DT-3, #451): the front door on TCP, and QUIC on UDP with what msquic does about a flood.
		Refused struct {
			TCP  nodeStateLimits `json:"tcp"`
			QUIC struct {
				nodeStateLimits
				Available        bool   `json:"available"`
				RetryMemoryLimit uint32 `json:"retryMemoryLimit"`
				Retrying         bool   `json:"retrying"`
				Retries          uint64 `json:"retries"`
			} `json:"quic"`
		} `json:"refused"`
	} `json:"frontDoor"`
	RelayUDPPort int `json:"relayUdpPort"`
}

// nodeStateLimits is what the limits for a source of one listener hold and refused: the connections
// that wait for their handshake now, the sources it counts, the connections it admitted, and the
// refusals by reason (SourceLimit.h).
type nodeStateLimits struct {
	Pending          uint32 `json:"pending"`
	Sources          uint32 `json:"sources"`
	Admitted         uint64 `json:"admitted"`
	RefusedFull      uint64 `json:"refusedFull"`
	RefusedSource    uint64 `json:"refusedSource"`
	RefusedRate      uint64 `json:"refusedRate"`
	RefusedHandshake uint64 `json:"refusedHandshake"`
}

// refusals is the sum of the refusals of one listener.
func (s nodeStateLimits) refusals() uint64 {
	return s.RefusedFull + s.RefusedSource + s.RefusedRate + s.RefusedHandshake
}

// limits is a listener's refusals in the words of the table: how many, and for which reason.
func (s nodeStateLimits) limits() string {
	return fmt.Sprintf("%d refused (%d over the cap in all, %d over the cap of a source, %d over the rate of connections, %d over the rate of handshakes), %d waiting for their handshake",
		s.refusals(), s.RefusedFull, s.RefusedSource, s.RefusedRate, s.RefusedHandshake, s.Pending)
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
	if d := a.DatagramPath; d != nil {
		fmt.Fprintf(tw, "Datagram path\t%s\n", d.words())
		if words, ok := d.punches(); ok && d.Running {
			fmt.Fprintf(tw, "Punches\t%s\n", words)
		}
	}
	l := a.Listeners
	fmt.Fprintf(tw, "Listeners\toverlay %s; front door %s; relay %s\n", orNone(l.Overlay), frontDoor(l), portOrNone("UDP", l.RelayUDPPort))
	if l.FrontDoor.Running {
		r := l.FrontDoor.Refused
		fmt.Fprintf(tw, "Refused on TCP\t%s\n", r.TCP.limits())
		if r.QUIC.Available {
			fmt.Fprintf(tw, "Refused on QUIC\t%s; retry %s, %d retries sent, limit %d/65535 of the memory\n", r.QUIC.limits(), retryWord(r.QUIC.Retrying), r.QUIC.Retries, r.QUIC.RetryMemoryLimit)
		}
	}
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
	fmt.Fprintln(tw, "PEER\tSESSION\tTRANSPORT\tAGE\tPATH\tDATAGRAMS")
	for _, s := range a.Sessions {
		if s.Up {
			fmt.Fprintf(tw, "%s\tup\t%s\t%ds\t%s\t%s\n", s.Peer, s.Transport, s.AgeSeconds, orNone(s.Path), datagrams(s))
		} else {
			fmt.Fprintf(tw, "%s\tdown\t-\t-\t%s\t%s\n", s.Peer, orNone(s.Path), datagrams(s))
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
		if f.Decoy != "" {
			return s + ", decoy " + f.Decoy
		}
		return s + ", no decoy"
	case f.Error != "":
		return "not running: " + f.Error
	}
	return "none"
}

// datagrams is what went each way on the datagram path of a peer, in the words of the table.
func datagrams(s nodeStateSession) string {
	return fmt.Sprintf("%d out, %d in", s.DatagramsOut, s.DatagramsIn)
}

func portOrNone(protocol string, port int) string {
	if port == 0 {
		return "none"
	}
	return protocol + " " + strconv.Itoa(port)
}

// retryWord is the state of the retry of msquic in the words of the table: it is set on every start, and it answers new
// connections once the handshakes hold more memory than its limit.
func retryWord(answering bool) string {
	if answering {
		return "answering now"
	}
	return "armed"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
