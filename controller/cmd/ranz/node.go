package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/install"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// ranz node holds the verbs of a Node on its own PC (SDN-90, #395):
//
//	ranz node controller set <host:port> <key> <fingerprint>   the Controller settings of the Node
//	ranz node controller show
//	ranz node controller clear
//	ranz node key                                              the public half of its static key
//	ranz node state [-o json|table]                            what it does now (nodestate.go; SDN-91)
//
// The Node service ranzvpnserver does the work. It answers one command a line on its admin pipe,
// which only SYSTEM, the Administrators and the service itself may open, so the verbs need
// administrator rights. It is the one writer of its Configuration store, where it keeps the
// settings, and it makes and holds its static key in its own key set, where no other account can
// read it: the verbs never open the store or the key themselves. The service takes the settings at
// start, so after a change the verb restarts it, and says so.
func init() {
	register("node", func(args []string) int { return runNode(args, os.Stdout, os.Stderr, adminPipe{}) })
}

// nodeAdminPipe is the name of the admin pipe of the Node service (NODE_ADMIN_PIPE of
// src/Cedar/Node.h): \\.\pipe\ranz-node-admin.
const nodeAdminPipe = `\\.\pipe\ranz-node-admin`

// nodeAgent is the Node service as the verbs reach it: one command line and the one JSON line of
// its answer, and a restart of the service.
type nodeAgent interface {
	ask(command string) ([]byte, error)
	restart() error
}

// nodeControllerSettings are the Controller settings as the Node service answers them: the three
// values of nodecontroller.Settings, and the TLS fingerprints that the Controller sent the Node
// (SDN-92, controller_tls of its NodeConfig), the one of the certificate in use first. They are
// absent until the Controller sent them: TLSFingerprint is then the only one the Node accepts. The
// Node writes them; `ranz node controller set` never does.
type nodeControllerSettings struct {
	nodecontroller.Settings
	TLSFingerprints []string `json:"tlsFingerprints,omitempty"`
}

// nodeControllerAnswer is the answer of the Node service to the commands of the Controller
// settings: the settings, nil when it has none, and whether its control stream is open, at which
// Generation. Error is the reason of a command that the service refused.
type nodeControllerAnswer struct {
	Controller *nodeControllerSettings `json:"controller"`
	Connected  bool                    `json:"connected"`
	Generation uint64                  `json:"generation"`
	Error      string                  `json:"error,omitempty"`
}

// nodeKeyAnswer is the answer of the Node service to the command key: the public half of its static
// key, in base64, as the publicKey of a Node resource takes it. Nothing else of the answer is
// printed.
type nodeKeyAnswer struct {
	PublicKey string `json:"publicKey"`
	Error     string `json:"error,omitempty"`
}

const nodeUsage = `usage:
  ranz node controller set <host:port> <key> <fingerprint>
  ranz node controller show
  ranz node controller clear
  ranz node key
  ranz node state [-o json|table]
<host:port>, <key> and <fingerprint> are the TLS port, publicKey and tlsFingerprint of ranz status on the Controller.`

func runNode(args []string, stdout, stderr io.Writer, agent nodeAgent) int {
	switch {
	case len(args) == 1 && args[0] == "key":
		return nodeKey(stdout, stderr, agent)
	case len(args) == 2 && args[0] == "controller" && args[1] == "show":
		return nodeController(stdout, stderr, agent, "ranz node controller show", "controller", false)
	case len(args) == 2 && args[0] == "controller" && args[1] == "clear":
		return nodeController(stdout, stderr, agent, "ranz node controller clear", "controller clear", true)
	case len(args) == 5 && args[0] == "controller" && args[1] == "set":
		s, err := nodecontroller.Parse(args[2], args[3], args[4])
		if err != nil {
			fmt.Fprintf(stderr, "ranz node controller set: %v\n", err)
			return 2
		}
		return nodeController(stdout, stderr, agent, "ranz node controller set", "controller set "+s.Address+" "+s.PublicKey+" "+s.TLSFingerprint, true)
	case len(args) >= 1 && args[0] == "state":
		return nodeState(args[1:], stdout, stderr, agent)
	case len(args) == 1 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help"):
		fmt.Fprintln(stdout, nodeUsage)
		return 0
	}
	fmt.Fprintln(stderr, nodeUsage)
	return 2
}

// nodeController runs one command of the Controller settings and prints the answer as JSON. A
// command that changed the settings restarts the service.
func nodeController(stdout, stderr io.Writer, agent nodeAgent, name, command string, changes bool) int {
	var a nodeControllerAnswer
	if err := askNode(agent, command, &a); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	if a.Error != "" {
		fmt.Fprintf(stderr, "%s: the Node refused it: %s\n", name, a.Error)
		return 1
	}
	if changes {
		if err := agent.restart(); err != nil {
			fmt.Fprintf(stderr, "%s: the settings are stored, but the Node service %s did not restart, and takes them at its next start: %v\n", name, install.NodeServiceName, err)
			return 1
		}
		fmt.Fprintf(stderr, "%s: the Node service %s restarted to take the Controller settings\n", name, install.NodeServiceName)
		// Just restarted, its control stream is not open yet
		a.Connected, a.Generation = false, 0
	}
	return printNodeJSON(stdout, stderr, name, a)
}

// nodeKey prints the public half of the static key of the Node; the service makes the key first when
// no role needed it yet
func nodeKey(stdout, stderr io.Writer, agent nodeAgent) int {
	var a nodeKeyAnswer
	if err := askNode(agent, "key", &a); err != nil {
		fmt.Fprintf(stderr, "ranz node key: %v\n", err)
		return 1
	}
	if a.Error != "" {
		fmt.Fprintf(stderr, "ranz node key: the Node refused it: %s\n", a.Error)
		return 1
	}
	if key, err := base64.StdEncoding.DecodeString(a.PublicKey); err != nil || len(key) != nodecontroller.KeySize {
		fmt.Fprintf(stderr, "ranz node key: the Node answered a key that is not the base64 of %d bytes: %q\n", nodecontroller.KeySize, a.PublicKey)
		return 1
	}
	return printNodeJSON(stdout, stderr, "ranz node key", nodeKeyAnswer{PublicKey: a.PublicKey})
}

// askNode sends command to the Node service and decodes its answer into out
func askNode(agent nodeAgent, command string, out any) error {
	b, err := agent.ask(command)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("the Node service answered something that is not JSON: %w", err)
	}
	return nil
}

func printNodeJSON(stdout, stderr io.Writer, name string, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}
