// Command ranz is the one executable of the Ranz Go programs (ADR-0011 amendment of 2026-10-22,
// ONE-1 #310). It is a multi-call binary: when the first argument names a subcommand, ranz runs
// that, and otherwise the arguments are a command of the controller's HTTP API (#176 "Intent
// API"), the CLI below.
//
// Subcommands, each registered by a file of its own (subcommand.go):
//
//	ranz controller [flags]   the Controller service with its web UI: run, install, uninstall,
//	                          reset-admin, backup and restore (package controllercmd)
//	ranz bgp -pipe NAME       the BGP sidecar of a Node, which the Node starts (package bgpcmd)
//	ranz mimic -pipe NAME     the mimicry sidecar of a Node, REALITY and uTLS, which the Node starts; ranz
//	                          mimic -keygen prints the key pair of a server (package mimic, CORE-P2-1 #85)
//	ranz install [-controller [-admin-from PREFIXES|any]] [-no-xdp] [-no-wireguard]
//	                          write the Node payload, Wintun, WireGuardNT (-no-wireguard leaves it
//	                          out, SDN-80 #375) and the NOTICE into Program Files, install the SeLow
//	                          driver and the XDP runtime (x64 only; -no-xdp leaves the XDP runtime
//	                          out), register and start the Node service, and, with -controller, the
//	                          Controller service too (package install, ONE-2 #311, ONE-3 #312)
//	ranz uninstall [-keep-ranz]
//	                          stop and remove the services, the drivers that install put on the
//	                          machine and the files it made, keeping the Node's data directory
//	                          (package install, ONE-2 #311, ONE-3 #312); with -keep-ranz, leave
//	                          ranz.exe and the Ranz folder for the MSI to remove (ONE-5 #314)
//	ranz notice               print the NOTICE: the licence texts of what ranz carries
//	ranz version              print the version, which is the same for every subcommand
//	ranz cert [flags]         make a self-signed or CA-signed certificate and its key, in files or in the
//	                          key storage provider (SDN-53, #246; the successor of vpncmd MakeCert)
//	ranz test throughput ...  measure the rate between two nodes: -listen runs the test server on one,
//	                          a host and port runs the client on another (the successor of vpncmd
//	                          TrafficServer and TrafficClient)
//	ranz doctor [-bundle [-o FILE]]
//	                          run the system check (the successor of vpncmd Check); with -bundle, also
//	                          write the diagnostics bundle of this host, a ZIP archive with the logs, the
//	                          configuration and the status of its Node and Controller and no secret (SDN-54, #247)
//	ranz explain [flags] A B  walk the compiled model of the controller for a packet from A to B and name each VRF,
//	                          route, 1:1 NAT rule, link and rule of the policy that it meets (explain.go, SDN-15 #191)
//	ranz login [flags]        sign in as a user that holds an API role and take its user token: in the browser, with
//	                          a device code (-device) or with the password of the user (-user); ranz node login enrols
//	                          the Node of this PC as a device of the user who signs in (login.go, SDN-32 #226)
//	ranz tray [flags] [status | login | up | down | exit NAME | exit none]
//	                          the tray icon of a laptop: the status of the Node of this PC, sign-in in the
//	                          browser and the choice of the exit node; the verbs do the same with no window
//	                          (tray.go, SDN-55 #248)
//
// Usage of the CLI:
//
//	ranz [flags] apply -f FILE                 apply the resources of an intent document (YAML or JSON, - for standard input)
//	ranz [flags] apply -f FILE -confirm DURATION
//	                                           the same, rolled back by the controller after DURATION (for example 5m) unless confirmed
//	ranz [flags] confirm REVISION              confirm the revision of an apply with -confirm, so that it stays
//	ranz [flags] diff [FROM [TO]]              print the resource changes from revision FROM to revision TO (the latest when left
//	                                           out); with no revision, the changes of the latest revision
//	ranz [flags] rollback REVISION             make the intent of REVISION the intent again, as a new revision (0 is the empty intent)
//	ranz [flags] get resources                 print the intent
//	ranz [flags] get nodes                     print the generation of each node, the one it acknowledged and its Capabilities
//	ranz [flags] get revisions                 print every revision of the intent
//	ranz [flags] get revision ID               print one revision with its resources
//	ranz [flags] get events                    print the events, such as an automatic rollback or a pool near exhaustion
//	ranz [flags] get ipam                      print how full each address pool is, and the routes of the gateway LAN subnets
//	ranz [flags] get leases                    print the leases of the DHCP responders of the L2 Networks
//	ranz [flags] get audit [filters] [-o json|table]
//	                                           print the records of the audit log, oldest first, with the filters of the API:
//	                                           -kind, -actor, -since, -until, -after and -limit (audit.go)
//	ranz [flags] get devices                   print the WireGuard Devices with the last handshake and the traffic of each
//	ranz [flags] get stretches                 print the Stretches of the L2 Networks, with their values and whether the controller
//	                                           gives each to its gateway (SDN-63)
//	ranz [flags] get device-config NAME        print the WireGuard configuration of the Device NAME, for a stock client
//	ranz [flags] device create -network N -gateway NODE [flags] NAME
//	                                           make the WireGuard Device NAME with its keys and print its finished configuration,
//	                                           which shows its private key and PresharedKey once; -qr draws the QR code (devicecreate.go,
//	                                           SDN-82)
//	ranz [flags] delete KIND NAME              delete one resource
//	ranz [flags] connect vrf A B               leak the routes of the VRFs A and B into each other, as one revision: each
//	                                           imports a route target that the other exports (SDN-7)
//	ranz [flags] export [-o json|yaml]         print the whole intent as one intent document, with the values the controller
//	                                           filled in, such as the id and the ULA of each VRF; JSON unless -o yaml
//	ranz [flags] import -f FILE                make the intent document in FILE (YAML or JSON, - for standard input) the whole
//	                                           intent, as a new revision: the resources it leaves out are deleted
//	ranz [flags] status                        print the controller's public key, control address and TLS fingerprint
//	ranz [flags] get licence                   print the licence in force: tier, node cap, features, expiry
//	ranz [flags] licence -f FILE               install the licence key in FILE (- for standard input)
//	ranz [flags] licence -remove               remove the licence key, which leaves the Personal tier
//	ranz [flags] whoami                        print the name and the role of the token
//	ranz [flags] token list [-o json|table]    print the API tokens, without their secrets, each with when it expires and when it
//	                                           was last used; ranz tokens is the same (tokens.go, AUD1-DT-13 #461)
//	ranz [flags] token create -role ROLE [-expires TIME|DURATION] NAME
//	                                           create an API token with the role viewer, operator or admin, and print its secret;
//	                                           the controller refuses it from the time that -expires names, an RFC 3339 time or
//	                                           a time from now such as 720h, and never when it is left out
//	ranz [flags] token delete NAME             delete an API token, an expired one too
//	ranz [flags] user list                     print the users, with their devices and whether each has a password (SDN-31)
//	ranz [flags] user set [flags] NAME         make the user, or change the fields that the flags name: -display, -groups,
//	                                           -expires, -max-devices, -may-change-password and -no-saved-password
//	ranz [flags] user password [-f FILE] NAME  set the password of the user from FILE or standard input, one line; the
//	                                           controller keeps a PBKDF2 hash of it, outside the intent
//	ranz [flags] user delete NAME              delete the user and its password
//	ranz [flags] group list                    print the groups, with their members: a group is a tag of policy for the
//	                                           devices of its members
//	ranz [flags] group set [-display TEXT] NAME  make the group, or change its display name
//	ranz [flags] group delete NAME             delete the group
//	ranz [flags] user role list|set NAME ROLE|clear NAME
//	                                           the API roles of users, which their logins carry (admin; userrole.go)
//	ranz [flags] token role NAME ROLE          give an API token another role in place, its secret unchanged (admin)
//	ranz [flags] session list [-user NAME] [-node NAME]
//	                                           print the sessions, the control streams of the nodes: who is connected, from
//	                                           where, with which addresses and how much traffic (SDN-50, operator)
//	ranz [flags] session disconnect ID         end the session ID at once; -user NAME ends every session of the user
//	ranz [flags] ban list                      print the banned users
//	ranz [flags] ban set [-reason TEXT] USER   ban the user: every device of the user is cut off at once, and none gets in
//	                                           until the ban is lifted with ban clear
//	ranz [flags] ban clear USER                lift the ban of the user
//	ranz [flags] node-key list [-o json|table] print the key of every Node: its state (valid, expired or pending), when it last
//	                                           authenticated, when it ends, the days that are left and whether it was approved
//	                                           (SDN-56, operator)
//	ranz [flags] node-key approve NODE         approve a Node that its Network holds for approval; its key lives from now
//	ranz [flags] node-key refresh NODE         give the key of a Node that has no owner another period, as the login of its
//	                                           user does for a device
//	ranz [flags] mac-table [-node NODE] NETWORK
//	                                           print the MAC table of the L2 Network on each node that holds it
//	ranz [flags] mac-table clear [-node NODE] [-mac ADDRESS] NETWORK
//	                                           remove the entry of the MAC address from it, or every entry
//	ranz [flags] ip-table [-node NODE] NETWORK  print the IP table of the L2 Network, as mac-table does
//	ranz [flags] ip-table clear [-node NODE] [-address ADDRESS] NETWORK
//	                                           remove the entry of the IP address from it, or every entry
//	ranz [flags] admin-sources list            print the admin source allowlist: the prefixes that the API and the web UI accept
//	                                           connections from (none: any address)
//	ranz [flags] admin-sources set PREFIX...   replace the allowlist with these prefixes, each a CIDR prefix such as 203.0.113.0/24
//	                                           or one address; a list without the address of the call is refused, and a loopback
//	                                           address, the host of the controller itself, always passes
//	ranz [flags] admin-sources clear           remove the allowlist, so that any address may reach the API and the web UI
//	ranz [flags] admin-destinations list       print the admin destination lists: the target hosts, the sensor prefixes and the
//	                                           UNC servers that an operator may point the Controller and the Nodes at (admin only)
//	ranz [flags] admin-destinations set [-targets LIST] [-sensors LIST] [-unc-servers LIST]
//	                                           replace the lists that a flag names, each separated by commas (empty for none)
//	ranz [flags] controller-cert show          print the certificate that the Controller serves on its TLS port: subject, names,
//	                                           thumbprint, TLS fingerprint, expiry and source, never a key (SDN-92)
//	ranz [flags] controller-cert set -host NAMES -cert FILE [-key FILE]
//	                                           serve the certificate in a PEM file with its key; -ksp THUMBPRINT names one of the
//	                                           Windows key storage with its key staying there, -acme NAMES gets one from an ACME
//	                                           service; refused with the reason when the certificate does not match its key, has
//	                                           expired or does not name the host that the Nodes use
//	ranz [flags] controller-cert clear         serve the Controller's own self-signed certificate again
//
// Flags:
//
//	-server URL           the API; https://127.0.0.1 (port 443) unless RANZ_SERVER names another
//	-token-file FILE      the file that holds the API token, RANZ_TOKEN_FILE by default; without
//	                      a file, RANZ_TOKEN holds the token itself
//	-tls-fingerprint HEX  accept only the certificate with this TLS fingerprint, the one that
//	                      `ranz status` prints, RANZ_TLS_FINGERPRINT by default: for a controller on
//	                      another host while its certificate is self-signed
//	-controller-dir DIR   the data directory of the controller on this host, RANZ_CONTROLLER_DIR by
//	                      default, the one of the service when left out. Toward a loopback address,
//	                      which is the default server, ranz accepts only the certificate with the TLS
//	                      fingerprint that the controller wrote to tls.fingerprint there, because
//	                      another program of the host can listen on a port that the controller is not
//	                      on. Without that file, and without -tls-fingerprint, it sends no token. On
//	                      Windows it takes the file only when no account but SYSTEM, the Administrators
//	                      and the service of the controller owns or may write the file or its folder.
//
// Every call needs the token of a role (SDN-14, #190): viewer reads and exports, operator also
// applies, imports, deletes, confirms, rolls back and installs or removes the licence key, and
// makes every call of the live operations, the reads of them too (session, ban, mac-table and
// ip-table: SDN-50, #243), admin also manages the tokens and the admin source allowlist
// (SDN-39, #232). The first start of the
// controller creates the admin token and writes its secret to
// admin.token in its data directory; when it is lost, `ranz controller reset-admin` on the
// controller's host makes a new one.
// The controller decides what a token may do, so ranz prints its answer as it is: JSON, the
// canonical form of the intent, or the controller's refusal. Each apply, import, delete and
// rollback prints the revision it made. An export moves the intent alone; the whole store, with
// the revisions, is backed up with `ranz controller backup` on the controller's host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const usage = `usage:
  ranz controller [flags]
  ranz bgp -pipe NAME [-log FILE] [-log-level LEVEL]
  ranz mimic (-pipe NAME [-log FILE] [-log-level LEVEL] | -keygen)
  ranz install [-controller [-admin-from PREFIXES|any]] [-no-xdp] [-no-wireguard]
  ranz uninstall [-keep-ranz]
  ranz notice
  ranz version
  ranz cert -cn NAME (-savecert FILE -savekey FILE | -ksp NAME) [flags]
  ranz test throughput -listen ADDRESS
  ranz test throughput [flags] HOST[:PORT]
  ranz doctor [-bundle [-o FILE]]
  ranz explain [flags] [-vrf VRF] [-protocol tcp|udp|icmp|N] [-sport PORT] [-port PORT] [-o text|json] A B
  ranz login [-server URL] [-tls-fingerprint HEX] [-controller-dir DIR] [-device | -user NAME [-password-file FILE]] [-o FILE]
  ranz tray [-server URL] [-tls-fingerprint HEX] [-controller-dir DIR] [-pipe NAME] [status | login [-device] | up | down | exit NAME [VRF] | exit none]
  ranz [flags] apply -f FILE [-confirm DURATION]
  ranz [flags] confirm REVISION
  ranz [flags] diff [FROM [TO]]
  ranz [flags] rollback REVISION
  ranz [flags] get resources|nodes|revisions|events|ipam|leases|licence|devices|stretches
  ranz [flags] get revision ID
  ranz [flags] get audit [-kind KIND] [-actor ACTOR] [-since TIME] [-until TIME] [-after ID] [-limit N] [-o json|table]
  ranz [flags] get device-config NAME
  ranz [flags] device create -network NETWORK -gateway NODE [-owner USER] [-tags A,B] [-battery-saver] [-public-key KEY] [-no-preshared-key] [-o FILE] [-qr] [-qr-file FILE] NAME
  ranz [flags] delete KIND NAME
  ranz [flags] connect vrf A B
  ranz [flags] export [-o json|yaml]
  ranz [flags] import -f FILE
  ranz [flags] status
  ranz [flags] licence -f FILE|-remove
  ranz [flags] whoami
  ranz [flags] token list [-o json|table]
  ranz [flags] tokens [-o json|table]
  ranz [flags] token create -role viewer|operator|admin [-expires TIME|DURATION] NAME
  ranz [flags] token delete NAME
  ranz [flags] user list
  ranz [flags] user set [-display TEXT] [-groups A,B] [-expires TIME|none] [-max-devices N] [-may-change-password=BOOL] [-no-saved-password=BOOL] NAME
  ranz [flags] user password [-f FILE] NAME
  ranz [flags] user delete NAME
  ranz [flags] group list
  ranz [flags] group set [-display TEXT] NAME
  ranz [flags] group delete NAME
  ranz [flags] user role list|set NAME ROLE|clear NAME
  ranz [flags] token role NAME viewer|operator|admin
  ranz [flags] session list [-user NAME] [-node NAME]
  ranz [flags] session disconnect ID|-user NAME
  ranz [flags] ban list
  ranz [flags] ban set [-reason TEXT] USER
  ranz [flags] ban clear USER
  ranz [flags] node-key list [-o json|table]
  ranz [flags] node-key approve NODE
  ranz [flags] node-key refresh NODE
  ranz [flags] mac-table [-node NODE] NETWORK
  ranz [flags] mac-table clear [-node NODE] [-mac ADDRESS] NETWORK
  ranz [flags] ip-table [-node NODE] NETWORK
  ranz [flags] ip-table clear [-node NODE] [-address ADDRESS] NETWORK
  ranz [flags] admin-sources list
  ranz [flags] admin-sources set PREFIX...
  ranz [flags] admin-sources clear
  ranz [flags] admin-destinations list
  ranz [flags] admin-destinations set [-targets LIST] [-sensors LIST] [-unc-servers LIST]
  ranz [flags] controller-cert show
  ranz [flags] controller-cert set (-cert FILE [-key FILE] | -ksp THUMBPRINT | -acme NAMES) [-host NAMES] [-force]
  ranz [flags] controller-cert clear [-force]
`

var errUsage = errors.New("bad arguments")

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		if run, ok := subcommands[args[0]]; ok {
			os.Exit(run(args[1:]))
		}
	}
	runCLI(args)
}

// runCLI runs the command of the controller's HTTP API that args hold, the arguments of ranz that
// no subcommand took, and exits with the code of a command that failed.
func runCLI(args []string) {
	flags := flag.NewFlagSet("ranz", flag.ExitOnError)
	server := os.Getenv("RANZ_SERVER")
	if server == "" {
		server = "https://127.0.0.1"
	}
	flags.StringVar(&server, "server", server, "the URL of the controller's HTTP API")
	tokenFile := flags.String("token-file", os.Getenv("RANZ_TOKEN_FILE"), "the file that holds the API token; without one, RANZ_TOKEN holds the token")
	fingerprint := flags.String("tls-fingerprint", os.Getenv("RANZ_TLS_FINGERPRINT"), "accept only the controller's certificate with this TLS fingerprint (ranz status prints it)")
	controllerDir := flags.String("controller-dir", os.Getenv("RANZ_CONTROLLER_DIR"), "the data directory of the controller on this host, which holds the TLS fingerprint that a loopback address is checked by; the one of the service when left out")
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flags.PrintDefaults()
	}
	_ = flags.Parse(args)
	c, err := newClient(server, *tokenFile, os.Getenv("RANZ_TOKEN"), *fingerprint, *controllerDir)
	if err == nil {
		err = do(context.Background(), c, flags.Args(), os.Stdout)
	}
	if errors.Is(err, errUsage) {
		flags.Usage()
		os.Exit(2)
	}
	if refusal := loopbackRefusal(err); refusal != nil {
		err = refusal
	}
	var refused *api.Error
	if errors.As(err, &refused) {
		fmt.Fprintf(os.Stderr, "ranz: %v (%d %s)\n", err, refused.Status, http.StatusText(refused.Status))
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ranz:", err)
		os.Exit(1)
	}
}

// newClient returns a client of the API at server. It calls with the token in the file
// tokenFile, or with token when tokenFile is empty, and pins the TLS fingerprint when it is set.
// Toward a loopback host with no fingerprint it checks the one in the data directory
// controllerDir of the controller of this host, and refuses every call when it cannot read it
// (checkLoopback): the client that api.NewClient makes for a loopback host checks nothing.
func newClient(server, tokenFile, token, fingerprint, controllerDir string) (*api.Client, error) {
	c := api.NewClient(server)
	c.Token = token
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("the token file: %w", err)
		}
		c.Token = strings.TrimSpace(string(b))
	}
	if fingerprint != "" {
		if err := c.Pin(fingerprint); err != nil {
			return nil, err
		}
	} else if api.Loopback(server) {
		checkLoopback(c, server, controllerDir)
	}
	return c, nil
}

// do runs the command args with c and prints its answer to out.
func do(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch {
	case len(args) == 4 && args[0] == "token" && args[1] == "role":
		// The role of an API token, changed in place (tokenrole.go; SDN-32)
		return tokenRole(ctx, c, args[2], args[3], out)
	case args[0] == "apply":
		flags := flag.NewFlagSet("apply", flag.ContinueOnError)
		file := flags.String("f", "", "the intent document, - for standard input")
		confirm := flags.Duration("confirm", 0, "have the controller roll the apply back after this long, for example 5m, unless ranz confirm confirms it")
		if err := flags.Parse(args[1:]); err != nil || *file == "" || flags.NArg() > 0 {
			return errUsage
		}
		doc, err := readDocument(*file)
		if err != nil {
			return err
		}
		res, err := c.ApplyConfirm(ctx, doc, *confirm)
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) == 2 && args[0] == "confirm":
		id, err := revisionArg(args[1])
		if err != nil {
			return err
		}
		rev, err := c.Confirm(ctx, id)
		if err != nil {
			return err
		}
		return show(out, rev)
	case len(args) <= 3 && args[0] == "diff":
		var ids []uint64
		for _, a := range args[1:] {
			id, err := revisionArg(a)
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		d, err := c.Diff(ctx, ids...)
		if err != nil {
			return err
		}
		return show(out, d)
	case len(args) == 2 && args[0] == "rollback":
		id, err := revisionArg(args[1])
		if err != nil {
			return err
		}
		res, err := c.Rollback(ctx, id)
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) >= 2 && args[0] == "get" && args[1] == "audit":
		return auditCommand(ctx, c, args[2:], out)
	case len(args) == 2 && args[0] == "get" && args[1] == "revisions":
		revs, err := c.Revisions(ctx)
		if err != nil {
			return err
		}
		return show(out, api.RevisionList{Revisions: revs})
	case len(args) == 3 && args[0] == "get" && args[1] == "revision":
		id, err := revisionArg(args[2])
		if err != nil {
			return err
		}
		rev, err := c.Revision(ctx, id)
		if err != nil {
			return err
		}
		return show(out, rev)
	case len(args) == 2 && args[0] == "get" && args[1] == "events":
		evs, err := c.Events(ctx)
		if err != nil {
			return err
		}
		return show(out, api.EventList{Events: evs})
	case len(args) == 2 && args[0] == "get" && args[1] == "ipam":
		ipam, err := c.IPAM(ctx)
		if err != nil {
			return err
		}
		return show(out, ipam)
	case len(args) == 2 && args[0] == "get" && args[1] == "leases":
		leases, err := c.DHCPLeases(ctx)
		if err != nil {
			return err
		}
		return show(out, api.LeaseList{Leases: leases})
	case len(args) >= 2 && args[0] == "get" && (args[1] == "devices" || args[1] == "device-config"):
		// The WireGuard Devices (devices.go; SDN-80)
		return getDevices(ctx, c, args[1:], out)
	case len(args) == 2 && args[0] == "get" && args[1] == "stretches":
		// The Stretches of the L2 Networks (stretches.go; SDN-63)
		return getStretches(ctx, c, out)
	case len(args) == 2 && args[0] == "get" && args[1] == "resources":
		rs, err := c.Resources(ctx)
		if err != nil {
			return err
		}
		return show(out, api.ResourceList{Resources: rs})
	case len(args) == 2 && args[0] == "get" && args[1] == "nodes":
		nodes, err := c.Nodes(ctx)
		if err != nil {
			return err
		}
		return show(out, api.NodeList{Nodes: nodes})
	case len(args) == 3 && args[0] == "delete":
		res, err := c.Delete(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) == 4 && args[0] == "connect" && args[1] == "vrf":
		res, err := c.Connect(ctx, args[2], args[3])
		if err != nil {
			return err
		}
		return show(out, res)
	case args[0] == "export":
		flags := flag.NewFlagSet("export", flag.ContinueOnError)
		format := flags.String("o", "json", "the form of the intent document: json or yaml")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() > 0 || (*format != "json" && *format != "yaml") {
			return errUsage
		}
		doc, err := c.Export(ctx)
		if err != nil {
			return err
		}
		if *format == "json" {
			return show(out, doc)
		}
		b, err := doc.YAML()
		if err != nil {
			return err
		}
		_, err = out.Write(b)
		return err
	case args[0] == "import":
		flags := flag.NewFlagSet("import", flag.ContinueOnError)
		file := flags.String("f", "", "the intent document, - for standard input")
		if err := flags.Parse(args[1:]); err != nil || *file == "" || flags.NArg() > 0 {
			return errUsage
		}
		doc, err := readDocument(*file)
		if err != nil {
			return err
		}
		res, err := c.Import(ctx, doc)
		if err != nil {
			return err
		}
		return show(out, res)
	case len(args) == 1 && args[0] == "status":
		s, err := c.Status(ctx)
		if err != nil {
			return err
		}
		return show(out, s)
	case len(args) == 1 && args[0] == "whoami":
		tok, err := c.Whoami(ctx)
		if err != nil {
			return err
		}
		return show(out, tok)
	case args[0] == "token" || args[0] == "tokens":
		// The API tokens, with their expiry and their last use (tokens.go; AUD1-DT-13)
		return tokenCommand(ctx, c, args, out)
	case len(args) >= 2 && args[0] == "device" && args[1] == "create":
		// A WireGuard Device with its keys (devicecreate.go; SDN-82)
		return createDevice(ctx, c, args[2:], out, os.Stderr)
	case args[0] == "user":
		return userCommand(ctx, c, args[1:], out)
	case args[0] == "group":
		return groupCommand(ctx, c, args[1:], out)
	case args[0] == "session":
		// The live operations (operations.go; SDN-50)
		return sessionCommand(ctx, c, args[1:], out)
	case args[0] == "ban":
		return banCommand(ctx, c, args[1:], out)
	case args[0] == "node-key":
		// The keys of the Nodes: their life and their approval (nodekeys.go; SDN-56)
		return nodeKeyCommand(ctx, c, args[1:], out)
	case args[0] == "mac-table":
		return macTableCommand(ctx, c, args[1:], out)
	case args[0] == "ip-table":
		return ipTableCommand(ctx, c, args[1:], out)
	case args[0] == "controller-cert":
		return controllerCertCommand(ctx, c, args[1:], out)
	case args[0] == "admin-destinations":
		return adminDestinationsCommand(ctx, c, args[1:], out)
	case len(args) == 2 && args[0] == "admin-sources" && args[1] == "list":
		prefixes, err := c.AdminSources(ctx)
		if err != nil {
			return err
		}
		return show(out, api.AdminSourceList{Prefixes: prefixes})
	case len(args) >= 3 && args[0] == "admin-sources" && args[1] == "set":
		prefixes, err := c.SetAdminSources(ctx, args[2:])
		if err != nil {
			return err
		}
		return show(out, api.AdminSourceList{Prefixes: prefixes})
	case len(args) == 2 && args[0] == "admin-sources" && args[1] == "clear":
		prefixes, err := c.SetAdminSources(ctx, nil)
		if err != nil {
			return err
		}
		return show(out, api.AdminSourceList{Prefixes: prefixes})
	case len(args) == 2 && args[0] == "get" && args[1] == "licence":
		st, err := c.Licence(ctx)
		if err != nil {
			return err
		}
		return show(out, st)
	case args[0] == "licence":
		flags := flag.NewFlagSet("licence", flag.ContinueOnError)
		file := flags.String("f", "", "the licence key, - for standard input")
		remove := flags.Bool("remove", false, "remove the licence key")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() > 0 || (*file != "") == *remove {
			return errUsage
		}
		if *remove {
			st, err := c.RemoveLicence(ctx)
			if err != nil {
				return err
			}
			return show(out, st)
		}
		b, err := readInput(*file)
		if err != nil {
			return err
		}
		st, err := c.SetLicence(ctx, string(b))
		if err != nil {
			return err
		}
		return show(out, st)
	}
	return errUsage
}

// revisionArg parses a revision number of the command line.
func revisionArg(s string) (uint64, error) {
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a revision number", s)
	}
	return id, nil
}

// readInput reads the file name, or standard input for "-".
func readInput(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(name)
}

// readDocument reads an intent document, YAML or JSON, from the file name, or from standard
// input for "-".
func readDocument(name string) (intent.Document, error) {
	b, err := readInput(name)
	if err != nil {
		return intent.Document{}, err
	}
	doc, err := intent.ParseDocument(b)
	if err != nil {
		return intent.Document{}, fmt.Errorf("%s is not an intent document: %w", name, err)
	}
	return doc, nil
}

func show(out io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
