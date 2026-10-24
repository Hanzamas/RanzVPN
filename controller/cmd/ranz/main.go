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
//	ranz install [-controller]
//	                          write the Node payload into Program Files, register and start the
//	                          Node service, and, with -controller, the Controller service too
//	                          (package install, ONE-2 #311)
//	ranz uninstall [-keep-ranz]
//	                          stop and remove the services and the files install made, keeping the
//	                          Node's data directory (package install, ONE-2 #311); with -keep-ranz,
//	                          leave ranz.exe and the Ranz folder for the MSI to remove (ONE-5 #314)
//	ranz notice               print the NOTICE: the licence texts of what ranz carries
//	ranz version              print the version, which is the same for every subcommand
//	ranz cert [flags]         make a self-signed or CA-signed certificate and its key, in files or in the
//	                          key storage provider (SDN-53, #246; the successor of vpncmd MakeCert)
//	ranz test throughput ...  measure the rate between two nodes: -listen runs the test server on one,
//	                          a host and port runs the client on another (the successor of vpncmd
//	                          TrafficServer and TrafficClient)
//	ranz doctor               run the system check (the successor of vpncmd Check)
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
//	ranz [flags] delete KIND NAME              delete one resource
//	ranz [flags] export [-o json|yaml]         print the whole intent as one intent document, with the values the controller
//	                                           filled in, such as the id and the ULA of each VRF; JSON unless -o yaml
//	ranz [flags] import -f FILE                make the intent document in FILE (YAML or JSON, - for standard input) the whole
//	                                           intent, as a new revision: the resources it leaves out are deleted
//	ranz [flags] status                        print the controller's public key, control address and TLS fingerprint
//	ranz [flags] get licence                   print the licence in force: tier, node cap, features, expiry
//	ranz [flags] licence -f FILE               install the licence key in FILE (- for standard input)
//	ranz [flags] licence -remove               remove the licence key, which leaves the Personal tier
//	ranz [flags] whoami                        print the name and the role of the token
//	ranz [flags] token list                    print the API tokens, without their secrets
//	ranz [flags] token create -role ROLE NAME  create an API token with the role viewer, operator or admin, and print its secret
//	ranz [flags] token delete NAME             delete an API token
//	ranz [flags] admin-sources list            print the admin source allowlist: the prefixes that the API and the web UI accept
//	                                           connections from (none: any address)
//	ranz [flags] admin-sources set PREFIX...   replace the allowlist with these prefixes, each a CIDR prefix such as 203.0.113.0/24
//	                                           or one address; a list without the address of the call is refused, and a loopback
//	                                           address, the host of the controller itself, always passes
//	ranz [flags] admin-sources clear           remove the allowlist, so that any address may reach the API and the web UI
//
// Flags:
//
//	-server URL           the API; https://127.0.0.1 (port 443) unless RANZ_SERVER names another
//	-token-file FILE      the file that holds the API token, RANZ_TOKEN_FILE by default; without
//	                      a file, RANZ_TOKEN holds the token itself
//	-tls-fingerprint HEX  accept only the certificate with this TLS fingerprint, the one that
//	                      `ranz status` prints, RANZ_TLS_FINGERPRINT by default: for a controller on
//	                      another host while its certificate is self-signed
//
// Every call needs the token of a role (SDN-14, #190): viewer reads and exports, operator also
// applies, imports, deletes, confirms, rolls back and installs or removes the licence key, admin
// also manages the tokens and the admin source allowlist (SDN-39, #232). The first start of the
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
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

const usage = `usage:
  ranz controller [flags]
  ranz bgp -pipe NAME [-log FILE] [-log-level LEVEL]
  ranz install [-controller]
  ranz uninstall [-keep-ranz]
  ranz notice
  ranz version
  ranz cert -cn NAME (-savecert FILE -savekey FILE | -ksp NAME) [flags]
  ranz test throughput -listen ADDRESS
  ranz test throughput [flags] HOST[:PORT]
  ranz doctor
  ranz [flags] apply -f FILE [-confirm DURATION]
  ranz [flags] confirm REVISION
  ranz [flags] diff [FROM [TO]]
  ranz [flags] rollback REVISION
  ranz [flags] get resources|nodes|revisions|events|ipam|licence
  ranz [flags] get revision ID
  ranz [flags] delete KIND NAME
  ranz [flags] export [-o json|yaml]
  ranz [flags] import -f FILE
  ranz [flags] status
  ranz [flags] licence -f FILE|-remove
  ranz [flags] whoami
  ranz [flags] token list
  ranz [flags] token create -role viewer|operator|admin NAME
  ranz [flags] token delete NAME
  ranz [flags] admin-sources list
  ranz [flags] admin-sources set PREFIX...
  ranz [flags] admin-sources clear
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
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flags.PrintDefaults()
	}
	_ = flags.Parse(args)
	c, err := newClient(server, *tokenFile, os.Getenv("RANZ_TOKEN"), *fingerprint)
	if err == nil {
		err = do(context.Background(), c, flags.Args(), os.Stdout)
	}
	if errors.Is(err, errUsage) {
		flags.Usage()
		os.Exit(2)
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
func newClient(server, tokenFile, token, fingerprint string) (*api.Client, error) {
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
	}
	return c, nil
}

// do runs the command args with c and prints its answer to out.
func do(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch {
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
	case len(args) == 2 && args[0] == "token" && args[1] == "list":
		ts, err := c.Tokens(ctx)
		if err != nil {
			return err
		}
		return show(out, api.TokenList{Tokens: ts})
	case len(args) >= 2 && args[0] == "token" && args[1] == "create":
		flags := flag.NewFlagSet("token create", flag.ContinueOnError)
		role := flags.String("role", "", "the role of the token: viewer, operator or admin")
		if err := flags.Parse(args[2:]); err != nil || *role == "" || flags.NArg() != 1 {
			return errUsage
		}
		tok, err := c.CreateToken(ctx, flags.Arg(0), rbac.Role(*role))
		if err != nil {
			return err
		}
		return show(out, tok)
	case len(args) == 3 && args[0] == "token" && args[1] == "delete":
		tok, err := c.DeleteToken(ctx, args[2])
		if err != nil {
			return err
		}
		return show(out, tok)
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
