// Command ranz is the command-line client of the controller's HTTP API (#176 "Intent API").
//
// Usage:
//
//	ranz [flags] apply -f FILE                 apply the resources of an intent document (YAML or JSON, - for standard input)
//	ranz [flags] apply -f FILE -confirm DURATION
//	                                           the same, rolled back by the controller after DURATION (for example 5m) unless confirmed
//	ranz [flags] confirm REVISION              confirm the revision of an apply with -confirm, so that it stays
//	ranz [flags] diff [FROM [TO]]              print the resource changes from revision FROM to revision TO (the latest when left
//	                                           out); with no revision, the changes of the latest revision
//	ranz [flags] rollback REVISION             make the intent of REVISION the intent again, as a new revision (0 is the empty intent)
//	ranz [flags] get resources                 print the intent
//	ranz [flags] get nodes                     print the generation of each node and the one it acknowledged
//	ranz [flags] get revisions                 print every revision of the intent
//	ranz [flags] get revision ID               print one revision with its resources
//	ranz [flags] get events                    print the events, such as an automatic rollback
//	ranz [flags] delete KIND NAME              delete one resource
//	ranz [flags] status                        print the controller's public key, control address and TLS fingerprint
//	ranz [flags] whoami                        print the name and the role of the token
//	ranz [flags] token list                    print the API tokens, without their secrets
//	ranz [flags] token create -role ROLE NAME  create an API token with the role viewer, operator or admin, and print its secret
//	ranz [flags] token delete NAME             delete an API token
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
// Every call needs the token of a role (SDN-14, #190): viewer reads, operator also applies,
// deletes, confirms and rolls back, admin also manages the tokens. The first start of the
// controller creates the admin token and writes its secret to admin.token in its data directory.
// The controller decides what a token may do, so ranz prints its answer as it is: JSON, the
// canonical form of the intent, or the controller's refusal. Each apply, delete and rollback
// prints the revision it made.
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
  ranz [flags] apply -f FILE [-confirm DURATION]
  ranz [flags] confirm REVISION
  ranz [flags] diff [FROM [TO]]
  ranz [flags] rollback REVISION
  ranz [flags] get resources|nodes|revisions|events
  ranz [flags] get revision ID
  ranz [flags] delete KIND NAME
  ranz [flags] status
  ranz [flags] whoami
  ranz [flags] token list
  ranz [flags] token create -role viewer|operator|admin NAME
  ranz [flags] token delete NAME
`

var errUsage = errors.New("bad arguments")

func main() {
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
	_ = flags.Parse(os.Args[1:])
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

// readDocument reads an intent document, YAML or JSON, from the file name, or from standard
// input for "-".
func readDocument(name string) (intent.Document, error) {
	var b []byte
	var err error
	if name == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(name)
	}
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
