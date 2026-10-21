// Command ranz is the command-line client of the controller's HTTP API (#176 "Intent API").
//
// Usage:
//
//	ranz [-server URL] apply -f FILE      apply the resources of an intent document (YAML or JSON, - for standard input)
//	ranz [-server URL] apply -f FILE -confirm DURATION
//	                                      the same, rolled back by the controller after DURATION (for example 5m) unless confirmed
//	ranz [-server URL] confirm REVISION   confirm the revision of an apply with -confirm, so that it stays
//	ranz [-server URL] diff [FROM [TO]]   print the resource changes from revision FROM to revision TO (the latest when left
//	                                      out); with no revision, the changes of the latest revision
//	ranz [-server URL] rollback REVISION  make the intent of REVISION the intent again, as a new revision (0 is the empty intent)
//	ranz [-server URL] get resources      print the intent
//	ranz [-server URL] get nodes          print the generation of each node and the one it acknowledged
//	ranz [-server URL] get revisions      print every revision of the intent
//	ranz [-server URL] get revision ID    print one revision with its resources
//	ranz [-server URL] get events         print the events, such as an automatic rollback
//	ranz [-server URL] delete KIND NAME   delete one resource
//	ranz [-server URL] status             print the controller's public key, control address and TLS fingerprint
//
// Each apply, delete and rollback prints the revision it made. The server is https://127.0.0.1
// (port 443) unless -server or the RANZ_SERVER environment variable names another. Every answer
// is printed as JSON, the canonical form of the intent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const usage = `usage:
  ranz [-server URL] apply -f FILE [-confirm DURATION]
  ranz [-server URL] confirm REVISION
  ranz [-server URL] diff [FROM [TO]]
  ranz [-server URL] rollback REVISION
  ranz [-server URL] get resources|nodes|revisions|events
  ranz [-server URL] get revision ID
  ranz [-server URL] delete KIND NAME
  ranz [-server URL] status
`

var errUsage = errors.New("bad arguments")

func main() {
	flags := flag.NewFlagSet("ranz", flag.ExitOnError)
	server := os.Getenv("RANZ_SERVER")
	if server == "" {
		server = "https://127.0.0.1"
	}
	flags.StringVar(&server, "server", server, "the URL of the controller's HTTP API")
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flags.PrintDefaults()
	}
	_ = flags.Parse(os.Args[1:])
	err := do(context.Background(), api.NewClient(server), flags.Args())
	if errors.Is(err, errUsage) {
		flags.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ranz:", err)
		os.Exit(1)
	}
}

func do(ctx context.Context, c *api.Client, args []string) error {
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
		return show(res)
	case len(args) == 2 && args[0] == "confirm":
		id, err := revisionArg(args[1])
		if err != nil {
			return err
		}
		rev, err := c.Confirm(ctx, id)
		if err != nil {
			return err
		}
		return show(rev)
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
		return show(d)
	case len(args) == 2 && args[0] == "rollback":
		id, err := revisionArg(args[1])
		if err != nil {
			return err
		}
		res, err := c.Rollback(ctx, id)
		if err != nil {
			return err
		}
		return show(res)
	case len(args) == 2 && args[0] == "get" && args[1] == "revisions":
		revs, err := c.Revisions(ctx)
		if err != nil {
			return err
		}
		return show(api.RevisionList{Revisions: revs})
	case len(args) == 3 && args[0] == "get" && args[1] == "revision":
		id, err := revisionArg(args[2])
		if err != nil {
			return err
		}
		rev, err := c.Revision(ctx, id)
		if err != nil {
			return err
		}
		return show(rev)
	case len(args) == 2 && args[0] == "get" && args[1] == "events":
		evs, err := c.Events(ctx)
		if err != nil {
			return err
		}
		return show(api.EventList{Events: evs})
	case len(args) == 2 && args[0] == "get" && args[1] == "resources":
		rs, err := c.Resources(ctx)
		if err != nil {
			return err
		}
		return show(api.ResourceList{Resources: rs})
	case len(args) == 2 && args[0] == "get" && args[1] == "nodes":
		nodes, err := c.Nodes(ctx)
		if err != nil {
			return err
		}
		return show(api.NodeList{Nodes: nodes})
	case len(args) == 3 && args[0] == "delete":
		res, err := c.Delete(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return show(res)
	case len(args) == 1 && args[0] == "status":
		s, err := c.Status(ctx)
		if err != nil {
			return err
		}
		return show(s)
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

func show(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(b))
	return err
}
