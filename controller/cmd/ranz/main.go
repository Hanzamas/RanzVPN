// Command ranz is the command-line client of the controller's HTTP API (#176 "Intent API").
//
// Usage:
//
//	ranz [-server URL] apply -f FILE      apply the resources of an intent document (YAML or JSON, - for standard input)
//	ranz [-server URL] get resources      print the intent
//	ranz [-server URL] get nodes          print the generation of each node and the one it acknowledged
//	ranz [-server URL] delete KIND NAME   delete one resource
//	ranz [-server URL] status             print the controller's public key, control address and TLS fingerprint
//	ranz [-server URL] get licence        print the licence in force: tier, node cap, features, expiry
//	ranz [-server URL] licence -f FILE    install the licence key in FILE (- for standard input)
//	ranz [-server URL] licence -remove    remove the licence key, which leaves the Personal tier
//
// The server is https://127.0.0.1 (port 443) unless -server or the RANZ_SERVER environment
// variable names another. Every answer is printed as JSON, the canonical form of the intent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const usage = `usage:
  ranz [-server URL] apply -f FILE
  ranz [-server URL] get resources|nodes|licence
  ranz [-server URL] delete KIND NAME
  ranz [-server URL] status
  ranz [-server URL] licence -f FILE|-remove
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
		if err := flags.Parse(args[1:]); err != nil || *file == "" || flags.NArg() > 0 {
			return errUsage
		}
		doc, err := readDocument(*file)
		if err != nil {
			return err
		}
		res, err := c.Apply(ctx, doc)
		if err != nil {
			return err
		}
		return show(res)
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
	case len(args) == 2 && args[0] == "get" && args[1] == "licence":
		st, err := c.Licence(ctx)
		if err != nil {
			return err
		}
		return show(st)
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
			return show(st)
		}
		b, err := readInput(*file)
		if err != nil {
			return err
		}
		st, err := c.SetLicence(ctx, string(b))
		if err != nil {
			return err
		}
		return show(st)
	}
	return errUsage
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

func show(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(b))
	return err
}
