// Command ranz is the command-line client of the controller's HTTP API (#176 "Intent API").
//
// Usage:
//
//	ranz [-server URL] apply -f FILE      apply the resources of an intent document (JSON, - for standard input)
//	ranz [-server URL] get resources      print the intent
//	ranz [-server URL] get nodes          print the generation of each node and the one it acknowledged
//	ranz [-server URL] delete KIND NAME   delete one resource
//	ranz [-server URL] status             print the controller's public key and control address
//
// The server is http://127.0.0.1:7080 unless -server or the RANZ_SERVER environment variable
// names another. Every answer is printed as JSON.
package main

import (
	"bytes"
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
  ranz [-server URL] get resources|nodes
  ranz [-server URL] delete KIND NAME
  ranz [-server URL] status
`

var errUsage = errors.New("bad arguments")

func main() {
	flags := flag.NewFlagSet("ranz", flag.ExitOnError)
	server := os.Getenv("RANZ_SERVER")
	if server == "" {
		server = "http://127.0.0.1:7080"
	}
	flags.StringVar(&server, "server", server, "the URL of the controller's HTTP API")
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flags.PrintDefaults()
	}
	_ = flags.Parse(os.Args[1:])
	err := do(context.Background(), &api.Client{URL: server}, flags.Args())
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
	}
	return errUsage
}

// readDocument reads an intent document from the file name, or from standard input for "-".
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
	var doc intent.Document
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
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
