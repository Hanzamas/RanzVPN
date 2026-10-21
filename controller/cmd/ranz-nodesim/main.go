// Command ranz-nodesim runs one simulated node (internal/nodesim) against a controller: it opens
// the control stream, applies and acknowledges each update, and prints each update as one line
// of JSON. It is the node side of the controller's service check in CI, and a way to try a
// controller by hand.
//
// Usage:
//
//	ranz-nodesim -key FILE -pubkey
//	ranz-nodesim -key FILE -controller HOST:PORT -controller-key KEY [-until GENERATION] [-timeout DURATION]
//
// The first form prints the node's public key, the publicKey of its Node resource; the key file
// is created the first time. The second runs the node; KEY is the controller's public key, which
// `ranz status` prints.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
)

func main() {
	keyFile := flag.String("key", "node.key", "the node's static key, created the first time")
	pubkey := flag.Bool("pubkey", false, "print the base64 public key of -key and exit")
	addr := flag.String("controller", "127.0.0.1:7443", "the host:port of the controller's control stream")
	controllerKey := flag.String("controller-key", "", "the base64 public key of the controller")
	until := flag.Uint64("until", 0, "exit once this generation is applied and acknowledged; 0 runs until interrupted")
	timeout := flag.Duration("timeout", 0, "give up after this long; 0 waits for ever")
	flag.Parse()

	key, err := control.LoadKey(*keyFile)
	if err != nil {
		fail(err)
	}
	if *pubkey {
		fmt.Println(base64.StdEncoding.EncodeToString(key.Public))
		return
	}
	ck, err := intent.ParseKey(*controllerKey)
	if err != nil {
		fail(fmt.Errorf("-controller-key: %w", err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	n := &nodesim.Node{Key: key, Controller: *addr, ControllerKey: ck, Updates: make(chan *controlpb.Update, 16)}
	errc := make(chan error, 1)
	go func() { errc <- n.Run(ctx) }()
	for {
		select {
		case u := <-n.Updates:
			b, err := protojson.Marshal(u)
			if err != nil {
				fail(err)
			}
			fmt.Println(string(b))
			if *until != 0 && u.GetGeneration() >= *until {
				return
			}
		case err := <-errc:
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ranz-nodesim:", err)
	os.Exit(1)
}
