// Command ranz-controller is the Ranz controller (#176): a Windows or Linux service that keeps
// the intent in rqlite, serves the HTTP API that `ranz` calls, and pushes the desired state of
// each node over the Noise control stream.
//
// Usage:
//
//	ranz-controller [flags]            run in the foreground, or as the Windows service
//	ranz-controller install [flags]    register the Windows service, which runs with these flags
//	ranz-controller uninstall          remove the Windows service
//
// rqlite is the controller's sidecar: with -rqlited the controller runs rqlited itself, with its
// data in the rqlite directory under -data; without it, the controller uses the rqlite at
// -rqlite.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// keyFile is the name of the controller's static key in the data directory.
const keyFile = "controller.key"

// startTimeout bounds the start of rqlited and the first connection to rqlite.
const startTimeout = 60 * time.Second

type config struct {
	dataDir     string
	controlAddr string
	apiAddr     string
	rqliteURL   string
	rqlited     string
	raftAddr    string
}

func parseFlags(args []string) (config, error) {
	flags := flag.NewFlagSet("ranz-controller", flag.ContinueOnError)
	var cfg config
	flags.StringVar(&cfg.dataDir, "data", defaultDataDir(), "the data directory: the controller key, the service log and the data of -rqlited")
	flags.StringVar(&cfg.controlAddr, "control-listen", ":7443", "the TCP address of the control stream")
	flags.StringVar(&cfg.apiAddr, "api-listen", "127.0.0.1:7080", "the TCP address of the HTTP API, which has no authentication yet")
	flags.StringVar(&cfg.rqliteURL, "rqlite", "http://127.0.0.1:4001", "the URL of the rqlite HTTP API; with -rqlited, rqlited listens on its host:port")
	flags.StringVar(&cfg.rqlited, "rqlited", "", "the path of rqlited, to run it as the controller's sidecar")
	flags.StringVar(&cfg.raftAddr, "rqlite-raft", "127.0.0.1:4002", "the TCP address of the Raft transport of -rqlited")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %q", flags.Args())
	}
	return cfg, nil
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		var err error
		if args[0] == "install" {
			if _, err = parseFlags(args[1:]); err == nil {
				err = install(args[1:])
			}
		} else {
			err = uninstall()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ranz-controller %s: %v\n", args[0], err)
			os.Exit(1)
		}
		fmt.Printf("ranz-controller %s: done (service %s)\n", args[0], serviceName)
		return
	}
	cfg, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		os.Exit(2)
	}
	if isService() {
		if err := runService(cfg); err != nil {
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log, os.Stderr, nil); err != nil {
		log.Error("controller failed", "err", err)
		os.Exit(1)
	}
}

// run runs the controller until ctx ends: rqlited if the configuration asks for it, the store,
// the control stream and the HTTP API. out receives the output of rqlited; ready, if not nil, is
// called once everything serves.
func run(ctx context.Context, cfg config, log *slog.Logger, out io.Writer, ready func()) error {
	if err := makeDataDir(cfg.dataDir); err != nil {
		return err
	}
	key, err := control.LoadKey(filepath.Join(cfg.dataDir, keyFile))
	if err != nil {
		return err
	}
	log.Info("controller key", "publicKey", base64.StdEncoding.EncodeToString(key.Public))

	if cfg.rqlited != "" {
		u, err := url.Parse(cfg.rqliteURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("-rqlite %q is not a URL with a host:port", cfg.rqliteURL)
		}
		rq := &sidecar.Rqlited{
			Path:     cfg.rqlited,
			DataDir:  filepath.Join(cfg.dataDir, "rqlite"),
			HTTPAddr: u.Host,
			RaftAddr: cfg.raftAddr,
			Output:   out,
		}
		sctx, cancel := context.WithTimeout(ctx, startTimeout)
		err = rq.Start(sctx)
		cancel()
		if err != nil {
			return err
		}
		defer rq.Stop()
		log.Info("rqlited started", "url", rq.URL())
	}

	sctx, cancel := context.WithTimeout(ctx, startTimeout)
	st, err := store.Open(sctx, cfg.rqliteURL)
	cancel()
	if err != nil {
		return err
	}
	defer st.Close()
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key, Log: log})
	if err != nil {
		return err
	}

	ln, err := control.Listen(cfg.controlAddr, key)
	if err != nil {
		return err
	}
	apiLn, err := net.Listen("tcp", cfg.apiAddr)
	if err != nil {
		ln.Close()
		return fmt.Errorf("API: %w", err)
	}
	srv := &http.Server{Handler: api.Handler(c, ln.Addr().String()), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- c.Serve(ln) }()
	go func() { errc <- srv.Serve(apiLn) }()
	log.Info("controller serving", "control", ln.Addr().String(), "api", apiLn.Addr().String())
	if ready != nil {
		ready()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	sctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	ln.Close()
	c.Close()
	log.Info("controller stopped")
	return serveErr
}

// makeDataDir creates the data directory if it does not exist, readable by its owner and the
// administrators only.
func makeDataDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return protectDir(dir)
}
