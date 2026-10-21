// Command ranz-controller is the Ranz controller (#176): a Windows or Linux service that keeps
// the intent in rqlite and serves, on one TLS port (TCP 443 by default), the Noise control
// stream of the nodes and the HTTP API that `ranz` calls, told apart by their ALPN protocol.
//
// Usage:
//
//	ranz-controller [flags]            run in the foreground, or as the Windows service
//	ranz-controller install [flags]    register the Windows service, which runs with these flags
//	ranz-controller uninstall          remove the Windows service
//
// Ports:
//
//	-listen          :443, TLS: ranz-control/1 to the control stream; h2, http/1.1 or none to the API
//	-http-listen     off; plain HTTP (port 80) for the redirect to HTTPS and ACME HTTP-01 only
//	-control-listen  off; a second TLS port for the control stream only, for development
//	-api-listen      off; plain HTTP on a loopback address for the API only, for development
//	-rqlite          127.0.0.1:4001, and -rqlite-raft 127.0.0.1:4002: rqlite, host-internal
//
// The API answers clients on the loopback interface only until RBAC (SDN-14, #190). rqlite is
// the controller's sidecar: with -rqlited the controller runs rqlited itself, with its data in
// the rqlite directory under -data; without it, the controller uses the rqlite at -rqlite.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// startTimeout bounds the start of rqlited and the first connection to rqlite.
const startTimeout = 60 * time.Second

type config struct {
	dataDir       string
	listen        string
	httpListen    string
	controlListen string
	apiListen     string
	rqliteURL     string
	rqlited       string
	raftAddr      string
}

func parseFlags(args []string) (config, error) {
	flags := flag.NewFlagSet("ranz-controller", flag.ContinueOnError)
	var cfg config
	flags.StringVar(&cfg.dataDir, "data", defaultDataDir(), "the data directory: the controller's keys, the service log and the data of -rqlited")
	flags.StringVar(&cfg.listen, "listen", ":443", "the TCP address of the TLS port: the control stream and the API, told apart by ALPN")
	flags.StringVar(&cfg.httpListen, "http-listen", "", "the TCP address of plain HTTP, for example :80, which only redirects to HTTPS and answers ACME HTTP-01 challenges; off when empty")
	flags.StringVar(&cfg.controlListen, "control-listen", "", "for development: a second TLS address for the control stream only, for example 127.0.0.1:7443")
	flags.StringVar(&cfg.apiListen, "api-listen", "", "for development: a loopback address for the API over plain HTTP, for example 127.0.0.1:7080")
	flags.StringVar(&cfg.rqliteURL, "rqlite", "http://127.0.0.1:4001", "the URL of the rqlite HTTP API; with -rqlited, rqlited listens on its host:port")
	flags.StringVar(&cfg.rqlited, "rqlited", "", "the path of rqlited, to run it as the controller's sidecar")
	flags.StringVar(&cfg.raftAddr, "rqlite-raft", "127.0.0.1:4002", "the TCP address of the Raft transport of -rqlited")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %q", flags.Args())
	}
	if cfg.apiListen != "" && !loopbackAddr(cfg.apiListen) {
		err := fmt.Errorf("-api-listen %q is not a loopback address: the API has no authentication yet (RBAC, SDN-14)", cfg.apiListen)
		fmt.Fprintln(flags.Output(), err)
		return config{}, err
	}
	return cfg, nil
}

// loopbackAddr reports whether the host of the TCP address addr is a loopback address.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
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
// the TLS port, and the optional ports. out receives the output of rqlited; ready, if not nil,
// is called once everything serves.
func run(ctx context.Context, cfg config, log *slog.Logger, out io.Writer, ready func()) error {
	if err := makeDataDir(cfg.dataDir); err != nil {
		return err
	}
	static, tlsKey, err := keys.Load(cfg.dataDir)
	if err != nil {
		return err
	}
	cert, err := keys.SelfSigned(tlsKey)
	if err != nil {
		return err
	}
	log.Info("controller keys", "publicKey", base64.StdEncoding.EncodeToString(static.Public()), "tlsFingerprint", keys.Fingerprint(cert))

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
	c, err := controller.New(ctx, controller.Config{Store: st, Key: static, Log: log})
	if err != nil {
		return err
	}
	defer c.Close()

	errc := make(chan error, 4)
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	apiHandler := api.Handler(c, api.Status{ControlAddress: ln.Addr().String(), TLSFingerprint: keys.Fingerprint(cert)})
	tlsPort := &port.Server{TLS: tlsCfg, Control: c.ServeStream, HTTP: apiHandler, Log: log}
	defer tlsPort.Close()
	defer ln.Close()
	go func() { errc <- tlsPort.Serve(ln) }()
	log.Info("TLS port", "address", ln.Addr().String(), "protocols", "ranz-control/1, h2, http/1.1")

	if cfg.controlListen != "" {
		cln, err := net.Listen("tcp", cfg.controlListen)
		if err != nil {
			return fmt.Errorf("-control-listen: %w", err)
		}
		dev := &port.Server{TLS: tlsCfg, Control: c.ServeStream, Log: log}
		defer dev.Close()
		defer cln.Close()
		go func() { errc <- dev.Serve(cln) }()
		log.Info("control stream port (development)", "address", cln.Addr().String())
	}
	if cfg.apiListen != "" {
		aln, err := net.Listen("tcp", cfg.apiListen)
		if err != nil {
			return fmt.Errorf("-api-listen: %w", err)
		}
		srv := &http.Server{Handler: apiHandler, ReadHeaderTimeout: 10 * time.Second}
		defer srv.Close()
		go func() { errc <- serveHTTP(srv, aln) }()
		log.Info("API over plain HTTP on loopback (development)", "address", aln.Addr().String())
	}
	if cfg.httpListen != "" {
		hln, err := net.Listen("tcp", cfg.httpListen)
		if err != nil {
			return fmt.Errorf("-http-listen: %w", err)
		}
		_, httpsPort, _ := net.SplitHostPort(ln.Addr().String())
		srv := &http.Server{Handler: port.Redirect(httpsPort, nil), ReadHeaderTimeout: 10 * time.Second}
		defer srv.Close()
		go func() { errc <- serveHTTP(srv, hln) }()
		log.Info("plain HTTP port: redirect to HTTPS and ACME HTTP-01", "address", hln.Addr().String())
	}
	if ready != nil {
		ready()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	log.Info("controller stopping")
	return serveErr
}

// serveHTTP serves srv on l until srv is closed.
func serveHTTP(srv *http.Server, l net.Listener) error {
	if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
