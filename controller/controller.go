// Package controllercmd is `ranz controller`, the Ranz controller (#176): a Windows or Linux
// service that keeps the intent in rqlite and serves, on one TLS port (TCP 443 by default), the
// Noise control stream of the nodes and the HTTP API that `ranz` calls, told apart by their ALPN
// protocol. Since ONE-1 (#310) it is a subcommand of the one executable ranz
// (controller/cmd/ranz), not a program of its own: Main runs it.
//
// Usage:
//
//	ranz controller [flags]              run in the foreground, or as the Windows service
//	ranz controller install [flags]      register the Windows service, which runs with these flags
//	ranz controller uninstall            remove the Windows service
//	ranz controller reset-admin [flags]  create a new admin token, with the flags of the service
//	ranz controller backup -o FILE [flags]
//	                                     write a backup of the whole store to FILE, with the flags of the service
//	ranz controller restore -f FILE [flags]
//	                                     replace the whole store with the backup in FILE, with the flags of the service
//
// Ports:
//
//	-listen          :443, TLS: ranz-control/1 to the control stream; h2, http/1.1 or none to the API
//	                 and the web UI (SDN-28);
//	                 with the default, a 443 that cannot be bound falls back to 5555 (ADR-0020)
//	-http-listen     off; plain HTTP (port 80) for the redirect to HTTPS and ACME HTTP-01 only,
//	                 through HTTP.sys on Windows
//	-control-listen  off; a second TLS port for the control stream only, for development
//	-api-listen      off; plain HTTP on a loopback address for the API only, for development
//	-rqlite          127.0.0.1:4001, and -rqlite-raft 127.0.0.1:4002: rqlite, host-internal
//
// Every call of the API needs the bearer token of a role (SDN-14, #190). The first start creates
// the admin token and writes its secret to admin.token in the data directory, for `ranz
// -token-file`. It also creates the intent of a first install as revision 1 (ADR-0034, SDN-3
// #179): VRF default with overlay DNS on, its Network default with the automatic IPv4 pool
// 100.64.0.0/10, and the starter rule default-allow-all; a Node that names no VRF joins VRF
// default. rqlite is the controller's sidecar, and the controller runs a member of its own: the
// rqlited.exe that ranz.exe carries as a Payload (ONE-4, #313), which it writes as
// payload\rqlited.exe in the data directory, again whenever it is missing or differs, after the
// check of its hash and its signature. With -rqlited PATH it runs that rqlited instead, and with
// -rqlite-external none: the rqlite at -rqlite is then another process's. A build with no member
// (Linux) uses the rqlite at -rqlite unless -rqlited names an rqlited. The member of the arm64
// build is the x64 rqlited.exe, which Windows 11 on ARM runs under emulation, as rqlite has no
// Windows build for arm64. The member keeps its data in the rqlite directory under -data.
//
// The API and the web UI accept connections only from the admin source allowlist (SDN-39, #232),
// which an admin sets with `ranz admin-sources`: from an address outside it, every request is
// refused with 403 before its token is looked at, and recorded as an event. Without a list, every
// address may reach them. A loopback address always passes, so a local administrator always
// reaches the controller. The control stream of the nodes is not behind it: a Network limits the
// addresses its Nodes enrol from (its enrolSources). In a cluster, the list must hold the
// addresses of the members too, because a standby forwards a call to the leader from its own
// address.
//
// Cluster (SDN-17, ADR-0026): a cluster of 3 or 5 members runs one `ranz controller` on each host,
// each with its own rqlited, all started with the same -rqlite-join (the Raft addresses of every
// member) and -rqlite-expect (the number of members), and each with its own -name and
// -advertise. The members elect a leader by a lease in rqlite (internal/cluster); the others are
// standbys that send nodes to the leader and forward API calls to it. -rqlite-raft must then be
// an address the other members reach (or -rqlite-raft-adv names one). The tokens are in rqlite,
// so every member knows them; admin.token is in the data directory of the member that started
// first. A single controller is a cluster of one member: it leads as soon as it starts.
//
// When nobody holds the secret of an admin token any more, a local administrator of the host
// (an elevated Administrator on Windows, root elsewhere) runs reset-admin with the flags of the
// service, while it runs or while it is stopped. reset-admin writes a new admin token to the
// store directly, prints its secret once, writes it to admin.token as the first start does, and
// records the reset in the Application log on Windows (event ID 5).
//
// A local administrator of the host also backs up the whole store (the intent with every
// revision, the node states, the events, the tokens and the licence key) with backup, and puts a
// backup back with restore (SDN-52, #245), with the flags of the service, while it runs or while
// it is stopped. A restore under a running controller first takes the lease of the leader for a
// lease duration, so the leader steps down, and then the next leader loads the restored store. In
// a cluster, restore runs while the members run: rqlite loads the backup into every member.
//
// The licence key (ADR-0036) is installed with `ranz licence -f FILE` and kept in rqlite. It
// must be signed with a vendor key that the release build links in (internal/licence); without
// one, the Personal tier is in force.
package controllercmd

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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/mitigation"
	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
	"github.com/Hanzamas/RanzVPN/controller/internal/webui"
)

// startTimeout bounds the start of rqlited and the first connection to rqlite.
const startTimeout = 60 * time.Second

// fallbackPort is the TLS port when the default 443 cannot be bound: the fallback that ADR-0020
// gives the server.
const fallbackPort = "5555"

// fallbackFile, in the data directory, records that the controller fell back to fallbackPort.
// Like the server of ADR-0020, the controller then keeps that port, also once 443 is free again,
// until the operator asks for 443 with an explicit -listen.
const fallbackFile = "listen-fallback"

// adminTokenFile, in the data directory, holds the secret of the admin token that the first
// start of the controller creates (rbac.Bootstrap). Only the directory's owner and the
// administrators can read it (makeDataDir).
const adminTokenFile = "admin.token"

// adminSourcesTTL is how long a member uses a read of the admin source allowlist: a change of it
// reaches every member within this time (api.NewSources).
const adminSourcesTTL = 2 * time.Second

type config struct {
	dataDir       string
	listen        string
	listenSet     bool // -listen was given, so it does not fall back
	httpListen    string
	controlListen string
	apiListen     string
	rqliteURL     string
	rqlited       string
	external      bool // -rqlite-external: no member of its own, the rqlite at -rqlite is another process's
	raftAddr      string
	raftAdv       string
	rqliteID      string
	join          []string
	expect        int
	name          string
	advertise     string
	lease         time.Duration
	schema        controlpb.SchemaVersion
}

func parseFlags(args []string) (config, error) {
	flags := flag.NewFlagSet("ranz controller", flag.ContinueOnError)
	var cfg config
	var join string
	var schema int
	host, _ := os.Hostname()
	flags.StringVar(&cfg.dataDir, "data", defaultDataDir(), "the data directory: the controller's keys, the service log and the data of -rqlited")
	flags.StringVar(&cfg.listen, "listen", ":443", "the TCP address of the TLS port: the control stream and the API, told apart by ALPN; the default falls back to 5555 when 443 cannot be bound")
	flags.StringVar(&cfg.httpListen, "http-listen", "", "the TCP address of plain HTTP, for example :80, which only redirects to HTTPS and answers ACME HTTP-01 challenges (through HTTP.sys on Windows); off when empty")
	flags.StringVar(&cfg.controlListen, "control-listen", "", "for development: a second TLS address for the control stream only, for example 127.0.0.1:7443")
	flags.StringVar(&cfg.apiListen, "api-listen", "", "for development: a loopback address for the API over plain HTTP, for example 127.0.0.1:7080")
	flags.StringVar(&cfg.rqliteURL, "rqlite", "http://127.0.0.1:4001", "the URL of the rqlite HTTP API; with -rqlited, rqlited listens on its host:port")
	flags.StringVar(&cfg.rqlited, "rqlited", "", "the path of rqlited, to run it as the controller's sidecar instead of the one that this executable carries (Windows)")
	flags.BoolVar(&cfg.external, "rqlite-external", false, "run no rqlite member of its own: the rqlite at -rqlite is another process's")
	flags.StringVar(&cfg.raftAddr, "rqlite-raft", "127.0.0.1:4002", "the TCP address of the Raft transport of -rqlited; in a cluster, one the other members reach")
	flags.StringVar(&cfg.raftAdv, "rqlite-raft-adv", "", "the Raft address of -rqlited as the other members reach it, when -rqlite-raft is not one (for example 0.0.0.0:4002)")
	flags.StringVar(&cfg.rqliteID, "rqlite-id", "", "the Raft node id of -rqlited: 1 for a single controller, -name in a cluster when it is empty")
	flags.StringVar(&join, "rqlite-join", "", "a cluster: the comma-separated Raft addresses of all its members (rqlited -join), the same on every member")
	flags.IntVar(&cfg.expect, "rqlite-expect", 0, "a new cluster: the number of members that form it, 3 or 5 (rqlited -bootstrap-expect), the same on every member and at every start")
	flags.StringVar(&cfg.name, "name", strings.ToLower(host), "the name of this member of the controller cluster, unique in the cluster")
	flags.StringVar(&cfg.advertise, "advertise", "", "host:port of the TLS port as nodes and the other members reach it; the -listen address when it names a host and this is empty")
	flags.DurationVar(&cfg.lease, "lease", cluster.DefaultLease, "the lease duration of the leader: a standby takes over this long after the leader is lost")
	flags.IntVar(&schema, "schema-version", 0, "the control schema version to run as: the newest of this release by default, or the one before it during a rolling upgrade of a cluster, until every member runs this release")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() > 0 {
		return config{}, fmt.Errorf("unexpected arguments: %q", flags.Args())
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			cfg.listenSet = true
		}
	})
	for _, a := range strings.Split(join, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.join = append(cfg.join, a)
		}
	}
	cfg.schema = controlpb.SchemaVersion(schema)
	var problem error
	switch {
	case cfg.apiListen != "" && !loopbackAddr(cfg.apiListen):
		problem = fmt.Errorf("-api-listen %q is not a loopback address: plain HTTP would carry the bearer tokens of the API in clear text", cfg.apiListen)
	case cfg.name == "":
		problem = errors.New("-name is empty and the host has no name")
	case cfg.lease < time.Second:
		problem = fmt.Errorf("-lease %v is shorter than 1s", cfg.lease)
	case schema != 0 && cfg.schema != controller.SchemaVersion && cfg.schema != controller.SchemaVersion-1:
		problem = fmt.Errorf("-schema-version %d: this release runs as version %d or %d", schema, int32(controller.SchemaVersion), int32(controller.SchemaVersion-1))
	case len(cfg.advertise) > intent.MaxAddress:
		problem = fmt.Errorf("-advertise is longer than %d characters", intent.MaxAddress)
	case cfg.expect > 0 && len(cfg.join) == 0:
		problem = errors.New("-rqlite-expect needs -rqlite-join")
	case cfg.external && cfg.rqlited != "":
		problem = errors.New("-rqlite-external and -rqlited exclude each other")
	}
	if problem != nil {
		fmt.Fprintln(flags.Output(), problem)
		return config{}, problem
	}
	return cfg, nil
}

// rqliteNodeID returns the Raft node id of -rqlited: -rqlite-id, else 1 for a single
// controller, the node id that a controller of SDN-2 has, and -name in a cluster.
func (cfg config) rqliteNodeID() string {
	switch {
	case cfg.rqliteID != "":
		return cfg.rqliteID
	case len(cfg.join) == 0:
		return "1"
	}
	return cfg.name
}

// payloadDir is the directory under the data directory where the controller writes the files that
// its executable carries (internal/payload): the rqlited.exe of its rqlite member.
const payloadDir = "payload"

// rqlitedExe returns the rqlited that the controller runs as its sidecar: the one that -rqlited
// names, else the rqlite member that this executable carries as a Payload (ONE-4, #313), which
// payload.Ensure writes under the data directory when the file is missing or differs, after the
// check of its hash and its signature. It returns "" when the controller runs no rqlited of its
// own and uses the rqlite at -rqlite: with -rqlite-external, or in a build that carries no member.
func (cfg config) rqlitedExe() (string, error) {
	switch {
	case cfg.rqlited != "":
		return cfg.rqlited, nil
	case cfg.external || len(payload.Rqlited.Data) == 0:
		return "", nil
	}
	return payload.Ensure(filepath.Join(cfg.dataDir, payloadDir), payload.Rqlited)
}

// advertised returns the address of the TLS port as nodes and the other members reach it:
// -advertise, else the address ln listens on when it names a host, else none.
func (cfg config) advertised(ln net.Listener) string {
	if cfg.advertise != "" {
		return cfg.advertise
	}
	if ap, err := netip.ParseAddrPort(ln.Addr().String()); err == nil && !ap.Addr().IsUnspecified() {
		return ap.String()
	}
	return ""
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

// mitigations and mitigationErr are what mitigation.Apply did in Main, which run logs; nil when a
// test calls run itself.
var (
	mitigations   []mitigation.Result
	mitigationErr error
)

// Main is `ranz controller` with the arguments after the subcommand. It returns the exit code of
// the process: 0 when the controller stopped or the command did what it was asked, 1 when either
// failed, and 2 for flags that are wrong.
func Main(args []string) int {
	// The process mitigations of ADR-0039 before the controller starts anything
	mitigations, mitigationErr = mitigation.Apply()
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		var err error
		if args[0] == "install" {
			var cfg config
			if cfg, err = parseFlags(args[1:]); err == nil {
				err = install(args[1:], cfg)
			}
		} else {
			err = uninstall()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ranz controller %s: %v\n", args[0], err)
			return 1
		}
		fmt.Printf("ranz controller %s: done (service %s)\n", args[0], serviceName)
		return 0
	}
	if len(args) > 0 && args[0] == "reset-admin" {
		if err := runResetAdmin(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "ranz controller reset-admin: %v\n", err)
			return 1
		}
		return 0
	}
	if len(args) > 0 && (args[0] == "backup" || args[0] == "restore") {
		cmd := runBackup
		if args[0] == "restore" {
			cmd = runRestore
		}
		if err := cmd(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "ranz controller %s: %v\n", args[0], err)
			return 1
		}
		return 0
	}
	cfg, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return 2
	}
	if isService() {
		if err := runService(cfg); err != nil {
			return 1
		}
		return 0
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log, os.Stderr, hooks{}); err != nil {
		log.Error("controller failed", "err", err)
		return 1
	}
	return 0
}

// hooks are what the Windows service adds to a run.
type hooks struct {
	ready func()           // called once everything serves
	warn  func(msg string) // a warning the operator must see, in the Application log
}

// run runs the controller until ctx ends: rqlited if the configuration asks for it, the store,
// the TLS port, and the optional ports. out receives the output of rqlited.
func run(ctx context.Context, cfg config, log *slog.Logger, out io.Writer, h hooks) error {
	mitigation.Log(log, mitigations, mitigationErr)
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

	rqlited, err := cfg.rqlitedExe()
	if err != nil {
		return fmt.Errorf("the rqlite member: %w", err)
	}
	if rqlited != "" {
		u, err := url.Parse(cfg.rqliteURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("-rqlite %q is not a URL with a host:port", cfg.rqliteURL)
		}
		rq := &sidecar.Rqlited{
			Path:     rqlited,
			DataDir:  filepath.Join(cfg.dataDir, "rqlite"),
			HTTPAddr: u.Host,
			RaftAddr: cfg.raftAddr,
			RaftAdv:  cfg.raftAdv,
			NodeID:   cfg.rqliteNodeID(),
			Join:     cfg.join,
			Expect:   cfg.expect,
			Output:   out,
		}
		sctx, cancel := context.WithTimeout(ctx, startTimeout)
		err = rq.Start(sctx)
		cancel()
		if err != nil {
			return err
		}
		defer rq.Stop()
		log.Info("rqlited started", "url", rq.URL(), "path", rqlited)
	}

	sctx, cancel := context.WithTimeout(ctx, startTimeout)
	st, err := store.Open(sctx, cfg.rqliteURL)
	cancel()
	if err != nil {
		return err
	}
	defer st.Close()
	tokens := rbac.New(st)
	tokenFile := filepath.Join(cfg.dataDir, adminTokenFile)
	created, err := tokens.Bootstrap(ctx, func(secret string) error {
		return os.WriteFile(tokenFile, []byte(secret+"\n"), 0o600)
	})
	if err != nil {
		return fmt.Errorf("the first admin token: %w", err)
	}
	if created {
		log.Info("first start: the admin token is created, its secret is in the data directory", "token", rbac.FirstAdmin, "file", tokenFile)
	}

	errc := make(chan error, 4)
	ln, fell, err := listenTLS(cfg.listen, fallbackPort, cfg.listenSet, cfg.dataDir)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	defer ln.Close()
	_, tlsPortNumber, _ := net.SplitHostPort(ln.Addr().String())
	if fell {
		msg := fmt.Sprintf("the TLS port fell back from %s to %s (ADR-0020): 443 could not be bound at this start or an earlier one; start with an explicit -listen %s to go back to it",
			cfg.listen, ln.Addr(), cfg.listen)
		log.Warn(msg)
		if h.warn != nil {
			h.warn(msg)
		}
	}

	var plainWhere string
	if cfg.httpListen != "" {
		plain, err := port.ListenPlain(cfg.httpListen, port.Redirect(tlsPortNumber, nil), log)
		if err != nil {
			return fmt.Errorf("-http-listen: %w", err)
		}
		defer plain.Close()
		go func() { errc <- plain.Serve() }()
		plainWhere = plain.Where()
		log.Info("plain HTTP port: redirect to HTTPS and ACME HTTP-01", "where", plainWhere)
	}

	tlsPortValue, _ := strconv.Atoi(tlsPortNumber)
	m, err := cluster.Start(cluster.Config{
		Name:        cfg.name,
		Address:     cfg.advertised(ln),
		Fingerprint: keys.Fingerprint(cert),
		Store:       st,
		Tokens:      tokens,
		Key:         static,
		Schema:      cfg.schema,
		Lease:       cfg.lease,
		Log:         log,
		Status: api.Status{
			ControlAddress: ln.Addr().String(),
			TLSFingerprint: keys.Fingerprint(cert),
			Capabilities:   api.Capabilities{TLSPort: tlsPortValue, TLSPortFallback: fell, PlainHTTP: plainWhere},
		},
		// The first start creates VRF default and the starter rule (ADR-0034)
		Defaults: true,
	})
	if err != nil {
		return err
	}
	defer m.Close()
	st0 := m.Status()
	log.Info("controller cluster member", "name", cfg.name, "advertise", cfg.advertised(ln), "role", st0.Cluster.Role,
		"leader", st0.Cluster.Leader, "schema", st0.Cluster.SchemaVersion, "rqliteJoin", strings.Join(cfg.join, ","))
	apiHandler := m.Handler()
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	// The web UI (internal/webui) is served beside the API it calls, at every path outside /api/,
	// and both only to the addresses of the admin source allowlist (SDN-39, #232).
	sources := api.NewSources(st, log, adminSourcesTTL).WithAudit(audit.NewLog(st, log))
	tlsPort := &port.Server{TLS: tlsCfg, Control: m.ServeStream, HTTP: webHandler(sources, apiHandler), Log: log}
	defer tlsPort.Close()
	go func() { errc <- tlsPort.Serve(ln) }()
	log.Info("TLS port", "address", ln.Addr().String(), "protocols", "ranz-control/1, h2, http/1.1")

	if cfg.controlListen != "" {
		cln, err := net.Listen("tcp", cfg.controlListen)
		if err != nil {
			return fmt.Errorf("-control-listen: %w", err)
		}
		dev := &port.Server{TLS: tlsCfg, Control: m.ServeStream, Log: log}
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
	if h.ready != nil {
		h.ready()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	log.Info("controller stopping")
	return serveErr
}

// listenTLS listens on the TLS port addr. When addr is the default (explicit false), a port that
// cannot be bound makes it listen on the port fallback of the same host instead, and record that
// in the data directory; a recorded fallback is used again at the next start, also when addr is
// free by then (ADR-0020). fell reports a fallback. An explicit addr is used as it is and drops
// the record.
func listenTLS(addr, fallback string, explicit bool, dataDir string) (ln net.Listener, fell bool, err error) {
	record := filepath.Join(dataDir, fallbackFile)
	if explicit {
		if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false, err
		}
		ln, err := net.Listen("tcp", addr)
		return ln, false, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, false, err
	}
	fallbackAddr := net.JoinHostPort(host, fallback)
	if _, err := os.Stat(record); err == nil {
		ln, err := net.Listen("tcp", fallbackAddr)
		return ln, err == nil, err
	}
	ln, err = net.Listen("tcp", addr)
	if err == nil {
		return ln, false, nil
	}
	ln, ferr := net.Listen("tcp", fallbackAddr)
	if ferr != nil {
		return nil, false, fmt.Errorf("%w, and the fallback %s: %w", err, fallbackAddr, ferr)
	}
	note := fmt.Sprintf("%s could not be bound (%v), so the TLS port is %s; remove this file or start with an explicit -listen to go back\n", addr, err, fallbackAddr)
	if werr := os.WriteFile(record, []byte(note), 0o600); werr != nil {
		ln.Close()
		return nil, false, fmt.Errorf("recording the fallback to %s: %w", fallbackAddr, werr)
	}
	return ln, true, nil
}

// webHandler is what the TLS port serves besides the control stream: the web UI and the API
// behind it (apiHandler), both behind the admin source allowlist, so that a request from an
// address outside it is refused whatever it asks for, the pages of the UI included.
func webHandler(sources *api.Sources, apiHandler http.Handler) http.Handler {
	return sources.Restrict(webui.Handler(apiHandler))
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
