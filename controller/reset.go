package controllercmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The offline recovery of the admin access (SDN-14 follow-up of #190, decision of 2026-10-22):
// when nobody holds the secret of an admin token any more, a local administrator of the
// controller's host creates a new admin token with `ranz controller reset-admin`, which writes
// it to the store directly, not through the API, so it needs no token.

// resetTimeout bounds a reset-admin: the start of rqlited while the service is stopped, the
// connection to rqlite and the creation of the token.
const resetTimeout = 2 * time.Minute

// probeTimeout is how long reset-admin tries the rqlite of a running service before it starts
// rqlited itself (-rqlited).
const probeTimeout = 3 * time.Second

// runResetAdmin runs `ranz controller reset-admin [flags]`, with the flags of the service. It
// prints the new admin token as JSON with its secret, which it shows this once, and records the
// reset in the Application log on Windows.
func runResetAdmin(args []string) error {
	cfg, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()
	tok, file, err := resetAdmin(ctx, cfg, adminRights, os.Stderr)
	if err != nil {
		return err
	}
	who := "a local administrator"
	if u, err := user.Current(); err == nil {
		who = u.Username
	}
	msg := fmt.Sprintf("%s: %s created the admin token %q with reset-admin; its secret is in %s", serviceName, who, tok.Name, file)
	if err := noteReset(msg); err != nil {
		fmt.Fprintf(os.Stderr, "ranz controller reset-admin: recording the reset in the Application log: %v\n", err)
	}
	b, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	fmt.Fprintf(os.Stderr, "ranz controller reset-admin: the secret of the admin token %q is shown above this once, and is in %s\n", tok.Name, file)
	return nil
}

// resetAdmin creates a new admin token in the controller's store and writes its secret to
// admin.token in the data directory, as the first start does (rbac.Bootstrap), and returns the
// token with its secret and that file. It runs on the controller's host only: rights must
// allow it (adminRights), and the data directory of cfg must exist and must not be another
// account's (checkDataDirOwner). While the service runs, its rqlite answers at -rqlite; while it
// is stopped, resetAdmin runs the rqlited of the service (-rqlited, or the member of this
// executable) on the service's data for as long as it takes. out receives the output of that
// rqlited.
func resetAdmin(ctx context.Context, cfg config, rights func() error, out io.Writer) (rbac.NewToken, string, error) {
	if err := rights(); err != nil {
		return rbac.NewToken{}, "", err
	}
	if fi, err := os.Stat(cfg.dataDir); err != nil || !fi.IsDir() {
		return rbac.NewToken{}, "", fmt.Errorf("the data directory %s (-data) does not exist: reset-admin runs on the controller's host, with the flags of the service", cfg.dataDir)
	}
	if err := checkDataDirOwner(cfg.dataDir); err != nil {
		return rbac.NewToken{}, "", err
	}
	st, stop, err := openStore(ctx, cfg, out)
	if err != nil {
		return rbac.NewToken{}, "", err
	}
	defer stop()
	file := filepath.Join(cfg.dataDir, adminTokenFile)
	name := "admin-" + time.Now().UTC().Format("20060102-150405")
	tok, err := rbac.New(st).Recover(ctx, name, func(secret string) error {
		return os.WriteFile(file, []byte(secret+"\n"), 0o600)
	})
	if err != nil {
		return rbac.NewToken{}, "", fmt.Errorf("the admin token: %w", err)
	}
	return tok, file, nil
}

// openStore connects to the controller's rqlite: the one that answers at -rqlite, which is the
// service's while it runs, or else an rqlited of its own on the service's data, which stop stops
// again: the one that -rqlited names, or the member that this executable carries (rqlitedExe).
func openStore(ctx context.Context, cfg config, out io.Writer) (st *store.Store, stop func(), err error) {
	// The credential of the store, when the service made one (AUD1-DT-8); this command makes none
	access, authFile, _, aerr := cfg.rqliteAccess(false)
	if aerr != nil {
		return nil, nil, fmt.Errorf("the credential of the store: %w", aerr)
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	st, err = store.OpenWith(pctx, cfg.rqliteURL, access)
	cancel()
	if err == nil {
		return st, st.Close, nil
	}
	rqlited, perr := cfg.rqlitedExe()
	if perr != nil {
		return nil, nil, fmt.Errorf("%w: the rqlite member: %w", err, perr)
	}
	if rqlited == "" {
		return nil, nil, fmt.Errorf("%w: while the service is stopped, give the -rqlited it runs with", err)
	}
	u, err := url.Parse(cfg.rqliteURL)
	if err != nil || u.Host == "" {
		return nil, nil, fmt.Errorf("-rqlite %q is not a URL with a host:port", cfg.rqliteURL)
	}
	rq, err := cfg.member(rqlited, u.Host, authFile)
	if err != nil {
		return nil, nil, err
	}
	rq.Output = out
	sctx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	if err := rq.Start(sctx); err != nil {
		return nil, nil, err
	}
	if st, err = store.OpenWith(sctx, cfg.rqliteURL, access); err != nil {
		rq.Stop()
		return nil, nil, err
	}
	return st, func() { st.Close(); rq.Stop() }, nil
}
