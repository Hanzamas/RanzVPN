package controllercmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// How the controller reaches its rqlite and how the members of a cluster reach each other
// (AUD1-DT-8, ADR-0026 amendment of 2026-10-27): rqlited runs with -auth, the store client and
// reset-admin, backup and restore send the credential, and the members of a cluster use mutual TLS
// on the Raft transport and the node API (rqlited -node-cert, -node-key, -node-ca-cert and -node-verify-client).

// rqliteAuthFile, in the data directory, is the credential file of rqlited (sidecar.WriteCredential).
// The first start of a single controller makes it with a random password; the data directory has
// the protected access list (makeDataDir), so a local process that is not the controller, an
// administrator or SYSTEM cannot read it.
const rqliteAuthFile = "rqlite-auth.json"

// checkRqlite is the part of parseFlags that checks how rqlite is reached.
func (cfg config) checkRqlite() error {
	if cfg.external {
		if err := store.CheckRqliteURL(cfg.rqliteURL); err != nil {
			return fmt.Errorf("-rqlite-external: -rqlite %w", err)
		}
	}
	n := 0
	for _, f := range []string{cfg.nodeCACert, cfg.nodeCert, cfg.nodeKey} {
		if f != "" {
			n++
		}
	}
	switch {
	case n != 0 && n != 3:
		return errors.New("-rqlite-node-ca-cert, -rqlite-node-cert and -rqlite-node-key go together")
	case n == 3 && cfg.external:
		return errors.New("-rqlite-node-ca-cert, -rqlite-node-cert and -rqlite-node-key are for the rqlite member of the controller, and -rqlite-external runs none")
	case len(cfg.join) > 0 && !cfg.external && n == 0:
		return errors.New("-rqlite-join needs -rqlite-node-ca-cert, -rqlite-node-cert and -rqlite-node-key: the members of a cluster use mutual TLS, so that a process without a certificate of the cluster CA cannot join")
	}
	return nil
}

// authPath returns the credential file: -rqlite-auth, else the one in the data directory.
func (cfg config) authPath() string {
	if cfg.rqliteAuth != "" {
		return cfg.rqliteAuth
	}
	return filepath.Join(cfg.dataDir, rqliteAuthFile)
}

// rqliteAccess returns how the controller reaches its rqlite: the credential of the file
// authPath names, and the CA of -rqlite-ca. It also returns that file, "" when there is none.
// With own the rqlited is the controller's own member: a single controller makes the file when it
// is missing (created), because its first start is the one that gives the store a credential, but
// a member of a cluster does not, because every member must hold the same credential, so it is an
// error there. Without own, a file that -rqlite-auth names must exist, and without that flag the
// rqlite at -rqlite is reached without a credential when the data directory has none.
func (cfg config) rqliteAccess(own bool) (a store.Access, authFile string, created bool, err error) {
	if cfg.rqliteCA != "" {
		if a.CA, err = os.ReadFile(cfg.rqliteCA); err != nil {
			return store.Access{}, "", false, fmt.Errorf("-rqlite-ca: %w", err)
		}
	}
	path := cfg.authPath()
	user, password, err := sidecar.ReadCredential(path)
	switch {
	case err == nil:
	case !errors.Is(err, fs.ErrNotExist):
		return store.Access{}, "", false, err
	case own && len(cfg.join) > 0:
		return store.Access{}, "", false, fmt.Errorf("a member of a cluster has the credential of the store from the other members: copy %s of the first member to %s, with the same access list", rqliteAuthFile, path)
	case own:
		if user, password, err = sidecar.WriteCredential(path); err != nil {
			return store.Access{}, "", false, err
		}
		created = true
	case cfg.rqliteAuth != "":
		return store.Access{}, "", false, err
	default:
		return a, "", false, nil
	}
	a.User, a.Password = user, password
	return a, path, created, nil
}

// member returns the rqlited of the controller's own member, which runs exe and listens for HTTP
// on rqliteHTTP, with its data, its credential file authFile ("" for none) and its certificates
// for the members of a cluster. The caller adds what differs between a run and the commands that
// start the member for a moment (the other members to join, the output).
func (cfg config) member(exe, rqliteHTTP, authFile string) (*sidecar.Rqlited, error) {
	rq := &sidecar.Rqlited{
		Path:     exe,
		DataDir:  filepath.Join(cfg.dataDir, "rqlite"),
		HTTPAddr: rqliteHTTP,
		RaftAddr: cfg.raftAddr,
		AuthFile: authFile,
	}
	if cfg.nodeCert != "" {
		var err error
		for _, f := range []struct {
			flag string
			path string
			to   *string
		}{
			{"-rqlite-node-ca-cert", cfg.nodeCACert, &rq.NodeCACert},
			{"-rqlite-node-cert", cfg.nodeCert, &rq.NodeCert},
			{"-rqlite-node-key", cfg.nodeKey, &rq.NodeKey},
		} {
			// rqlited runs in the working directory of the controller, which a service does not choose
			if *f.to, err = filepath.Abs(f.path); err != nil {
				return nil, fmt.Errorf("%s: %w", f.flag, err)
			}
			if _, err = os.Stat(*f.to); err != nil {
				return nil, fmt.Errorf("%s: %w", f.flag, err)
			}
		}
	}
	return rq, nil
}
