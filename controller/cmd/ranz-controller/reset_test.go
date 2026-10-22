package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// reset-admin refuses a caller without the rights of a local administrator before it reaches
// the store, which here answers nowhere: it creates no token and writes no admin.token.
func TestResetAdminRefusesWithoutAdminRights(t *testing.T) {
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = resetAdmin(context.Background(), cfg, func() error { return errNoAdminRights }, io.Discard)
	if !errors.Is(err, errNoAdminRights) {
		t.Errorf("reset-admin without the rights of an administrator gave %v, want %v", err, errNoAdminRights)
	}
	if _, err := os.Stat(filepath.Join(dir, adminTokenFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused reset-admin left %s in the data directory (%v)", adminTokenFile, err)
	}
}

// reset-admin runs on the controller's host only: without the data directory of the service it
// is refused before it reaches the store.
func TestResetAdminNeedsTheDataDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "none")
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = resetAdmin(context.Background(), cfg, func() error { return nil }, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("reset-admin without the data directory gave %v, want an error that names it", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused reset-admin made the data directory %s (%v)", dir, err)
	}
}

// With the rights, reset-admin creates a new admin token in the store of the running service,
// beside the admin token whose secret is lost, and writes its secret to admin.token.
func TestResetAdmin(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	tokens := rbac.New(st)
	if _, err := tokens.Bootstrap(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", rq.URL()})
	if err != nil {
		t.Fatal(err)
	}
	tok, file, err := resetAdmin(ctx, cfg, func() error { return nil }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if file != filepath.Join(dir, adminTokenFile) || tok.Role != rbac.Admin || !strings.HasPrefix(tok.Name, "admin-") {
		t.Errorf("reset-admin gave the token %+v in %s, want an admin token in %s", tok.Token, file, filepath.Join(dir, adminTokenFile))
	}
	b, err := os.ReadFile(file)
	if err != nil || string(b) != tok.Secret+"\n" {
		t.Errorf("%s holds %q (%v), want the secret of the new token", file, b, err)
	}
	if got, err := tokens.Authenticate(ctx, tok.Secret); err != nil || got != tok.Token {
		t.Errorf("the new secret authenticates as %+v, %v", got, err)
	}
	ts, err := tokens.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 || ts[0].Name != rbac.FirstAdmin {
		t.Errorf("after reset-admin the tokens are %+v, want %s and the new one", ts, rbac.FirstAdmin)
	}
}
