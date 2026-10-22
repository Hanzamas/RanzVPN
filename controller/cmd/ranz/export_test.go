package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
)

// `ranz export -o yaml` writes an intent document that `ranz import -f` reads back (SDN-52,
// #245): the intent exported, emptied and imported again is the same intent.
func TestExportYAMLImportsBack(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	if _, err := cli.Apply(ctx, mustDocument(t, lab)); err != nil {
		t.Fatal(err)
	}
	before, err := cli.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := do(ctx, cli, []string{"export", "-o", "yaml"}, &out); err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(bytes.TrimSpace(out.Bytes()), []byte("{")) {
		t.Fatalf("ranz export -o yaml printed JSON:\n%s", out.Bytes())
	}
	file := filepath.Join(t.TempDir(), "intent.yaml")
	if err := os.WriteFile(file, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Rollback(ctx, 0); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := do(ctx, cli, []string{"import", "-f", file}, &out); err != nil {
		t.Fatal(err)
	}
	after, err := cli.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Errorf("the intent imported from the YAML export is %+v, want %+v", after, before)
	}
	if err := do(ctx, cli, []string{"export", "-o", "xml"}, &out); !errors.Is(err, errUsage) {
		t.Errorf("ranz export -o xml: %v, want the usage", err)
	}
}
