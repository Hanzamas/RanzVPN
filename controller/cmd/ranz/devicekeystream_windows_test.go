//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
)

// TestDeviceCreateRefusesAStreamOfAFile is the third criterion of SDN-82-R2 on Windows: a name with a colon in its last
// element, as notes.txt:phone.conf, makes a stream of the file notes.txt when that file exists, and the stream has the access
// list of notes.txt, not the protected list of a key file, so the keys of the Device would be in a stream that every account
// that reads notes.txt reads. ranz refuses such a name for -o and for -qr-file before it asks the controller to make the
// Device, so nothing is made and nothing is printed, the file keeps what it holds, and no stream is made.
func TestDeviceCreateRefusesAStreamOfAFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The volume of the test keeps streams, so that it is the refusal that stops one and the test cannot pass for want of them
	if err := os.WriteFile(notes+":probe", []byte("probe"), 0o600); err != nil {
		t.Fatalf("a name with a colon makes no stream on the volume of the test, which the test needs: %v", err)
	}

	stream := notes + ":phone.conf"
	for _, option := range []string{"-o", "-qr-file"} {
		cli, sent := deviceController(t, madePhone(t), 0)
		var out, errOut bytes.Buffer
		err := createDevice(ctx, cli, []string{"-network", "lab-net", "-gateway", "gw", option, stream, "phone"}, &out, &errOut)
		if !errors.Is(err, certgen.ErrStream) || !strings.Contains(err.Error(), "nothing is made") {
			t.Errorf("ranz device create %s %s gave %v, want a refusal that says that the colon makes a stream and that nothing is made", option, stream, err)
		}
		if sent.Name != "" {
			t.Errorf("ranz device create %s %s asked the controller to make %+v", option, stream, *sent)
		}
		if out.Len() != 0 || errOut.Len() != 0 {
			t.Errorf("ranz device create %s %s printed %q and %q", option, stream, out.String(), errOut.String())
		}
	}
	if _, err := os.Stat(stream); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the stream %s exists after the refusals: %v", stream, err)
	}
	if b, err := os.ReadFile(notes); err != nil || string(b) != "notes" {
		t.Errorf("notes.txt holds %q (%v) after the refusals, want what it held", b, err)
	}
}
