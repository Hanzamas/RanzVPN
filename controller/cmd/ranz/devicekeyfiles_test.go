package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
)

// TestDeviceCreateRefusesAFileThatExists is the first criterion of SDN-82-R1: ranz device create writes the keys of a
// Device only to a new file, so a file of -o or -qr-file that exists, a link too, or one file for both, is refused
// before the controller is asked to make the Device. The file keeps what it holds, nothing is printed and nothing is
// made.
func TestDeviceCreateRefusesAFileThatExists(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	mine := filepath.Join(dir, "mine.conf")
	if err := os.WriteFile(mine, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"-o", mine},
		{"-qr-file", mine},
		{"-o", filepath.Join(dir, "phone.conf"), "-qr-file", filepath.Join(dir, ".", "phone.conf")},
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link.conf")
		if err := os.Symlink(filepath.Join(dir, "nowhere.conf"), link); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, []string{"-o", link})
	}
	for _, files := range cases {
		cli, sent := deviceController(t, madePhone(t), 0)
		var out, errOut bytes.Buffer
		args := append(append([]string{"-network", "lab-net", "-gateway", "gw"}, files...), "phone")
		err := createDevice(ctx, cli, args, &out, &errOut)
		if err == nil || !strings.Contains(err.Error(), "nothing is made") {
			t.Errorf("ranz device create %s gave %v, want a refusal that says that nothing is made", strings.Join(files, " "), err)
		}
		if sent.Name != "" {
			t.Errorf("ranz device create %s asked the controller to make %+v", strings.Join(files, " "), *sent)
		}
		if out.Len() != 0 || errOut.Len() != 0 {
			t.Errorf("ranz device create %s printed %q and %q", strings.Join(files, " "), out.String(), errOut.String())
		}
	}
	if b, err := os.ReadFile(mine); err != nil || string(b) != "mine" {
		t.Errorf("the file that exists holds %q (%v) after the refusals, want what it held", b, err)
	}
	for _, name := range []string{"phone.conf", "nowhere.conf"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refusal made the file %s: %v", name, err)
		}
	}
}

// TestDeviceCreateWritesOverNoFileThatAppears: a file of -o or -qr-file that another program makes while the controller
// makes the Device, after ranz looked, is not written over, since ranz makes its files itself (certgen.CreateKeyFile).
// The file keeps what it holds, the configuration, which shows once, is printed instead, and the PNG file is an error
// after it (SDN-82-R1).
func TestDeviceCreateWritesOverNoFileThatAppears(t *testing.T) {
	dir := t.TempDir()
	conf, qr := filepath.Join(dir, "phone.conf"), filepath.Join(dir, "phone.png")
	made := madePhone(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, path := range []string{conf, qr} {
			if err := os.WriteFile(path, []byte("theirs"), 0o644); err != nil {
				t.Error(err)
			}
		}
		_ = json.NewEncoder(w).Encode(made)
	}))
	t.Cleanup(srv.Close)
	cli := &api.Client{URL: srv.URL, Token: "ranz_test", HTTP: srv.Client()}

	var out, errOut bytes.Buffer
	err := createDevice(context.Background(), cli, []string{"-network", "lab-net", "-gateway", "gw", "-o", conf, "-qr-file", qr, "phone"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "the QR code could not be written to "+qr) {
		t.Errorf("a PNG file that appeared gave %v, want an error that says that the QR code could not be written", err)
	}
	if out.String() != deviceConfig || !strings.Contains(errOut.String(), "could not be written to "+conf+", so it is printed here instead") {
		t.Errorf("a file of -o that appeared gave %q on the standard output and %q on the standard error, want the configuration printed", out.String(), errOut.String())
	}
	for _, path := range []string{conf, qr} {
		if b, err := os.ReadFile(path); err != nil || string(b) != "theirs" {
			t.Errorf("the file %s holds %q (%v), want what the other program wrote", path, b, err)
		}
	}
}

// scanConsoleQR reads the QR code that qrText drew without colour codes in text, as a scanner reads it off a console that
// shows its light text on a dark background: the blocks are the light modules, two rows of modules to a line.
func scanConsoleQR(t *testing.T, text string) string {
	t.Helper()
	var lines [][]rune
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		lines = append(lines, []rune(line))
	}
	const scale = 3
	// The background of the console is black: every pixel that no block lights
	img := image.NewGray(image.Rect(0, 0, len(lines[0])*scale, len(lines)*2*scale))
	light := func(x, row int) {
		for dy := range scale {
			for dx := range scale {
				img.SetGray(x*scale+dx, row*scale+dy, color.Gray{Y: 0xff})
			}
		}
	}
	for y, line := range lines {
		for x, r := range line {
			if r == '█' || r == '▀' {
				light(x, 2*y)
			}
			if r == '█' || r == '▄' {
				light(x, 2*y+1)
			}
		}
	}
	got, err := qrscan.Scan(img)
	if err != nil {
		t.Fatalf("the QR code for a console without colour codes cannot be read: %v", err)
	}
	return got
}

// TestQRTextForAConsoleWithoutColours is the writer of the last criterion of SDN-82-R1: for a console that prints colour
// codes as text, an old console of Windows, the QR code has none, and a scanner reads it as the configuration off the
// light text on the dark background of such a console. With the colour codes it is black on white, which a scanner
// reads on any theme, and a writer that is no console takes them.
func TestQRTextForAConsoleWithoutColours(t *testing.T) {
	made := madePhone(t)
	plain := qrText(made.QR, false)
	if strings.ContainsRune(plain, '\x1b') {
		t.Errorf("the QR code for a console without colour codes holds some: %q", plain)
	}
	if got := scanConsoleQR(t, plain); got != deviceConfig {
		t.Errorf("the QR code for a console without colour codes reads as\n%s\nwant\n%s", got, deviceConfig)
	}
	if got := scanTerminalQR(t, qrText(made.QR, true)); got != deviceConfig {
		t.Errorf("the QR code with colour codes reads as\n%s\nwant\n%s", got, deviceConfig)
	}
	colours, restore := consoleColours(&bytes.Buffer{})
	restore()
	if !colours {
		t.Error("a writer that is no console gets the QR code without colour codes")
	}
}

// TestGetDevicesSaysAPresharedKeyDoesNotOpen is part of the third criterion of SDN-82-R1: ranz get devices prints what
// the controller lists of each Device, so a PresharedKey that does not open shows there.
func TestGetDevicesSaysAPresharedKeyDoesNotOpen(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/devices" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(api.DeviceList{Devices: []controller.DeviceStatus{{Name: "phone", Network: "lab-net", Gateway: "gw",
			PresharedKey: true, PresharedKeyDoesNotOpen: true}}})
	}))
	t.Cleanup(srv.Close)
	cli := &api.Client{URL: srv.URL, Token: "ranz_test", HTTP: srv.Client()}
	var out bytes.Buffer
	if err := do(context.Background(), cli, []string{"get", "devices"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"presharedKeyDoesNotOpen": true`) {
		t.Errorf("ranz get devices printed\n%s\nwant that the PresharedKey of phone does not open", out.String())
	}
}
