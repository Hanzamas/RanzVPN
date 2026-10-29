package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
)

// deviceConfig is the finished configuration that the controller answers the making of Device phone with
// in these tests: the keys of the Device are in it, which only that answer holds.
const deviceConfig = `# Ranz VPN: the WireGuard configuration of Device phone, of Network lab-net in VRF lab
[Interface]
PrivateKey = oB7+uwO0wrnQpmM0v9YEbQnl1ZNo1vKyuxqmyXMZ9mE=
Address = 10.70.0.3/32, fd07:7:7:1::3/128
MTU = 1280

[Peer]
# The gateway, Node gw
PublicKey = EREREREREREREREREREREREREREREREREREREREREQ=
PresharedKey = Vv3fKHXY8l1b3xvq9sTDzv0q8c7oJ9j0bN1Bv0W0m5k=
Endpoint = gw.example.net:51820
AllowedIPs = 10.70.0.0/24, fd07:7:7:1::/64
PersistentKeepalive = 25
`

// deviceController is a controller of the tests of ranz device create: it answers POST /api/v1/devices
// with made, or with the status refusal when that is not 0, and keeps the request that it got.
func deviceController(t *testing.T, made controller.DeviceCreated, refusal int) (*api.Client, *controller.DeviceRequest) {
	t.Helper()
	var got controller.DeviceRequest
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/devices" {
			t.Errorf("ranz called %s %s, want POST /api/v1/devices", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			t.Errorf("the body of the call is no Device to make: %v", err)
		}
		if refusal != 0 {
			w.WriteHeader(refusal)
			_ = json.NewEncoder(w).Encode(api.Problem{Error: `Device "phone" exists already`})
			return
		}
		_ = json.NewEncoder(w).Encode(made)
	}))
	t.Cleanup(srv.Close)
	return &api.Client{URL: srv.URL, Token: "ranz_test", HTTP: srv.Client()}, &got
}

// madePhone is the answer to the making of Device phone with its keys made by the controller.
func madePhone(t *testing.T) controller.DeviceCreated {
	t.Helper()
	rows, err := devicekey.Rows(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	return controller.DeviceCreated{Name: "phone", Revision: 7, PublicKey: "ENFlsy6D1xWNwQGMeJBwTTTpf3JxJxqoGB5s5MCzC1s=",
		KeyMade: true, PresharedKey: true, Config: deviceConfig, QR: rows}
}

// scanTerminalQR reads the QR code that qrText drew for a terminal in text: each line of the code, which
// the colour codes of qrText start and end, holds two rows of modules in half blocks.
func scanTerminalQR(t *testing.T, text string) string {
	t.Helper()
	var lines [][]rune
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(line, "\x1b[30;47m"); ok {
			lines = append(lines, []rune(strings.TrimSuffix(rest, "\x1b[0m")))
		}
	}
	if len(lines) == 0 {
		t.Fatalf("the terminal shows no QR code:\n%s", text)
	}
	const scale = 3
	img := image.NewGray(image.Rect(0, 0, len(lines[0])*scale, len(lines)*2*scale))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	black := func(x, row int) {
		for dy := range scale {
			for dx := range scale {
				img.SetGray(x*scale+dx, row*scale+dy, color.Gray{Y: 0})
			}
		}
	}
	for y, line := range lines {
		for x, r := range line {
			if r == '█' || r == '▀' {
				black(x, 2*y)
			}
			if r == '█' || r == '▄' {
				black(x, 2*y+1)
			}
		}
	}
	got, err := qrscan.Scan(img)
	if err != nil {
		t.Fatalf("the QR code on the terminal cannot be read: %v", err)
	}
	return got
}

// TestDeviceCreate is the command of the first criteria of SDN-82 (#377): ranz device create prints the
// finished configuration, which holds the keys of the Device, and says that they show only now; its QR
// code, on the terminal and in a PNG file, reads as exactly that configuration; and the flags are the
// Device that the controller is asked to make.
func TestDeviceCreate(t *testing.T) {
	ctx := context.Background()
	made := madePhone(t)
	cli, sent := deviceController(t, made, 0)

	var out, errOut bytes.Buffer
	file := filepath.Join(t.TempDir(), "phone.png")
	args := []string{"-network", "lab-net", "-gateway", "gw", "-owner", "alice", "-tags", "b, a,,", "-battery-saver", "-qr", "-qr-file", file, "phone"}
	if err := createDevice(ctx, cli, args, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if want := (controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", Owner: "alice", Tags: []string{"b", "a"}, BatterySaver: true}); !reflect.DeepEqual(*sent, want) {
		t.Errorf("the controller was asked to make %+v, want %+v", *sent, want)
	}
	if out.String() != deviceConfig {
		t.Errorf("ranz printed\n%s\nwant the configuration\n%s", out.String(), deviceConfig)
	}
	for _, want := range []string{"Device phone is made as revision 7.", "The private key and the PresharedKey in its configuration show only now"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("ranz said %q, want %q", errOut.String(), want)
		}
	}
	if strings.Contains(errOut.String(), "PrivateKey") || strings.Contains(errOut.String(), "oB7+uwO0") {
		t.Errorf("ranz said a key on its standard error: %q", errOut.String())
	}

	// The QR code on the terminal and the one in the file read as the configuration that was printed
	if got := scanTerminalQR(t, errOut.String()); got != out.String() {
		t.Errorf("the QR code on the terminal reads as\n%s\nwant\n%s", got, out.String())
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := qrscan.Scan(img); err != nil || got != out.String() {
		t.Errorf("the QR code of the PNG file reads as %q, %v, want the configuration that was printed", got, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the PNG file has the mode %v, %v: it holds the keys of the Device, so its owner alone reads it", info.Mode(), err)
		}
	}
}

// TestDeviceCreateWithAKeyOfYourOwn: with -public-key the administrator supplies the key of a router, and
// -no-preshared-key leaves the PresharedKey out; ranz then says only what the controller showed.
func TestDeviceCreateWithAKeyOfYourOwn(t *testing.T) {
	made := madePhone(t)
	made.KeyMade = false
	cli, sent := deviceController(t, made, 0)
	var out, errOut bytes.Buffer
	if err := createDevice(context.Background(), cli, []string{"-network", "lab-net", "-gateway", "gw", "-public-key", made.PublicKey, "phone"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if sent.PublicKey != made.PublicKey || sent.NoPresharedKey {
		t.Errorf("the controller was asked to make %+v, want the key of the router and a PresharedKey", *sent)
	}
	if want := "The PresharedKey in its configuration shows only now; the private key stays with the Device."; !strings.Contains(errOut.String(), want) {
		t.Errorf("ranz said %q, want %q", errOut.String(), want)
	}

	made.PresharedKey = false
	cli, sent = deviceController(t, made, 0)
	errOut.Reset()
	if err := createDevice(context.Background(), cli, []string{"-network", "lab-net", "-gateway", "gw", "-public-key", made.PublicKey, "-no-preshared-key", "phone"}, io.Discard, &errOut); err != nil {
		t.Fatal(err)
	}
	if !sent.NoPresharedKey {
		t.Errorf("the controller was asked to make %+v, want no PresharedKey", *sent)
	}
	if strings.Contains(errOut.String(), "show only now") || strings.Contains(errOut.String(), "shows only now") {
		t.Errorf("ranz said %q for a Device with no key to show", errOut.String())
	}
}

// TestDeviceCreateToAFile: with -o the configuration goes to a file that its owner alone reads, and not to
// the terminal; a file that cannot be written does not lose it, since it shows only once: it is printed.
func TestDeviceCreateToAFile(t *testing.T) {
	ctx := context.Background()
	cli, _ := deviceController(t, madePhone(t), 0)
	dir := t.TempDir()
	file := filepath.Join(dir, "phone.conf")
	var out, errOut bytes.Buffer
	if err := createDevice(ctx, cli, []string{"-network", "lab-net", "-gateway", "gw", "-o", file, "phone"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != deviceConfig {
		t.Errorf("the file holds %q, %v, want the configuration", b, err)
	}
	if out.Len() != 0 {
		t.Errorf("ranz printed %q besides the file", out.String())
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the file has the mode %v, %v: it holds the keys of the Device, so its owner alone reads it", info.Mode(), err)
		}
	}

	out.Reset()
	errOut.Reset()
	missing := filepath.Join(dir, "no", "such", "folder", "phone.conf")
	if err := createDevice(ctx, cli, []string{"-network", "lab-net", "-gateway", "gw", "-o", missing, "phone"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if out.String() != deviceConfig || !strings.Contains(errOut.String(), "so it is printed here instead") {
		t.Errorf("a file that cannot be written gave %q on the standard output and %q on the standard error", out.String(), errOut.String())
	}

	// A PNG file that cannot be written is an error, and the configuration was shown before it
	out.Reset()
	if err := createDevice(ctx, cli, []string{"-network", "lab-net", "-gateway", "gw", "-qr-file", missing, "phone"}, &out, io.Discard); err == nil || out.String() != deviceConfig {
		t.Errorf("a QR file that cannot be written gave %v, and the configuration %q", err, out.String())
	}
}

// TestDeviceCreateRefused: what the controller refuses reaches the administrator as the refusal of the API,
// and nothing is printed.
func TestDeviceCreateRefused(t *testing.T) {
	cli, _ := deviceController(t, controller.DeviceCreated{}, http.StatusConflict)
	var out, errOut bytes.Buffer
	err := createDevice(context.Background(), cli, []string{"-network", "lab-net", "-gateway", "gw", "phone"}, &out, &errOut)
	var e *api.Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict || !strings.Contains(e.Message, "exists already") {
		t.Errorf("a refusal gave %v, want 409 Conflict", err)
	}
	if out.Len() != 0 || errOut.Len() != 0 {
		t.Errorf("a refusal printed %q and %q", out.String(), errOut.String())
	}
}

// TestDeviceCreateUsage: the command takes one name, the Network and the gateway; ranz device takes create.
func TestDeviceCreateUsage(t *testing.T) {
	cli := &api.Client{}
	for _, args := range [][]string{
		nil,
		{"phone"},
		{"-network", "lab-net", "phone"},
		{"-gateway", "gw", "phone"},
		{"-network", "lab-net", "-gateway", "gw"},
		{"-network", "lab-net", "-gateway", "gw", "phone", "laptop"},
		{"-bogus", "-network", "lab-net", "-gateway", "gw", "phone"},
	} {
		if err := createDevice(context.Background(), cli, args, io.Discard, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz device create %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
	for _, args := range [][]string{{"device"}, {"device", "make"}} {
		if err := do(context.Background(), cli, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}

// TestDeviceCreateIsACommandOfRanz: ranz device create is one of the commands of ranz, and its answer is the one that
// the API gave: the API client of ranz makes the call.
func TestDeviceCreateIsACommandOfRanz(t *testing.T) {
	cli, sent := deviceController(t, madePhone(t), 0)
	var out bytes.Buffer
	if err := do(context.Background(), cli, []string{"device", "create", "-network", "lab-net", "-gateway", "gw", "phone"}, &out); err != nil {
		t.Fatal(err)
	}
	if sent.Name != "phone" || out.String() != deviceConfig {
		t.Errorf("ranz device create asked for %+v and printed %q", *sent, out.String())
	}
}
