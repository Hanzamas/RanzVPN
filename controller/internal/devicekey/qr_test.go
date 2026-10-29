package devicekey_test

import (
	"image/color"
	"slices"
	"strings"
	"testing"

	"github.com/skip2/go-qrcode"

	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
)

// config is a finished configuration of a Device, as the controller writes it (internal/intent,
// DeviceConfigWith): its lines end in line feeds, and it holds three keys of 44 characters.
const config = `# Ranz VPN: the WireGuard configuration of Device phone, of Network lab-net in VRF lab
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

// TestRowsDecodeToTheirText is the third criterion of SDN-82 (#377) for the modules: the QR code that Rows
// gives, drawn as a picture of any scale, is read by a scanner (qrscan) as exactly the text that it was
// made of, line feeds and all. The text may be as long as a QR code holds: level M holds a configuration
// that is a few Networks long, and level L the longest text that there is room for.
func TestRowsDecodeToTheirText(t *testing.T) {
	for _, c := range []struct {
		name, text string
		scale      int
	}{
		{"a word", "WireGuard", 6},
		{"a configuration", config, 4},
		{"a configuration, drawn small", config, 3},
		{"a text that only level L holds", strings.Repeat("aB!x", 625), 3},
		{"a text close to the most that level L holds", strings.Repeat("aB!x", 725), 3},
	} {
		rows, err := devicekey.Rows(c.text)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got, err := qrscan.Scan(devicekey.Image(rows, c.scale)); err != nil || got != c.text {
			t.Errorf("%s: the QR code reads as %q, %v, want %q", c.name, got, err, c.text)
		}
	}
}

// TestRowsLevel: a text that level M holds is drawn at level M, which a phone reads off a screen with a
// scratch on it, and one that it does not at level L.
func TestRowsLevel(t *testing.T) {
	for _, c := range []struct {
		text  string
		level qrcode.RecoveryLevel
	}{
		{config, qrcode.Medium},
		{strings.Repeat("aB!x", 625), qrcode.Low},
	} {
		q, err := qrcode.New(c.text, c.level)
		if err != nil {
			t.Fatal(err)
		}
		q.DisableBorder = true
		var want []string
		for _, row := range q.Bitmap() {
			var b strings.Builder
			for _, dark := range row {
				if dark {
					b.WriteByte('1')
				} else {
					b.WriteByte('0')
				}
			}
			want = append(want, b.String())
		}
		if got, err := devicekey.Rows(c.text); err != nil || !slices.Equal(got, want) {
			t.Errorf("the QR code of a text of %d bytes is not the one of level %d: %v", len(c.text), c.level, err)
		}
	}
}

// TestRowsRefusesTooMuch: a text that no QR code holds is an error that says what it was for.
func TestRowsRefusesTooMuch(t *testing.T) {
	if rows, err := devicekey.Rows(strings.Repeat("aB!x", 750)); err == nil || rows != nil || !strings.Contains(err.Error(), "the QR code of the configuration") {
		t.Errorf("a text of 3000 bytes gave %d rows and %v", len(rows), err)
	}
}

// TestRowsAreSquareAndBinary: every row of the modules is as long as there are rows, of 0 and 1 only.
func TestRowsAreSquareAndBinary(t *testing.T) {
	rows, err := devicekey.Rows(config)
	if err != nil {
		t.Fatal(err)
	}
	for y, row := range rows {
		if len(row) != len(rows) || strings.Trim(row, "01") != "" {
			t.Fatalf("row %d of %d is %q", y, len(rows), row)
		}
	}
}

// TestImage: the picture has the quiet zone of 4 modules of white around the modules, a dark module is a
// square of black of the size of the scale, and a scale below one is one.
func TestImage(t *testing.T) {
	rows := []string{"10", "01"}
	for _, scale := range []int{3, 1, 0, -5} {
		got := devicekey.Image(rows, scale)
		s := max(scale, 1)
		side := (len(rows) + 2*devicekey.Quiet) * s
		if b := got.Bounds(); b.Dx() != side || b.Dy() != side {
			t.Fatalf("the picture at scale %d is %dx%d, want %dx%d", scale, b.Dx(), b.Dy(), side, side)
		}
		for y := range side {
			for x := range side {
				mx, my := x/s-devicekey.Quiet, y/s-devicekey.Quiet
				want := color.Gray{Y: 0xff}
				if mx >= 0 && my >= 0 && mx < 2 && my < 2 && rows[my][mx] == '1' {
					want = color.Gray{Y: 0}
				}
				if got.GrayAt(x, y) != want {
					t.Fatalf("at scale %d the pixel (%d, %d), of the module (%d, %d), is %v, want %v", scale, x, y, mx, my, got.GrayAt(x, y), want)
				}
			}
		}
	}
	if got := devicekey.Image(nil, 4); got.Bounds().Dx() != 2*devicekey.Quiet*4 {
		t.Errorf("the picture of no modules is %d pixels wide", got.Bounds().Dx())
	}
}

// TestDark: only a module of the code that is a 1 is dark; the quiet zone and what is outside are light.
func TestDark(t *testing.T) {
	rows := []string{"10", "01"}
	for _, c := range []struct {
		x, y int
		want bool
	}{
		{0, 0, true}, {1, 0, false}, {0, 1, false}, {1, 1, true},
		{-1, 0, false}, {0, -1, false}, {2, 0, false}, {0, 2, false}, {-4, -4, false},
	} {
		if got := devicekey.Dark(rows, c.x, c.y); got != c.want {
			t.Errorf("Dark(%d, %d) = %v, want %v", c.x, c.y, got, c.want)
		}
	}
}
