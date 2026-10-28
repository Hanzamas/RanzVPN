package qrscan_test

import (
	"encoding/base64"
	"fmt"
	"image"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
)

// configuration is a finished configuration of a Device as the controller writes it, with the places of its
// private key and of its PresharedKey.
const configuration = `# Ranz VPN: the WireGuard configuration of Device phone, of Network lab-net in VRF lab
[Interface]
PrivateKey = %s
Address = 10.70.0.3/32, fd07:7:7:1::3/128
MTU = 1280

[Peer]
# The gateway, Node gw
PublicKey = ERERERERERERERERERERERERERERERERERERERERERE=
PresharedKey = %s
Endpoint = gw.example.net:51820
AllowedIPs = 10.70.0.0/24, fd07:7:7:1::/64
PersistentKeepalive = 25
`

// Scan returns the text that the QR code of the picture holds, and an error for a picture that holds none.
func TestScan(t *testing.T) {
	text := "[Interface]\nPrivateKey = not a key\nAddress = 10.0.0.2/32\n"
	rows, err := devicekey.Rows(text)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := qrscan.Scan(devicekey.Image(rows, 4)); err != nil || got != text {
		t.Errorf("Scan of the QR code of %q = %q, %v", text, got, err)
	}

	blank := image.NewGray(image.Rect(0, 0, 100, 100))
	for i := range blank.Pix {
		blank.Pix[i] = 0xff
	}
	if got, err := qrscan.Scan(blank); err == nil || !strings.Contains(err.Error(), "no QR code") {
		t.Errorf("Scan of a blank picture = %q, %v, want an error that says there is no QR code", got, err)
	}
}

// TestScanReadsEveryConfiguration: the keys of a configuration differ in every run, and so does the code that
// draws it, and the search for the corners of a code read none once (the controller test of the QR code
// failed with "dimension = 55"). Scan reads the code of each of a hundred configurations, at the scale that
// the tests draw at and at the one of the web page. The keys come from a fixed seed, so that every run reads
// the same hundred codes.
func TestScanReadsEveryConfiguration(t *testing.T) {
	rng := rand.New(rand.NewPCG(377, 82))
	key := func() string {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(rng.Uint32())
		}
		return base64.StdEncoding.EncodeToString(k)
	}
	for n := range 100 {
		text := fmt.Sprintf(configuration, key(), key())
		rows, err := devicekey.Rows(text)
		if err != nil {
			t.Fatal(err)
		}
		for _, scale := range []int{3, 6} {
			if got, err := qrscan.Scan(devicekey.Image(rows, scale)); err != nil || got != text {
				t.Fatalf("configuration %d: the code of %d modules drawn at scale %d reads as %q, %v, want\n%s", n, len(rows), scale, got, err, text)
			}
		}
	}
}
