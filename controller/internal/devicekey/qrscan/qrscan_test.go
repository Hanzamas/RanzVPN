package qrscan_test

import (
	"image"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
)

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
