package devicekey

import (
	"fmt"
	"image"
	"image/color"

	"github.com/skip2/go-qrcode"
)

// The QR code of the finished configuration of a Device, which the WireGuard app of a phone scans to
// import it. The library draws it (github.com/skip2/go-qrcode, since no Windows API does), and the
// controller hands the modules to whoever shows it: the web UI draws them on a canvas, ranz on a
// terminal or into a PNG file (Image), so the controller never holds a picture and no client needs a
// QR library.

// Quiet is the quiet zone around a QR code, in modules: the 4 modules of white that a scanner needs.
const Quiet = 4

// Rows returns the QR code of text as its modules, one string for each row: a 1 for a dark module and a
// 0 for a light one, without the quiet zone. The error correction is level M, which a phone reads off a
// screen with a scratch on it, and level L for a text that M cannot hold. A text that L cannot hold
// either, more than 2953 bytes, is an error.
func Rows(text string) ([]string, error) {
	var q *qrcode.QRCode
	var err error
	for _, level := range []qrcode.RecoveryLevel{qrcode.Medium, qrcode.Low} {
		if q, err = qrcode.New(text, level); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("the QR code of the configuration: %w", err)
	}
	q.DisableBorder = true
	bitmap := q.Bitmap()
	rows := make([]string, len(bitmap))
	for y, row := range bitmap {
		line := make([]byte, len(row))
		for x, dark := range row {
			line[x] = '0'
			if dark {
				line[x] = '1'
			}
		}
		rows[y] = string(line)
	}
	return rows, nil
}

// Dark reports whether the module at column x and row y of the QR code that rows hold is dark: a module
// outside the code, in its quiet zone, is light.
func Dark(rows []string, x, y int) bool {
	return y >= 0 && y < len(rows) && x >= 0 && x < len(rows[y]) && rows[y][x] == '1'
}

// Image draws the QR code that rows hold as a picture: black modules on white, scale pixels to a
// module, with the quiet zone of Quiet modules around it. A scale below 1 is 1.
func Image(rows []string, scale int) *image.Gray {
	scale = max(scale, 1)
	side := (len(rows) + 2*Quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	for y, row := range rows {
		for x := range len(row) {
			if !Dark(rows, x, y) {
				continue
			}
			for dy := range scale {
				for dx := range scale {
					img.SetGray((x+Quiet)*scale+dx, (y+Quiet)*scale+dy, color.Gray{Y: 0})
				}
			}
		}
	}
	return img
}
