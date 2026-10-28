// Package qrscan reads the QR code of a picture. The tests of the QR code of the configuration of a
// WireGuard Device (SDN-82 #377) scan what the controller, ranz and the web UI show, and compare the text
// of the code with the configuration that they show beside it. Only tests import it: no program of ranz
// links it, and so none carries the library that reads the code.
package qrscan

import (
	"fmt"
	"image"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Scan returns the text of the QR code in img. It is an error when the picture holds none, or one that
// cannot be read.
//
// The pictures that the tests scan are drawings of the controller, of ranz and of the web UI: the code with
// its quiet zone and nothing else, and every module a square of whole pixels. The reader takes the grid of
// such a picture from its geometry (the pure mode of the library), which is exact. The search for the three
// finder patterns that a camera needs comes second: it skips rows and picks the three patterns that look
// most like the corners of a code, and with the keys of a configuration, which differ in every run, it
// read no code in a picture that was right (NotFoundException "dimension = 55", at two scales of the same
// code), so a test that began with it failed once in a while.
func Scan(img image.Image) (string, error) {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("qrscan: %w", err)
	}
	reader := qrcode.NewQRCodeReader()
	result, drawn := reader.Decode(bitmap, map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_PURE_BARCODE: true})
	if drawn != nil {
		var searched error
		if result, searched = reader.Decode(bitmap, map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}); searched != nil {
			return "", fmt.Errorf("qrscan: no QR code can be read: %w; the search for its corners: %v", drawn, searched)
		}
	}
	return result.GetText(), nil
}
