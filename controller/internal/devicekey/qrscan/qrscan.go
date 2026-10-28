// Package qrscan reads the QR code of a picture, as the camera of a phone does. The tests of the QR code
// of the configuration of a WireGuard Device (SDN-82 #377) scan what the controller, ranz and the web UI
// show, and compare the text of the code with the configuration that they show beside it. Only tests
// import it: no program of ranz links it, and so none carries the library that reads the code.
package qrscan

import (
	"fmt"
	"image"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Scan returns the text of the QR code in img. It is an error when the picture holds none, or one that
// cannot be read.
func Scan(img image.Image) (string, error) {
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("qrscan: %w", err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bitmap, nil)
	if err != nil {
		return "", fmt.Errorf("qrscan: no QR code can be read: %w", err)
	}
	return result.GetText(), nil
}
