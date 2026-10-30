package main

import (
	"encoding/binary"
	"math"
)

// The icon of the tray (SDN-55, #248) is a disc whose colour says what the tray shows. It is drawn here, in
// the bits of an icon resource, so that the executable carries no image file and no resource: the Windows
// code gives the bits to CreateIconFromResourceEx at the size that the notification area asks for.

// trayKind is what the icon of the tray shows
type trayKind int

const (
	trayGrey  trayKind = iota // nothing runs, or Ranz is turned off
	trayAmber                 // something is going on: Ranz connects, or signs in
	trayGreen                 // Ranz is connected
	trayRed                   // something is wrong that the user or an administrator solves
	trayKinds                 // the number of kinds
)

// trayColours are the fill and the ring of the disc of each kind, red, green and blue
var trayColours = [trayKinds][2][3]byte{
	trayGrey:  {{0x8A, 0x8F, 0x98}, {0x5C, 0x61, 0x69}},
	trayAmber: {{0xF0, 0xB4, 0x29}, {0xB0, 0x7C, 0x0C}},
	trayGreen: {{0x2F, 0xB4, 0x4F}, {0x1C, 0x7A, 0x33}},
	trayRed:   {{0xE2, 0x4B, 0x4B}, {0x9C, 0x24, 0x24}},
}

// iconBits returns the bits of an icon of size by size pixels as the shell reads them from an icon
// resource: a BITMAPINFOHEADER whose height is twice the size, the 32 bit pixels of the colour from the
// bottom row up (blue, green, red and alpha), and the AND mask, a bit for each pixel, with the rows
// padded to 4 bytes, in which 1 is a pixel that shows what is behind the icon. The icon is a disc with a
// margin of one pixel, filled with fill and ringed with ring, its edge antialiased in the alpha.
func iconBits(size int, kind trayKind) []byte {
	fill, ring := trayColours[kind][0], trayColours[kind][1]
	maskRow := (size + 31) / 32 * 4
	colour := size * size * 4
	bits := make([]byte, 40+colour+maskRow*size)
	binary.LittleEndian.PutUint32(bits[0:], 40)                           // biSize
	binary.LittleEndian.PutUint32(bits[4:], uint32(size))                 // biWidth
	binary.LittleEndian.PutUint32(bits[8:], uint32(size*2))               // biHeight: the colour and the mask
	binary.LittleEndian.PutUint16(bits[12:], 1)                           // biPlanes
	binary.LittleEndian.PutUint16(bits[14:], 32)                          // biBitCount
	binary.LittleEndian.PutUint32(bits[20:], uint32(colour+maskRow*size)) // biSizeImage
	centre := float64(size) / 2
	radius := centre - 1
	for y := range size {
		for x := range size {
			dx, dy := float64(x)+0.5-centre, float64(y)+0.5-centre
			distance := math.Sqrt(dx*dx + dy*dy)
			// 1 inside the disc, 0 outside it, and the share of the pixel that the disc covers on its edge
			cover := math.Max(0, math.Min(1, radius+0.5-distance))
			paint := fill
			if distance > radius-1.5 {
				paint = ring
			}
			row := size - 1 - y
			at := 40 + (row*size+x)*4
			bits[at], bits[at+1], bits[at+2], bits[at+3] = paint[2], paint[1], paint[0], byte(math.Round(cover*255))
			if cover == 0 {
				bits[40+colour+row*maskRow+x/8] |= 0x80 >> (x % 8)
			}
		}
	}
	return bits
}
