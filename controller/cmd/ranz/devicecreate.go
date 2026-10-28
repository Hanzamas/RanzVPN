package main

import (
	"context"
	"flag"
	"fmt"
	"image/png"
	"io"
	"os"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
)

// The command that makes a WireGuard Device with its keys (SDN-82 #377), which main.go hands the
// arguments that follow device create:
//
//	ranz device create -network NETWORK -gateway NODE [flags] NAME
//
// The controller makes the key pair and the PresharedKey of the Device, and ranz prints the finished
// WireGuard configuration, the text of a .conf file that a stock client imports, to standard output, or
// writes it to the file of -o (readable by its owner only). -qr draws the QR code of the configuration on
// standard error, for the WireGuard app of a phone to scan, and -qr-file writes it as a PNG file. The
// configuration and the QR code hold the private key and the PresharedKey of the Device, which show only
// now: the controller never stores the private key, and shows the PresharedKey once. With -public-key
// the administrator supplies the public key of the Device, a router or an advanced user that holds the
// private key itself, and the controller makes only the PresharedKey. The flags are:
//
//	-network NETWORK     the L3 Network that the Device joins
//	-gateway NODE        the Node that terminates its WireGuard
//	-owner USER          the User that the Device is a device of: it carries the groups of the User as tags
//	-tags A,B            the tags set on the Device, which a standalone Device takes
//	-battery-saver       turn the keepalive of the configuration off
//	-public-key KEY      the WireGuard public key of the Device, base64
//	-no-preshared-key    leave the PresharedKey out
//	-o FILE              write the configuration to FILE instead of standard output
//	-qr                  draw the QR code on standard error
//	-qr-file FILE        write the QR code as a PNG file

// qrScale is the pixels to a module of the PNG file of the QR code.
const qrScale = 8

// createDevice makes the Device of args, the arguments after device create, and prints its
// configuration to out; the notes and the QR code go to errOut.
func createDevice(ctx context.Context, c *api.Client, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("device create", flag.ContinueOnError)
	network := flags.String("network", "", "the L3 Network that the Device joins")
	gateway := flags.String("gateway", "", "the Node that terminates the WireGuard of the Device")
	owner := flags.String("owner", "", "the User that the Device is a device of, whose groups are tags of the Device")
	tags := flags.String("tags", "", "the tags set on the Device, separated by commas")
	saver := flags.Bool("battery-saver", false, "turn the keepalive of the configuration off")
	publicKey := flags.String("public-key", "", "the WireGuard public key of the Device, base64, when you hold its private key; the controller then makes none")
	noPreshared := flags.Bool("no-preshared-key", false, "leave the PresharedKey out")
	file := flags.String("o", "", "write the configuration to this file instead of standard output")
	qr := flags.Bool("qr", false, "draw the QR code of the configuration on standard error")
	qrFile := flags.String("qr-file", "", "write the QR code of the configuration to this PNG file")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || *network == "" || *gateway == "" {
		return errUsage
	}
	created, err := c.CreateDevice(ctx, controller.DeviceRequest{Name: flags.Arg(0), Network: *network, Gateway: *gateway, Owner: *owner,
		Tags: splitList(*tags), BatterySaver: *saver, PublicKey: *publicKey, NoPresharedKey: *noPreshared})
	if err != nil {
		return err
	}

	// The configuration shows once, so whatever fails below, it reaches the person who made the Device
	written := false
	if *file != "" {
		if err := os.WriteFile(*file, []byte(created.Config), 0o600); err != nil {
			fmt.Fprintf(errOut, "ranz: the configuration could not be written to %s, so it is printed here instead: %v\n", *file, err)
		} else {
			written = true
		}
	}
	if !written {
		if _, err := io.WriteString(out, created.Config); err != nil {
			return err
		}
	}
	fmt.Fprintf(errOut, "ranz: Device %s is made as revision %d.%s\n", created.Name, created.Revision, shownOnce(created))
	if *qr {
		fmt.Fprint(errOut, qrText(created.QR))
	}
	if *qrFile != "" {
		f, err := os.OpenFile(*qrFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		err = png.Encode(f, created.QRImage(qrScale))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("the QR code could not be written to %s: %w", *qrFile, err)
		}
	}
	return nil
}

// shownOnce returns the sentence that says which keys of the configuration of created show only now.
func shownOnce(created controller.DeviceCreated) string {
	switch {
	case created.KeyMade && created.PresharedKey:
		return " The private key and the PresharedKey in its configuration show only now: the controller keeps no private key, and shows the PresharedKey once."
	case created.KeyMade:
		return " The private key in its configuration shows only now: the controller keeps no private key."
	case created.PresharedKey:
		return " The PresharedKey in its configuration shows only now; the private key stays with the Device."
	}
	return ""
}

// qrText draws the QR code that rows hold for a terminal: black on white with the quiet zone of 4
// modules, two rows of modules to a line in half blocks. The colours are set, so that the code reads the
// same on a dark theme as on a light one.
func qrText(rows []string) string {
	size := len(rows) + 2*devicekey.Quiet
	dark := func(x, y int) bool {
		return devicekey.Dark(rows, x-devicekey.Quiet, y-devicekey.Quiet)
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		b.WriteString("\x1b[30;47m")
		for x := range size {
			switch upper, lower := dark(x, y), dark(x, y+1); {
			case upper && lower:
				b.WriteString("█")
			case upper:
				b.WriteString("▀")
			case lower:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}
