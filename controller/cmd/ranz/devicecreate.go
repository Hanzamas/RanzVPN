package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
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
// writes it to the file of -o. -qr draws the QR code of the configuration on standard error, for the
// WireGuard app of a phone to scan, and -qr-file writes it as a PNG file. The configuration and the QR
// code hold the private key and the PresharedKey of the Device, which show only now: the controller
// never stores the private key, and shows the PresharedKey once. So ranz writes them only to files that
// it makes for them, which only their owner reads, and on Windows SYSTEM and the Administrators, from the
// moment they exist (certgen.CreateKeyFile); a file that exists is refused before the Device is made
// (SDN-82-R1). With -public-key the administrator supplies the public key of the Device, a router or an
// advanced user that holds the private key itself, and the controller makes only the PresharedKey. The
// flags are:
//
//	-network NETWORK     the L3 Network that the Device joins
//	-gateway NODE        the Node that terminates its WireGuard
//	-owner USER          the User that the Device is a device of: it carries the groups of the User as tags
//	-tags A,B            the tags set on the Device, which a standalone Device takes
//	-battery-saver       turn the keepalive of the configuration off
//	-public-key KEY      the WireGuard public key of the Device, base64
//	-no-preshared-key    leave the PresharedKey out
//	-o FILE              write the configuration to FILE, a new file, instead of standard output
//	-qr                  draw the QR code on standard error; a scanner that does not read it there reads the
//	                     file of -qr-file
//	-qr-file FILE        write the QR code as a PNG file, a new file

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
	file := flags.String("o", "", "write the configuration to this new file, which only its owner reads, instead of standard output")
	qr := flags.Bool("qr", false, "draw the QR code of the configuration on standard error; when a scanner does not read it there, as on an old Windows console, use -qr-file")
	qrFile := flags.String("qr-file", "", "write the QR code of the configuration to this new PNG file, which only its owner reads")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || *network == "" || *gateway == "" {
		return errUsage
	}
	// The keys go only to new files: one that exists is refused before the Device is made (SDN-82-R1)
	if err := newKeyFiles(*file, *qrFile); err != nil {
		return err
	}
	created, err := c.CreateDevice(ctx, controller.DeviceRequest{Name: flags.Arg(0), Network: *network, Gateway: *gateway, Owner: *owner,
		Tags: splitList(*tags), BatterySaver: *saver, PublicKey: *publicKey, NoPresharedKey: *noPreshared})
	if err != nil {
		return err
	}

	// The configuration shows once, so whatever fails below, it reaches the person who made the Device
	written := false
	if *file != "" {
		if err := writeKeyFile(*file, []byte(created.Config), errOut); err != nil {
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
		// A console of Windows shows the colour codes only once its mode says so (SDN-82-R1)
		colours, restore := consoleColours(errOut)
		fmt.Fprint(errOut, qrText(created.QR, colours))
		restore()
	}
	if *qrFile != "" {
		var b bytes.Buffer
		err := png.Encode(&b, created.QRImage(qrScale))
		if err == nil {
			err = writeKeyFile(*qrFile, b.Bytes(), errOut)
		}
		if err != nil {
			return fmt.Errorf("the QR code could not be written to %s: %w", *qrFile, err)
		}
	}
	return nil
}

// newKeyFiles refuses file and qrFile, the files of -o and -qr-file, when one of them exists already, a
// link too, or both name one file. The keys of a Device go only to a file that ranz makes for them
// (writeKeyFile): a file that exists keeps the access list or the mode that it has, and may be open in
// another program, so it is refused before the Device is made, and nothing is lost. An empty name is no
// file.
func newKeyFiles(file, qrFile string) error {
	if file != "" && qrFile != "" && filepath.Clean(file) == filepath.Clean(qrFile) {
		return fmt.Errorf("-o and -qr-file name the same file, %s, and each needs a file of its own: nothing is made", file)
	}
	for _, path := range []string{file, qrFile} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s exists already, and ranz writes the keys of a Device only to a new file: name a file that does not exist, or delete this one; nothing is made", path)
		}
	}
	return nil
}

// writeKeyFile writes data, which holds the keys of a Device, to the file path, which it makes for them:
// readable by its owner only, and on Windows by SYSTEM and the Administrators too, from the moment it
// exists (certgen.CreateKeyFile). A file that exists, which appeared after newKeyFiles looked, is refused
// and keeps what it holds, and a file that could not be written whole is removed. A volume that keeps no
// access lists, such as a FAT drive on Windows, is written, and the note says who may read the file.
func writeKeyFile(path string, data []byte, errOut io.Writer) error {
	f, acls, err := certgen.CreateKeyFile(path)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	if !acls {
		fmt.Fprintf(errOut, "ranz: the volume of %s keeps no access lists, so every account of this computer may read the keys in it: delete it once the Device has imported it\n", path)
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

// qrText draws the QR code that rows hold for a terminal, with the quiet zone of 4 modules, two rows of
// modules to a line in half blocks. With colours, it sets them: black on white, so that the code reads the
// same on a dark theme as on a light one. Without, for a console that shows no colour codes but prints
// them as text, such as an old console of Windows (consoleColours), it has none and is drawn for the light
// text on the dark background of such a console: the blocks are the light modules, and the background is
// the dark ones (SDN-82-R1).
func qrText(rows []string, colours bool) string {
	size := len(rows) + 2*devicekey.Quiet
	// ink tells the modules that the blocks draw
	ink := func(x, y int) bool {
		dark := devicekey.Dark(rows, x-devicekey.Quiet, y-devicekey.Quiet)
		if colours {
			return dark
		}
		return !dark
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		if colours {
			b.WriteString("\x1b[30;47m")
		}
		for x := range size {
			switch upper, lower := ink(x, y), ink(x, y+1); {
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
		if colours {
			b.WriteString("\x1b[0m")
		}
		b.WriteByte('\n')
	}
	return b.String()
}
