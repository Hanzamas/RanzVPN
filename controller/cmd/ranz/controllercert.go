package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"math"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The command of the certificate that the Controller serves on its TLS port (SDN-92, #397), which
// main.go hands the arguments that follow controller-cert:
//
//	ranz controller-cert show           print the certificate that the Controller serves: its subject, issuer,
//	                                    names, thumbprint, TLS fingerprint, expiry and source, and never a key
//	ranz controller-cert set [flags]    serve another certificate, from a file with its key (-cert and -key), a
//	                                    certificate of the Windows key storage by its thumbprint (-ksp) or an ACME
//	                                    service (-acme); the Controller checks it first and refuses it with the
//	                                    reason when it does not match its key, has expired, or does not name the
//	                                    host that the Nodes use (-host), and the certificate in use stays
//	ranz controller-cert clear          remove the setting: the Controller serves its own self-signed certificate
//
// The files and the thumbprint are on the host of the Controller, and the account that runs it must
// be able to read them. A certificate with another key than the one in use has another TLS
// fingerprint, which the Nodes pin: the Controller sends it to the Nodes that are connected before it
// serves the certificate. A Node that is not connected could not be told, so the command is refused
// with the names of the Nodes unless -force goes on without them.

// controllerCertCommand runs the command of args, the arguments after controller-cert.
func controllerCertCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "show":
		info, err := c.ControllerCertificate(ctx)
		if err != nil {
			return err
		}
		return show(out, info)
	case len(args) >= 1 && args[0] == "set":
		return controllerCertSet(ctx, c, args[1:], out)
	case len(args) >= 1 && args[0] == "clear":
		flags := flag.NewFlagSet("controller-cert clear", flag.ContinueOnError)
		force := flags.Bool("force", false, "go on although a Node that is not connected did not take the TLS fingerprint of the self-signed certificate")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() > 0 {
			return errUsage
		}
		res, err := c.ClearControllerCertificate(ctx, *force)
		if err != nil {
			return err
		}
		return show(out, res)
	}
	return errUsage
}

// controllerCertSet sets the certificate that the flags of args name.
func controllerCertSet(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("controller-cert set", flag.ContinueOnError)
	host := flags.String("host", "", "the host that the Nodes use to reach the Controller, a DNS name or an IP address, several separated by commas: the certificate must name each; with -acme it is the names")
	cert := flags.String("cert", "", "the file with the certificate in PEM form and the certificates that lead to its root, on the host of the Controller")
	key := flags.String("key", "", "the file with the private key of -cert in PEM form, not encrypted; the file of the certificate when it is left out")
	ksp := flags.String("ksp", "", "the SHA-1 thumbprint of a certificate of the My store of the host of the Controller whose key is in the Microsoft Software Key Storage Provider (Windows)")
	acme := flags.String("acme", "", "get the certificate of these DNS names, separated by commas, from an ACME service")
	directory := flags.String("acme-directory", "", "the https URL of the ACME directory; Let's Encrypt when it is left out")
	email := flags.String("acme-email", "", "the contact of the ACME account")
	httpPort := flags.Uint("acme-http-port", 0, "the TCP port of the HTTP-01 challenge when the Controller has no plain HTTP port of its own (-http-listen); 80 when it is left out")
	caFile := flags.String("acme-ca", "", "a PEM file on the host of the Controller with the roots of a private ACME service")
	renewDays := flags.Uint("acme-renew-days", 0, "renew the ACME certificate this many days before its end; 30 when it is left out")
	force := flags.Bool("force", false, "go on although a Node that is not connected did not take the new TLS fingerprint: it needs ranz node controller set with it")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 {
		return errUsage
	}
	sources := 0
	s := servercert.Setting{Hosts: splitList(*host)}
	if *cert != "" {
		s.File = &servercert.File{Certificate: *cert, Key: *key}
		sources++
	} else if *key != "" {
		return errors.New("-key goes with -cert")
	}
	if *ksp != "" {
		s.KSP = *ksp
		sources++
	}
	if *acme != "" {
		if *httpPort > math.MaxUint16 || *renewDays > math.MaxUint32 {
			return errors.New("-acme-http-port is not a port, or -acme-renew-days is more than a number of days")
		}
		s.ACME = &servercert.ACME{Directory: *directory, Email: *email, Names: splitList(*acme), HTTPPort: uint16(*httpPort), CAFile: *caFile, RenewDays: uint32(*renewDays)}
		sources++
	}
	if sources != 1 {
		return errors.New("name the source of the certificate: -cert (with -key), -ksp or -acme, one of them")
	}
	res, err := c.SetControllerCertificate(ctx, s, *force)
	if err != nil {
		return err
	}
	return show(out, res)
}
