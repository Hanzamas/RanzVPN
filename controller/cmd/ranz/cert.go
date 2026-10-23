package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// ranz cert makes a certificate, the successor of the tools MakeCert and MakeCert2048 of vpncmd
// (SDN-53, #246): a self-signed certificate or one that a CA signs, and the CA certificate that
// signs others, ECDSA P-256 as ADR-0022 sets for the new core or RSA. The key goes to a file, or on
// Windows it stays in the Microsoft Software Key Storage Provider and the certificate goes into the
// certificate store, linked to it, where the node finds the certificate of its listener. The
// package certgen holds the making.
func init() {
	register("cert", func(args []string) int { return runCert(args, os.Stdout, os.Stderr) })
}

const certUsage = `usage: ranz cert -cn NAME (-savecert FILE -savekey FILE | -ksp NAME) [flags]

ranz cert makes a certificate and its private key: ECDSA P-256, or RSA with -rsa. The certificate
is self-signed, or signed by a CA with -signcert and -signkey; -ca makes a CA certificate that can
sign others. The key goes to a file (-savekey, PKCS #8 in PEM). On Windows it can stay in the
Microsoft Software Key Storage Provider instead (-ksp), where it cannot be copied out, and the
certificate goes into the My certificate store, linked to the key: its thumbprint is what the
configuration of a node names. -savecert writes the certificate in PEM in both cases.
`

// certOptions are the flags of ranz cert.
type certOptions struct {
	name     certgen.Name
	serial   string
	days     int
	hosts    string
	ca       bool
	signCert string
	signKey  string
	signKSP  string
	saveCert string
	saveKey  string
	ksp      string
	machine  bool
	rsa      int
	force    bool
}

// runCert is `ranz cert`. It returns the exit code of the process: 0 when the certificate was
// made, 1 when it was not, and 2 for arguments that are wrong. It writes what it made to stdout.
func runCert(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz cert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o certOptions
	flags.StringVar(&o.name.CommonName, "cn", "", "the name (CN) of the certificate; when it is a host name or an IP address and -hosts is not given, the certificate is valid for that host")
	flags.StringVar(&o.name.Organization, "o", "", "the organization (O)")
	flags.StringVar(&o.name.OrganizationalUnit, "ou", "", "the organization unit (OU)")
	flags.StringVar(&o.name.Country, "c", "", "the country (C)")
	flags.StringVar(&o.name.State, "st", "", "the state (ST)")
	flags.StringVar(&o.name.Locality, "l", "", "the locality (L)")
	flags.StringVar(&o.serial, "serial", "", "the serial number in hexadecimal; a random one when it is left out")
	flags.IntVar(&o.days, "expires", certgen.DefaultDays, "the validity in days, 10950 at most; 0 is the default")
	flags.StringVar(&o.hosts, "hosts", "", "the DNS names and IP addresses that the certificate is valid for, separated by commas")
	flags.BoolVar(&o.ca, "ca", false, "make a CA certificate, which can sign other certificates")
	flags.StringVar(&o.signCert, "signcert", "", "the CA certificate (PEM) that signs the new certificate; without it the new one is self-signed")
	flags.StringVar(&o.signKey, "signkey", "", "the private key (PEM) of the CA certificate")
	flags.StringVar(&o.signKSP, "signksp", "", "the key of the CA certificate in the Microsoft Software Key Storage Provider (Windows), instead of -signkey")
	flags.StringVar(&o.saveCert, "savecert", "", "the file for the certificate (PEM)")
	flags.StringVar(&o.saveKey, "savekey", "", "the file for the private key (PKCS #8 in PEM, not encrypted)")
	flags.StringVar(&o.ksp, "ksp", "", "keep the key in the Microsoft Software Key Storage Provider (Windows) under this name, and put the certificate into the My store")
	flags.BoolVar(&o.machine, "machine", false, "with -ksp or -signksp: the machine key set and the LocalMachine store, which need an administrator, instead of the current user's")
	flags.IntVar(&o.rsa, "rsa", 0, "make an RSA key of this many bits, 2048 to 8192, instead of an ECDSA P-256 key; not with -ksp")
	flags.BoolVar(&o.force, "force", false, "overwrite the files that -savecert and -savekey name")
	flags.Usage = func() {
		fmt.Fprint(stderr, certUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "ranz cert: unexpected arguments: %q\n", flags.Args())
		return 2
	}
	serial, err := o.check()
	if err != nil {
		fmt.Fprintln(stderr, "ranz cert:", err)
		return 2
	}
	if err := makeCert(o, serial, stdout); err != nil {
		fmt.Fprintln(stderr, "ranz cert:", err)
		return 1
	}
	return 0
}

// check refuses flags that cannot go together, and returns the serial number that -serial gives,
// nil when it gives none.
func (o certOptions) check() (*big.Int, error) {
	switch {
	case o.name.CommonName == "":
		return nil, errors.New("-cn names no certificate: give its name")
	case o.days < 0 || o.days > certgen.MaxDays:
		return nil, fmt.Errorf("-expires %d is not between 0 and %d days", o.days, certgen.MaxDays)
	case o.saveCert == "" && o.ksp == "":
		return nil, errors.New("nothing is written: give -savecert and -savekey, or -ksp")
	case o.ksp == "" && o.saveKey == "":
		return nil, errors.New("-savekey names no file for the private key: give one, or keep the key with -ksp")
	case o.ksp != "" && o.saveKey != "":
		return nil, errors.New("a key of the provider cannot be written to a file: leave out -savekey")
	case o.ksp != "" && o.rsa != 0:
		return nil, errors.New("-rsa makes a key in a file: the key of the provider is ECDSA P-256")
	case o.signCert == "" && (o.signKey != "" || o.signKSP != ""):
		return nil, errors.New("-signkey and -signksp need -signcert, the certificate of the CA")
	case o.signCert != "" && o.signKey == "" && o.signKSP == "":
		return nil, errors.New("-signcert needs the key of the CA: -signkey FILE, or -signksp NAME")
	case o.signKey != "" && o.signKSP != "":
		return nil, errors.New("give the key of the CA with -signkey or with -signksp, not with both")
	case o.machine && o.ksp == "" && o.signKSP == "":
		return nil, errors.New("-machine goes with -ksp or -signksp")
	case o.ca && o.hosts != "":
		return nil, errors.New("a CA certificate has no host names: leave out -hosts")
	}
	if o.serial == "" {
		return nil, nil
	}
	n, ok := new(big.Int).SetString(strings.ReplaceAll(o.serial, ":", ""), 16)
	if !ok {
		return nil, fmt.Errorf("-serial %q is no hexadecimal number", o.serial)
	}
	return n, nil
}

// splitHosts returns the names of the comma-separated list s, trimmed, without the empty ones.
func splitHosts(s string) []string {
	var hosts []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// authority returns the CA that signs the certificate: the certificate of -signcert and the key of
// -signkey or -signksp. It returns nil when the certificate is self-signed.
func (o certOptions) authority() (*certgen.Authority, error) {
	if o.signCert == "" {
		return nil, nil
	}
	certPEM, err := os.ReadFile(o.signCert)
	if err != nil {
		return nil, fmt.Errorf("-signcert: %w", err)
	}
	if o.signKSP != "" {
		cert, err := certgen.LoadCertificate(certPEM)
		if err != nil {
			return nil, fmt.Errorf("-signcert: %w", err)
		}
		key, err := keys.LoadKSP(o.signKSP, o.machine)
		if err != nil {
			return nil, fmt.Errorf("-signksp: %w", err)
		}
		return certgen.NewAuthority(cert, key)
	}
	keyPEM, err := os.ReadFile(o.signKey)
	if err != nil {
		return nil, fmt.Errorf("-signkey: %w", err)
	}
	return certgen.LoadAuthority(certPEM, keyPEM)
}

// makeCert makes the certificate that the options describe, writes it where they say, and prints
// what it made to stdout. A failure leaves nothing behind that this call made: no file, no key in
// the provider, no certificate in the store.
func makeCert(o certOptions, serial *big.Int, stdout io.Writer) error {
	authority, err := o.authority()
	if err != nil {
		return err
	}
	var key crypto.Signer
	if o.ksp != "" {
		key, err = keys.CreateKSP(o.ksp, o.machine)
	} else {
		key, err = certgen.NewKey(o.rsa)
	}
	if err != nil {
		return err
	}

	// What a failure from here on undoes, last made first
	var undo []func()
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if o.ksp != "" {
		undo = append(undo, func() { keys.DeleteKSP(o.ksp, o.machine) })
	}
	der, err := certgen.Make(certgen.Request{Name: o.name, Serial: serial, Days: o.days, CA: o.ca, Hosts: splitHosts(o.hosts)}, key, authority)
	if err != nil {
		rollback()
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		rollback()
		return err
	}
	if o.saveKey != "" {
		keyPEM, err := certgen.EncodeKey(key)
		if err != nil {
			rollback()
			return err
		}
		if err := certgen.WriteFile(o.saveKey, keyPEM, true, o.force); err != nil {
			rollback()
			return fmt.Errorf("-savekey: %w", err)
		}
		undo = append(undo, func() { os.Remove(o.saveKey) })
	}
	if o.saveCert != "" {
		if err := certgen.WriteFile(o.saveCert, certgen.EncodeCertificate(der), false, o.force); err != nil {
			rollback()
			return fmt.Errorf("-savecert: %w", err)
		}
		undo = append(undo, func() { os.Remove(o.saveCert) })
	}
	if o.ksp != "" {
		thumbprint := certgen.Thumbprint(der)
		if err := certgen.InstallInStore(der, o.ksp, o.machine); err != nil {
			rollback()
			return fmt.Errorf("the certificate store: %w", err)
		}
		undo = append(undo, func() { certgen.RemoveFromStore(thumbprint, o.machine) })
		// The node finds the key of the certificate through the store, so the store must hold it
		if err := certgen.CheckStoredKey(thumbprint, o.machine); err != nil {
			rollback()
			return err
		}
	}
	printCert(stdout, o, der, cert, authority)
	return nil
}

// storeName returns the name of the store that -ksp puts the certificate into.
func storeName(machine bool) string {
	if machine {
		return `LocalMachine\My`
	}
	return `CurrentUser\My`
}

// describeKey returns what the certificate says of its key, and where the key is.
func describeKey(cert *x509.Certificate, o certOptions) string {
	var kind string
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		kind = "ECDSA " + pub.Curve.Params().Name
	case *rsa.PublicKey:
		kind = fmt.Sprintf("RSA %d", pub.N.BitLen())
	default:
		kind = fmt.Sprintf("%T", pub)
	}
	if o.ksp == "" {
		return kind
	}
	set := "the key set of the current user"
	if o.machine {
		set = "the machine key set"
	}
	return fmt.Sprintf("%s in the Microsoft Software Key Storage Provider as %q, in %s", kind, o.ksp, set)
}

// printCert prints the certificate that was made and where it went.
func printCert(w io.Writer, o certOptions, der []byte, cert *x509.Certificate, ca *certgen.Authority) {
	issuer := "itself (self-signed)"
	if ca != nil {
		issuer = cert.Issuer.String()
	}
	use := "a server and a client"
	if cert.IsCA {
		use = "a CA, which signs certificates"
	}
	var names []string
	for _, n := range cert.DNSNames {
		names = append(names, "DNS:"+n)
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, "IP:"+ip.String())
	}
	fmt.Fprintf(w, "Subject      %s\n", cert.Subject)
	fmt.Fprintf(w, "Issuer       %s\n", issuer)
	fmt.Fprintf(w, "Serial       %X\n", cert.SerialNumber)
	fmt.Fprintf(w, "Valid        %s to %s\n", cert.NotBefore.UTC().Format(time.DateOnly), cert.NotAfter.UTC().Format(time.DateOnly))
	if len(names) > 0 {
		fmt.Fprintf(w, "Names        %s\n", strings.Join(names, " "))
	}
	fmt.Fprintf(w, "Use          %s\n", use)
	fmt.Fprintf(w, "Key          %s\n", describeKey(cert, o))
	fmt.Fprintf(w, "Thumbprint   %s\n", certgen.Thumbprint(der))
	fmt.Fprintf(w, "SHA-256      %s\n", certgen.Digest(der))
	if o.saveCert != "" {
		fmt.Fprintf(w, "Certificate  %s\n", o.saveCert)
	}
	if o.saveKey != "" {
		fmt.Fprintf(w, "Private key  %s (PKCS #8, not encrypted)\n", o.saveKey)
	}
	if o.ksp != "" {
		fmt.Fprintf(w, "Store        %s, linked to its key\n", storeName(o.machine))
	}
	if ca != nil && cert.NotAfter.After(ca.Cert.NotAfter) {
		fmt.Fprintf(w, "Note         the certificate is valid beyond the expiry of its CA, %s\n", ca.Cert.NotAfter.UTC().Format(time.DateOnly))
	}
}
