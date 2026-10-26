//go:build windows

package certgen

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")

// FindInStore returns the certificate with the SHA-1 thumbprint of the My store of the local machine,
// or, when that holds none, of the current user: its encoding, and where its key is. The Controller
// serves such a certificate with its key staying in the key storage provider (SDN-92, #397).
func FindInStore(thumbprint string) (StoredCertificate, error) {
	c, machineErr := findInStore(thumbprint, true)
	if machineErr == nil {
		return c, nil
	}
	c, userErr := findInStore(thumbprint, false)
	if userErr == nil {
		return c, nil
	}
	return StoredCertificate{}, fmt.Errorf("certgen: the certificate with the thumbprint %s is in neither store: LocalMachine\\My: %v; CurrentUser\\My: %v", thumbprint, machineErr, userErr)
}

// findInStore returns the certificate with the thumbprint of the My store of the local machine, or
// of the current user.
func findInStore(thumbprint string, machine bool) (StoredCertificate, error) {
	store, ctx, err := openByThumbprint(thumbprint, machine)
	if err != nil {
		return StoredCertificate{}, err
	}
	defer windows.CertCloseStore(store, 0)
	defer windows.CertFreeCertificateContext(ctx)
	der := bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length))
	key, keyMachine, err := keyOf(ctx)
	if err != nil {
		return StoredCertificate{}, err
	}
	return StoredCertificate{DER: der, Key: key, Machine: keyMachine}, nil
}

// keyOf returns the name of the key that the certificate ctx is linked to in the Microsoft Software
// Key Storage Provider, and whether the key is in the machine key set.
func keyOf(ctx *windows.CertContext) (string, bool, error) {
	var n uint32
	r, _, callErr := procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&n)))
	if r == 0 || n == 0 {
		return "", false, fmt.Errorf("certgen: the certificate is linked to no key: %w", callErr)
	}
	buf := make([]byte, n)
	r, _, callErr = procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", false, fmt.Errorf("certgen: the key of the certificate: %w", callErr)
	}
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	if provider := windows.UTF16PtrToString(info.provName); provider != keyProvider {
		return "", false, fmt.Errorf("certgen: the key of the certificate is in the provider %q, not in the %s", provider, keyProvider)
	}
	return windows.UTF16PtrToString(info.containerName), info.flags&machineKeyFlag != 0, nil
}
