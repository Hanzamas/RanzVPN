//go:build windows

package certgen

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// encoding is the encoding of every certificate that the functions here pass to CryptoAPI.
const encoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

// certKeyProvInfoPropID is CERT_KEY_PROV_INFO_PROP_ID, the property that links a certificate to
// its key.
const certKeyProvInfoPropID = 2

// machineKeyFlag is NCRYPT_MACHINE_KEY_FLAG: the key is in the machine key set.
const machineKeyFlag = 0x20

// keyProvider is the name of the provider that holds the keys of the certificates: the software
// KSP, as src/Core/CryptoCert.c names it.
const keyProvider = "Microsoft Software Key Storage Provider"

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertSetCertificateContextProperty = crypt32.NewProc("CertSetCertificateContextProperty")
	ncrypt                                = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptFreeObject                  = ncrypt.NewProc("NCryptFreeObject")
)

// cryptKeyProvInfo is CRYPT_KEY_PROV_INFO: the link of a certificate to its key.
type cryptKeyProvInfo struct {
	containerName  *uint16
	provName       *uint16
	provType       uint32
	flags          uint32
	provParamCount uint32
	provParam      uintptr
	keySpec        uint32
}

// openStore opens the My store of the current user, or of the local machine, which needs the
// rights of an administrator to change.
func openStore(machine bool) (windows.Handle, error) {
	flags := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if machine {
		flags = windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if err != nil {
		return 0, fmt.Errorf("certgen: opening the My certificate store: %w", err)
	}
	return store, nil
}

// InstallInStore puts the certificate der into the My store of the current user, or of the local
// machine, and links it to the key keyName of the Microsoft Software Key Storage Provider, in the
// key set of the same scope. The link is what lets Schannel find the key of the certificate when
// the node loads it by its thumbprint, as CryptoCertCreateSelfSigned arranges it for the node's own
// certificates. A certificate of the same thumbprint that the store holds is replaced.
func InstallInStore(der []byte, keyName string, machine bool) error {
	if len(der) == 0 {
		return errors.New("certgen: no certificate to install")
	}
	ctx, err := windows.CertCreateCertificateContext(encoding, &der[0], uint32(len(der)))
	if err != nil {
		return fmt.Errorf("certgen: the certificate does not load: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx)
	store, err := openStore(machine)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	var stored *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, &stored); err != nil {
		return fmt.Errorf("certgen: adding the certificate to the My store: %w", err)
	}
	defer windows.CertFreeCertificateContext(stored)
	return linkKey(stored, keyName, machine)
}

// linkKey sets the key property of the certificate cert, a context of a store, to the key keyName.
func linkKey(cert *windows.CertContext, keyName string, machine bool) error {
	container, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return fmt.Errorf("certgen: the name of the key: %w", err)
	}
	provider, err := windows.UTF16PtrFromString(keyProvider)
	if err != nil {
		return err
	}
	info := cryptKeyProvInfo{containerName: container, provName: provider}
	if machine {
		info.flags = machineKeyFlag
	}
	r, _, callErr := procCertSetCertificateContextProperty.Call(uintptr(unsafe.Pointer(cert)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(container)
	runtime.KeepAlive(provider)
	if r == 0 {
		return fmt.Errorf("certgen: linking the certificate to its key: %w", callErr)
	}
	return nil
}

// findByHash returns the certificate of the store that has the SHA-1 thumbprint hash. The caller
// frees it.
func findByHash(store windows.Handle, hash []byte) (*windows.CertContext, error) {
	blob := windows.CryptHashBlob{Size: uint32(len(hash)), Data: &hash[0]}
	ctx, err := windows.CertFindCertificateInStore(store, encoding, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
	if err != nil {
		return nil, fmt.Errorf("certgen: no certificate with the thumbprint %X in the My store: %w", hash, err)
	}
	return ctx, nil
}

// openByThumbprint opens the My store and finds the certificate with the thumbprint in it. The
// caller frees the certificate and then closes the store.
func openByThumbprint(thumbprint string, machine bool) (windows.Handle, *windows.CertContext, error) {
	hash, err := hex.DecodeString(thumbprint)
	if err != nil || len(hash) == 0 {
		return 0, nil, fmt.Errorf("certgen: %q is no thumbprint", thumbprint)
	}
	store, err := openStore(machine)
	if err != nil {
		return 0, nil, err
	}
	ctx, err := findByHash(store, hash)
	if err != nil {
		windows.CertCloseStore(store, 0)
		return 0, nil, err
	}
	return store, ctx, nil
}

// RemoveFromStore removes the certificate with the thumbprint from the My store of the current
// user, or of the local machine. It leaves the key of the certificate where it is.
func RemoveFromStore(thumbprint string, machine bool) error {
	store, ctx, err := openByThumbprint(thumbprint, machine)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	// CertDeleteCertificateFromStore frees the context it is given, whether it deletes or not
	if err := windows.CertDeleteCertificateFromStore(ctx); err != nil {
		return fmt.Errorf("certgen: removing the certificate from the My store: %w", err)
	}
	return nil
}

// CheckStoredKey checks that the certificate with the thumbprint, in the My store of the current
// user or of the local machine, finds its key in a key storage provider, as Schannel does when the
// node serves with the certificate.
func CheckStoredKey(thumbprint string, machine bool) error {
	store, ctx, err := openByThumbprint(thumbprint, machine)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(store, 0)
	defer windows.CertFreeCertificateContext(ctx)
	var (
		key      windows.Handle
		spec     uint32
		mustFree bool
	)
	flags := uint32(windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | windows.CRYPT_ACQUIRE_SILENT_FLAG)
	if err := windows.CryptAcquireCertificatePrivateKey(ctx, flags, nil, &key, &spec, &mustFree); err != nil {
		return fmt.Errorf("certgen: the certificate has no key in a key storage provider: %w", err)
	}
	if mustFree {
		procNCryptFreeObject.Call(uintptr(key))
	}
	if spec != windows.CERT_NCRYPT_KEY_SPEC {
		return fmt.Errorf("certgen: the key of the certificate is no key of a key storage provider (key spec %d)", spec)
	}
	return nil
}
