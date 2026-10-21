//go:build windows

package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The CNG names and values (ncrypt.h, bcrypt.h) this file uses.
const (
	msKeyStorageProvider = "Microsoft Software Key Storage Provider" // MS_KEY_STORAGE_PROVIDER

	algECDH      = "ECDH"       // NCRYPT_ECDH_ALGORITHM
	algECDSAP256 = "ECDSA_P256" // NCRYPT_ECDSA_P256_ALGORITHM
	curve25519   = "curve25519" // BCRYPT_ECC_CURVE_25519

	propCurveName    = "ECCCurveName"  // NCRYPT_ECC_CURVE_NAME_PROPERTY
	propExportPolicy = "Export Policy" // NCRYPT_EXPORT_POLICY_PROPERTY

	blobECCPublic = "ECCPUBLICBLOB" // BCRYPT_ECCPUBLIC_BLOB
	kdfRawSecret  = "TRUNCATE"      // BCRYPT_KDF_RAW_SECRET

	machineKeyFlag = 0x20 // NCRYPT_MACHINE_KEY_FLAG
	silentFlag     = 0x40 // NCRYPT_SILENT_FLAG

	bufferECCCurveName = 60 // NCRYPTBUFFER_ECC_CURVE_NAME

	magicECDSAPublicP256   = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	magicECDHPublicGeneric = 0x504B4345 // BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
)

// errBadKeyset is NTE_BAD_KEYSET: the provider holds no key of that name.
var errBadKeyset = windows.Errno(0x80090016)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procImportKey           = ncrypt.NewProc("NCryptImportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procSecretAgreement     = ncrypt.NewProc("NCryptSecretAgreement")
	procDeriveKey           = ncrypt.NewProc("NCryptDeriveKey")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// ncryptBuffer and ncryptBufferDesc are NCryptBuffer and NCryptBufferDesc.
type ncryptBuffer struct {
	size uint32
	typ  uint32
	data unsafe.Pointer
}

type ncryptBufferDesc struct {
	version uint32
	count   uint32
	buffers *ncryptBuffer
}

// status turns the SECURITY_STATUS r that the CNG function fn returned into an error.
func status(fn string, r uintptr) error {
	if s := uint32(r); s != 0 {
		return fmt.Errorf("keys: %s: %w", fn, windows.Errno(s))
	}
	return nil
}

func utf16z(s string) *uint16 {
	// The names of this package hold no NUL, so the conversion cannot fail.
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// stringValue is s as a property value: UTF-16 with its terminating NUL.
func stringValue(s string) []byte {
	u, _ := windows.UTF16FromString(s)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
}

func openProvider() (uintptr, error) {
	var prov uintptr
	r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(utf16z(msKeyStorageProvider))), 0)
	return prov, status("NCryptOpenStorageProvider", r)
}

func freeObject(h uintptr) {
	procFreeObject.Call(h)
}

func setProperty(h uintptr, name string, value []byte) error {
	r, _, _ := procSetProperty.Call(h, uintptr(unsafe.Pointer(utf16z(name))), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), silentFlag)
	return status("NCryptSetProperty "+name, r)
}

// createKey creates a key of the algorithm alg in the provider prov: persisted under name, with
// machineKeyFlag in flags for the machine scope, or ephemeral when name is empty. curve names
// the curve of an ECDH key; exportPolicy is the export policy, 0 for a key that never leaves the
// provider.
func createKey(prov uintptr, name, alg, curve string, flags, exportPolicy uint32) (uintptr, error) {
	var namePtr *uint16
	if name != "" {
		namePtr = utf16z(name)
	}
	var h uintptr
	r, _, _ := procCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16z(alg))), uintptr(unsafe.Pointer(namePtr)), 0, uintptr(flags))
	if err := status("NCryptCreatePersistedKey", r); err != nil {
		return 0, err
	}
	if curve != "" {
		if err := setProperty(h, propCurveName, stringValue(curve)); err != nil {
			freeObject(h)
			return 0, err
		}
	}
	if err := setProperty(h, propExportPolicy, binary.LittleEndian.AppendUint32(nil, exportPolicy)); err != nil {
		freeObject(h)
		return 0, err
	}
	r, _, _ = procFinalizeKey.Call(h, silentFlag)
	if err := status("NCryptFinalizeKey", r); err != nil {
		freeObject(h)
		return 0, err
	}
	return h, nil
}

// openKey opens the persisted key name of prov; errors.Is(err, errBadKeyset) when there is none.
func openKey(prov uintptr, name string, flags uint32) (uintptr, error) {
	var h uintptr
	r, _, _ := procOpenKey.Call(prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16z(name))), 0, uintptr(flags|silentFlag))
	return h, status("NCryptOpenKey", r)
}

// openOrCreate opens the machine-scope key name of prov, or creates it, not exportable, the first
// time.
func openOrCreate(prov uintptr, name, alg, curve string) (uintptr, error) {
	h, err := openKey(prov, name, machineKeyFlag)
	if errors.Is(err, errBadKeyset) {
		return createKey(prov, name, alg, curve, machineKeyFlag, 0)
	}
	return h, err
}

// deleteKey deletes the persisted key h and frees its handle.
func deleteKey(h uintptr) error {
	r, _, _ := procDeleteKey.Call(h, silentFlag)
	return status("NCryptDeleteKey", r)
}

func exportBlob(h uintptr, blobType string) ([]byte, error) {
	t := utf16z(blobType)
	var n uint32
	r, _, _ := procExportKey.Call(h, 0, uintptr(unsafe.Pointer(t)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), silentFlag)
	if err := status("NCryptExportKey "+blobType, r); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, fmt.Errorf("keys: NCryptExportKey %s: an empty blob", blobType)
	}
	b := make([]byte, n)
	r, _, _ = procExportKey.Call(h, 0, uintptr(unsafe.Pointer(t)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), silentFlag)
	if err := status("NCryptExportKey "+blobType, r); err != nil {
		return nil, err
	}
	return b[:n], nil
}

// importKey imports an ephemeral key from blob, of the curve curve when it is not empty.
func importKey(prov uintptr, blobType string, blob []byte, curve string) (uintptr, error) {
	var params *ncryptBufferDesc
	if curve != "" {
		v := stringValue(curve)
		params = &ncryptBufferDesc{count: 1, buffers: &ncryptBuffer{size: uint32(len(v)), typ: bufferECCCurveName, data: unsafe.Pointer(&v[0])}}
	}
	var h uintptr
	r, _, _ := procImportKey.Call(prov, 0, uintptr(unsafe.Pointer(utf16z(blobType))), uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), silentFlag)
	return h, status("NCryptImportKey "+blobType, r)
}

// agree returns the secret agreement of the private key priv and the public key pub as
// NCryptDeriveKey returns it with BCRYPT_KDF_RAW_SECRET.
func agree(priv, pub uintptr) ([]byte, error) {
	var secret uintptr
	r, _, _ := procSecretAgreement.Call(priv, pub, uintptr(unsafe.Pointer(&secret)), 0)
	if err := status("NCryptSecretAgreement", r); err != nil {
		return nil, err
	}
	defer freeObject(secret)
	out := make([]byte, 128)
	var n uint32
	r, _, _ = procDeriveKey.Call(secret, uintptr(unsafe.Pointer(utf16z(kdfRawSecret))), 0, uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), 0)
	if err := status("NCryptDeriveKey", r); err != nil {
		return nil, err
	}
	return out[:n], nil
}

func signHash(h uintptr, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("keys: nothing to sign")
	}
	sig := make([]byte, 132)
	var n uint32
	r, _, _ := procSignHash.Call(h, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), silentFlag)
	if err := status("NCryptSignHash", r); err != nil {
		return nil, err
	}
	return sig[:n], nil
}

// eccBlob returns a BCRYPT_ECCKEY_BLOB: the magic, the size of one coordinate, then the parts
// (X and Y, and d in a private blob), each of that size.
func eccBlob(magic uint32, parts ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, magic)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(parts[0])))
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// parseECCBlob splits a BCRYPT_ECCKEY_BLOB into its magic and parts: X and Y, and d when the
// blob is a private one.
func parseECCBlob(b []byte) (magic uint32, parts [][]byte, err error) {
	if len(b) < 8 {
		return 0, nil, errors.New("keys: an ECC key blob shorter than its header")
	}
	magic = binary.LittleEndian.Uint32(b)
	size := int(binary.LittleEndian.Uint32(b[4:]))
	rest := b[8:]
	if size == 0 || len(rest)%size != 0 {
		return 0, nil, fmt.Errorf("keys: an ECC key blob of %d bytes after its header, for parts of %d", len(rest), size)
	}
	for len(rest) > 0 {
		parts = append(parts, rest[:size])
		rest = rest[size:]
	}
	return magic, parts, nil
}

// kspStatic is an X25519 key of the key storage provider, the Noise static key on Windows. Its
// Diffie-Hellman runs inside the provider. Its handles stay open for the life of the process.
type kspStatic struct {
	mu   sync.Mutex
	prov uintptr
	h    uintptr
	pub  []byte
}

func newKSPStatic(prov, h uintptr) (*kspStatic, error) {
	blob, err := exportBlob(h, blobECCPublic)
	if err != nil {
		return nil, err
	}
	magic, parts, err := parseECCBlob(blob)
	if err != nil {
		return nil, err
	}
	if magic != magicECDHPublicGeneric || len(parts) != 2 || len(parts[0]) != 32 {
		return nil, fmt.Errorf("keys: the Noise static key is not an X25519 key (blob magic %#x)", magic)
	}
	// X is the public key as RFC 7748 encodes it; Y is zero.
	return &kspStatic{prov: prov, h: h, pub: bytes.Clone(parts[0])}, nil
}

// Public returns the 32-byte public key.
func (k *kspStatic) Public() []byte {
	return k.pub
}

// DH returns the X25519 shared secret of the key and the public key peer. The provider takes
// the peer as an ECC public blob with the key as X and Y zero, imported with the curve name as a
// parameter, and returns the raw secret in the reverse byte order of RFC 7748; DH turns it
// back. TestKSPStatic checks the result against crypto/ecdh.
func (k *kspStatic) DH(peer []byte) ([]byte, error) {
	if len(peer) != 32 {
		return nil, fmt.Errorf("keys: a peer key of %d bytes, not 32", len(peer))
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	hp, err := importKey(k.prov, blobECCPublic, eccBlob(magicECDHPublicGeneric, peer, make([]byte, 32)), curve25519)
	if err != nil {
		return nil, err
	}
	defer freeObject(hp)
	secret, err := agree(k.h, hp)
	if err != nil {
		return nil, err
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("keys: a shared secret of %d bytes, not 32", len(secret))
	}
	slices.Reverse(secret)
	if bytes.Equal(secret, make([]byte, 32)) {
		return nil, errors.New("keys: the peer key is a low-order point")
	}
	return secret, nil
}

// kspSigner is an ECDSA P-256 key of the key storage provider, as the crypto.Signer that
// crypto/tls and crypto/x509 sign with. Its handle stays open for the life of the process.
type kspSigner struct {
	mu  sync.Mutex
	h   uintptr
	pub *ecdsa.PublicKey
}

func newKSPSigner(h uintptr) (*kspSigner, error) {
	blob, err := exportBlob(h, blobECCPublic)
	if err != nil {
		return nil, err
	}
	magic, parts, err := parseECCBlob(blob)
	if err != nil {
		return nil, err
	}
	if magic != magicECDSAPublicP256 || len(parts) != 2 || len(parts[0]) != 32 {
		return nil, fmt.Errorf("keys: the TLS key is not an ECDSA P-256 key (blob magic %#x)", magic)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(parts[0]), Y: new(big.Int).SetBytes(parts[1])}
	return &kspSigner{h: h, pub: pub}, nil
}

// Public returns the public key.
func (s *kspSigner) Public() crypto.PublicKey {
	return s.pub
}

// Sign signs digest inside the provider. NCryptSignHash returns r and s, big-endian, one after
// the other; crypto/tls and crypto/x509 take the ASN.1 form.
func (s *kspSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	sig, err := signHash(s.h, digest)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	half := len(sig) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:])})
}
