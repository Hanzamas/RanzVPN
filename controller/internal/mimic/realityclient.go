package mimic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// The client side of REALITY. The library of REALITY (github.com/xtls/reality) is the server side
// only and leaves the client to the program that embeds uTLS, so this is the client of the
// protocol, which the server library defines (its Server function, tls.go):
//
//   - The client sends an ordinary browser ClientHello (uTLS) whose session id is the proof: 32
//     bytes that AES-256-GCM seals from 16 plain bytes (the version of the client, a reserved byte,
//     the time and the short id), under the key HKDF-SHA256 makes from the X25519 shared secret of
//     the ephemeral key share of the ClientHello and the public key of the server, with the first 20
//     bytes of the random of the ClientHello as the salt and "REALITY" as the info. The last 12
//     bytes of the random are the nonce, and the ClientHello itself, with the session id zeroed, is
//     the associated data.
//   - A server that opens the proof answers as the TLS 1.3 server of the site it borrows, with a
//     temporary certificate: an Ed25519 certificate whose signature is the HMAC-SHA512 of its public
//     key under the same auth key. The client checks that and nothing else: no chain leads to it.
//   - A server that does not open the proof splices the connection to the real site, whose
//     certificate is what the client then sees, and the client sends an alert and gives up.

// clientVersion is the version that the proof carries. A server accepts the versions between
// minClientVersion and maxClientVersion, so that a client of REALITY that is no Ranz client (Xray,
// with its own version numbers) is spliced to the site even when it holds the key.
var (
	clientVersion    = [3]byte{1, 0, 0}
	minClientVersion = []byte{1, 0, 0}
	maxClientVersion = []byte{1, 255, 255}
)

// sessionIDOffset is where the session id starts in a ClientHello message: the header of 4 bytes,
// the version of 2 and the random of 32, and the length byte of the id.
const sessionIDOffset = 4 + 2 + 32 + 1

// errNotAuthenticated is what the check of the certificate of the server gives when it is not the
// temporary certificate of REALITY.
var errNotAuthenticated = errors.New("the server did not prove its key: it presented a certificate of its own, so the public key, the short id or the clock of the link is wrong, or something redirected the connection to the real site")

// authenticate puts the proof of the link into hello, the ClientHello that uTLS built, and returns the
// auth key that the certificate of the server is checked against. keys are the private key shares
// that uTLS made for hello, and now is the time that the proof carries.
func authenticate(hello *utls.PubClientHelloMsg, keys *utls.KeySharePrivateKeys, l *linkConfig, now time.Time) ([]byte, error) {
	if keys == nil || len(hello.Random) != 32 || len(hello.Raw) < sessionIDOffset+32 {
		return nil, errors.New("the ClientHello of this fingerprint has no room for the proof")
	}
	// The key share of the proof is the X25519 key of the ClientHello: the plain share, or the
	// X25519 half of the hybrid one when the ClientHello has no plain share.
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("the ClientHello of this fingerprint has no X25519 key share: REALITY cannot take its proof")
	}
	shared, err := ecdhe.ECDH(l.publicKey)
	if err != nil {
		return nil, fmt.Errorf("key agreement with the key of the server: %w", err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// The associated data is the ClientHello with a session id of zeros
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
	copy(hello.SessionId[0:3], clientVersion[:])
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(now.Unix()))
	copy(hello.SessionId[8:], l.shortID[:])
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
	return authKey, nil
}

// temporaryCertificate reports whether der is the temporary certificate of the server that opened
// the proof made under authKey: an Ed25519 certificate whose signature is the HMAC-SHA512 of its
// public key under authKey.
func temporaryCertificate(der, authKey []byte) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	return hmac.Equal(mac.Sum(nil), cert.Signature)
}

// realityHandshake runs the TLS handshake of the link over raw, a TCP connection to the server: the
// ClientHello of the fingerprint with the proof of the link in it, and the check of the certificate
// that answers. It fails when the server did not prove its key; raw is the caller's then.
func realityHandshake(ctx context.Context, raw net.Conn, l *linkConfig) (*utls.UConn, error) {
	var authKey []byte
	verified := false
	cfg := &utls.Config{
		ServerName: l.serverName,
		// No chain leads to the temporary certificate: it is checked by the key of the server, below
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || !temporaryCertificate(rawCerts[0], authKey) {
				return errNotAuthenticated
			}
			verified = true
			return nil
		},
		// No session to resume: a resumption would skip the certificate, and so the check of the key
		SessionTicketsDisabled: true,
		// One write is one TLS record, so that the sizes of the frames are the sizes on the wire
		DynamicRecordSizingDisabled: true,
	}

	uc, err := l.fp.newUConn(raw, cfg)
	if err != nil {
		return nil, fmt.Errorf("the %s ClientHello: %w", l.fp.name, err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("the %s ClientHello: %w", l.fp.name, err)
	}
	if authKey, err = authenticate(uc.HandshakeState.Hello, uc.HandshakeState.State13.KeyShareKeys, l, time.Now()); err != nil {
		return nil, err
	}
	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified {
		return nil, errNotAuthenticated
	}
	return uc, nil
}

// exporter is the channel binding of a TLS session: the connection state of uTLS and of REALITY both
// give it.
type exporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// bindingText is the channel binding of the TLS session that state describes, as the text of the
// first line of a stream: 64 hex digits, or "-" when the session gives none.
func bindingText(state exporter) string {
	b, err := state.ExportKeyingMaterial(BindingLabel, nil, BindingSize)
	if err != nil || len(b) != BindingSize {
		return "-"
	}
	return hex.EncodeToString(b)
}
