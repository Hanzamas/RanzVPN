package servercert

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FingerprintFile is the file in the data directory of the Controller that holds the TLS fingerprint of
// the certificate that its TLS port serves (AUD1-DT-13, #461): the 64 hex digits and a line end. The ranz
// of the same host reads it, and checks the certificate of a Controller on a loopback address against it,
// so that a program of the host that listens on the port in the Controller's place gets no token. Only the
// owner of the data directory and the administrators write there, which is why the file can be trusted;
// what it holds is no secret, since every client of the port sees it.
const FingerprintFile = "tls.fingerprint"

const (
	// maxFingerprintFile bounds what ReadFingerprint reads: a fingerprint, a line end and a little more.
	maxFingerprintFile = 256
	// renewTries and renewWait are how often, and how long apart, WriteFingerprint tries to put the new
	// file in place of the old one: Windows refuses that while a reader has the old one open.
	renewTries = 5
	renewWait  = 20 * time.Millisecond
)

// errNotFingerprint is what parseFingerprint says of a text that holds no fingerprint.
var errNotFingerprint = errors.New("it holds no TLS fingerprint, which is the 64 hex digits of a SHA-256")

// parseFingerprint returns the fingerprint that text holds, in lower case: the 64 hex digits of a SHA-256
// with white space around them, and nothing else.
func parseFingerprint(text string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(text))
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", errNotFingerprint
	}
	return s, nil
}

// WriteFingerprint writes the TLS fingerprint fp to FingerprintFile in dir. It writes the whole file and
// puts it in place of the old one in one step, so that a reader sees the old fingerprint or the new one
// and never a part of one.
func WriteFingerprint(dir, fp string) error {
	clean, err := parseFingerprint(fp)
	if err != nil {
		return fmt.Errorf("the TLS fingerprint %q: %w", fp, err)
	}
	file := filepath.Join(dir, FingerprintFile)
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(clean+"\n"), 0o644); err != nil {
		return err
	}
	for range renewTries {
		if err = os.Rename(tmp, file); err == nil {
			return nil
		}
		time.Sleep(renewWait)
	}
	_ = os.Remove(tmp)
	return err
}

// ReadFingerprint returns the TLS fingerprint that FingerprintFile in dir holds, in lower case, for a
// program on the host of the Controller. The error says why there is none: the file is not there or cannot
// be read, or it holds no fingerprint.
func ReadFingerprint(dir string) (string, error) {
	file := filepath.Join(dir, FingerprintFile)
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFingerprintFile))
	if err != nil {
		return "", err
	}
	fp, err := parseFingerprint(string(b))
	if err != nil {
		return "", fmt.Errorf("%s: %w", file, err)
	}
	return fp, nil
}

// PublishFingerprint makes the Manager keep FingerprintFile in dir at the TLS fingerprint of the certificate
// that it serves: it writes the file now, and again each time the Manager serves another certificate,
// whether an operator set it (Adopt), another member did (a look at the store) or ACME renewed it. The
// file is right again when the call that changed the certificate ends. A file that cannot be written is
// logged, and tried again at the next change; ranz on this host then needs -tls-fingerprint. It must be
// called before Start, and does nothing for a Manager with no data directory.
func (m *Manager) PublishFingerprint(dir string) {
	if dir == "" {
		return
	}
	var mu sync.Mutex
	var written string
	publish := func() {
		mu.Lock()
		defer mu.Unlock()
		// What is served now, not what the change that called says: of two changes in a row the last one wins
		fp := m.Fingerprint()
		if fp == written {
			return
		}
		if err := WriteFingerprint(dir, fp); err != nil {
			m.log.Warn("the TLS fingerprint cannot be written to the data directory, so ranz on this host needs -tls-fingerprint",
				"file", filepath.Join(dir, FingerprintFile), "err", err)
			return
		}
		written = fp
	}
	m.served = func(Info) { publish() }
	publish()
}
