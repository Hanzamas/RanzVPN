package sidecar

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// The credential of the store (AUD1-DT-8, ADR-0026 amendment of 2026-10-27): rqlited runs with
// -auth, so every request of its HTTP API needs a user and a password. The file is the one that
// rqlited reads (https://rqlite.io/docs/guides/security/): a JSON list of users with their
// permissions. The controller keeps one user, CredentialUser, with every permission, and a random
// password that its first start makes. The file lives in the data directory, whose access list
// the controller protects, so a local process that cannot read the data directory cannot read the
// store.

// CredentialUser is the user of the credential file, the one that the store client, reset-admin,
// backup and restore send, and that a member of a cluster joins with (-join-as).
const CredentialUser = "controller"

// credentialBytes is the size of the random password, 256 bits.
const credentialBytes = 32

// ErrCredentialExists marks a credential file that is there already: WriteCredential never
// replaces one.
var ErrCredentialExists = errors.New("the credential file exists already")

type credentialEntry struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Perms    []string `json:"perms"`
}

// WriteCredential writes a new credential file at path, readable by its owner only, with a random
// password, and returns the user and the password. It refuses a file that exists
// (ErrCredentialExists): replacing the credential of a store that runs would lock the members out.
func WriteCredential(path string) (user, password string, err error) {
	b := make([]byte, credentialBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("sidecar: the credential: %w", err)
	}
	password = hex.EncodeToString(b)
	file, err := json.MarshalIndent([]credentialEntry{{Username: CredentialUser, Password: password, Perms: []string{"all"}}}, "", "  ")
	if err != nil {
		return "", "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return "", "", fmt.Errorf("sidecar: %s: %w", path, ErrCredentialExists)
	}
	if err != nil {
		return "", "", fmt.Errorf("sidecar: %w", err)
	}
	_, err = f.Write(append(file, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", "", fmt.Errorf("sidecar: %s: %w", path, err)
	}
	return CredentialUser, password, nil
}

// ReadCredential reads the credential file at path and returns its user and password. A missing
// file is an error that wraps os.ErrNotExist.
func ReadCredential(path string) (user, password string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("sidecar: %w", err)
	}
	if user, password, err = parseCredential(b); err != nil {
		return "", "", fmt.Errorf("sidecar: %s: %w", path, err)
	}
	return user, password, nil
}

// parseCredential returns the user and the password of the entry for CredentialUser in file.
func parseCredential(file []byte) (user, password string, err error) {
	var entries []credentialEntry
	if err := json.Unmarshal(file, &entries); err != nil {
		return "", "", fmt.Errorf("not a list of users: %w", err)
	}
	for _, e := range entries {
		if e.Username == CredentialUser && e.Password != "" {
			return e.Username, e.Password, nil
		}
	}
	return "", "", fmt.Errorf("it holds no user %q with a password", CredentialUser)
}
