//go:build !windows

package keys

import (
	"crypto"
	"errors"
)

// ErrNoKSP is what the functions for the Microsoft Software Key Storage Provider return where
// there is none: off Windows.
var ErrNoKSP = errors.New("keys: the Microsoft Software Key Storage Provider exists on Windows only")

// CreateKSP returns ErrNoKSP.
func CreateKSP(name string, machine bool) (crypto.Signer, error) {
	return nil, ErrNoKSP
}

// LoadKSP returns ErrNoKSP.
func LoadKSP(name string, machine bool) (crypto.Signer, error) {
	return nil, ErrNoKSP
}

// DeleteKSP returns ErrNoKSP.
func DeleteKSP(name string, machine bool) error {
	return ErrNoKSP
}
