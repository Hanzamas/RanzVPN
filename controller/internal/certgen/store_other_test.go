//go:build !windows

package certgen

import (
	"errors"
	"testing"
)

// Off Windows the certificate store has no functions, and each says so.
func TestNoStore(t *testing.T) {
	if err := InstallInStore([]byte{1}, "key", false); !errors.Is(err, ErrNoStore) {
		t.Errorf("InstallInStore: %v, want ErrNoStore", err)
	}
	if err := RemoveFromStore("00", true); !errors.Is(err, ErrNoStore) {
		t.Errorf("RemoveFromStore: %v, want ErrNoStore", err)
	}
	if err := CheckStoredKey("00", false); !errors.Is(err, ErrNoStore) {
		t.Errorf("CheckStoredKey: %v, want ErrNoStore", err)
	}
}
