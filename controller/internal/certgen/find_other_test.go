//go:build !windows

package certgen

import (
	"errors"
	"testing"
)

// Off Windows no certificate is found in a store, and FindInStore says so.
func TestFindInStoreOffWindows(t *testing.T) {
	if c, err := FindInStore("00"); !errors.Is(err, ErrNoStore) || c.DER != nil || c.Key != "" {
		t.Errorf("FindInStore: %+v, %v, want ErrNoStore", c, err)
	}
}
