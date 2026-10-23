//go:build !windows

package keys

import (
	"errors"
	"testing"
)

// Off Windows there is no key storage provider, and each function for it says so.
func TestNoKSP(t *testing.T) {
	if _, err := CreateKSP("ranz-test", false); !errors.Is(err, ErrNoKSP) {
		t.Errorf("CreateKSP: %v, want ErrNoKSP", err)
	}
	if _, err := LoadKSP("ranz-test", true); !errors.Is(err, ErrNoKSP) {
		t.Errorf("LoadKSP: %v, want ErrNoKSP", err)
	}
	if err := DeleteKSP("ranz-test", false); !errors.Is(err, ErrNoKSP) {
		t.Errorf("DeleteKSP: %v, want ErrNoKSP", err)
	}
}
