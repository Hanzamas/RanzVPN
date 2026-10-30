package controllercmd

import (
	"errors"
	"fmt"
	"testing"
)

// The refusal of a fingerprint file that another account may have written (AUD1-DT-14, #496) names the file or the
// folder and says why, in one line, and is found in what wraps it, which is how ranz tells it from a file that cannot
// be read.
func TestUntrustedErrorNamesWhatItRefusesAndWhy(t *testing.T) {
	err := error(&UntrustedError{Path: `C:\ProgramData\Ranz\controller`, Why: `may be written by BUILTIN\Users`})
	if got, want := err.Error(), `C:\ProgramData\Ranz\controller may be written by BUILTIN\Users`; got != want {
		t.Errorf("the refusal reads %q, want %q", got, want)
	}
	var untrusted *UntrustedError
	if !errors.As(fmt.Errorf("Get https://127.0.0.1: %w", err), &untrusted) || untrusted.Path != `C:\ProgramData\Ranz\controller` {
		t.Errorf("the refusal is not found in what wraps it: %v", untrusted)
	}
	if errors.As(errors.New("open: access denied"), &untrusted) {
		t.Error("an error that is no refusal of trust is found as one")
	}
}
