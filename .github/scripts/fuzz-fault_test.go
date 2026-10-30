// fuzz-fault_test.go
// The planted fault of the fuzz campaign (AUD-3, #363; .github/workflows/fuzz.yml, .github/scripts/fuzz-campaign.py): a
// Go fuzz test that panics on the input "FUZZ". The campaign runs it as it runs a fuzz test of the registry, from a seed
// that is one byte away from the input ("FUZY"), and the leg must end in a finding with the failing input that go test
// saved under testdata/fuzz. A campaign that reported nothing could not be told from one that found nothing, so a leg
// that does not report this fault fails.
//
// It is no part of the module of ranz: the campaign copies it as fault_test.go into a module of its own, which it makes in
// a temporary directory, so no go.mod of the tree names it and go vet, staticcheck and the registry never see it.

package fuzzfault

import "testing"

func FuzzFault(f *testing.F) {
	f.Add([]byte("FUZY"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) >= 4 && b[0] == 'F' && b[1] == 'U' && b[2] == 'Z' && b[3] == 'Z' {
			panic("planted fault: the input starts with FUZZ")
		}
	})
}
