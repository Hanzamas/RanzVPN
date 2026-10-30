package store

import (
	"bytes"
	"testing"
)

// FuzzDecodeCopy feeds decodeCopy the text of a copy of the Cluster key in a row of cluster_key_copies,
// which anyone who can write to the store can choose. It must not panic; a text that is not empty is a
// copy that is there, whether it opens or not; and the copy that encodeCopy makes of what decodeCopy gave
// comes back as it was.
func FuzzDecodeCopy(f *testing.F) {
	f.Add(encodeCopy([]byte("the sealed bytes of a copy")))
	f.Add("")
	f.Add(sealedPrefix)
	f.Add(sealedPrefix + "!!")
	f.Add(sealedPrefix + "AAAA=")
	f.Add("not a copy")
	f.Fuzz(func(t *testing.T, text string) {
		b := decodeCopy(text)
		if text == "" {
			if b != nil {
				t.Fatalf("no text gave the copy %x", b)
			}
			return
		}
		if len(b) == 0 {
			t.Fatalf("the text %q gave no copy", text)
		}
		if again := decodeCopy(encodeCopy(b)); !bytes.Equal(again, b) {
			t.Fatalf("the copy %x came back as %x", b, again)
		}
	})
}
