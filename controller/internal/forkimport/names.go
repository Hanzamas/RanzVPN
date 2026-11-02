package forkimport

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// nameLimit is the most characters of the name of a resource: a name is a DNS label (intent.Apply).
const nameLimit = 63

// slug writes the name raw of a Virtual Hub, a user or a group of the fork as the name of a resource: its letters in
// lower case and its digits, and a hyphen for each run of other characters, with none at either end. A name that has
// no letter or digit is fallback, and a name that is longer than nameLimit is cut short, each followed by a hyphen and
// the first 8 hex digits of the SHA-256 of raw, so that two such names differ.
func slug(raw, fallback string) string {
	var b []byte
	dash := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			if dash && len(b) > 0 {
				b = append(b, '-')
			}
			dash = false
			b = append(b, c)
		} else {
			dash = true
		}
	}
	name := string(b)
	if name == "" {
		return fallback + "-" + shortHash(raw)
	}
	if len(name) > nameLimit {
		keep := nameLimit - 9
		return strings.TrimRight(name[:keep], "-") + "-" + shortHash(raw)
	}
	return name
}

// shortHash returns the first 8 hex digits of the SHA-256 of raw.
func shortHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:4])
}

// namer gives out the names of the resources of an import, each name once for its kind: the name that is asked for,
// and when another resource of the kind has it, the name with -2, -3 and so on after it.
type namer struct {
	used map[string]map[string]bool
	next map[string]int
}

func newNamer() *namer {
	return &namer{used: map[string]map[string]bool{}, next: map[string]int{}}
}

// take returns a name of the kind kind that nobody has, for base.
func (n *namer) take(kind, base string) string {
	used := n.used[kind]
	if used == nil {
		used = map[string]bool{}
		n.used[kind] = used
	}
	name := base
	key := kind + "/" + base
	for i := max(n.next[key], 2); used[name]; i++ {
		suffix := "-" + strconv.Itoa(i)
		stem := base
		if len(stem)+len(suffix) > nameLimit {
			stem = strings.TrimRight(stem[:nameLimit-len(suffix)], "-")
		}
		name = stem + suffix
		n.next[key] = i + 1
	}
	used[name] = true
	return name
}
