package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

// plantedToken is a token of the API, which every rule of Redact finds by its form.
const plantedToken = "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23"

// FuzzRedact is ADR-0040 item 1 for the text of a log that Redact reads: whatever the bytes around
// it, Redact does not panic, changes nothing it did not count, leaves no private key block and no
// token of the API of a form it knows.
func FuzzRedact(f *testing.F) {
	for _, seed := range []string{
		"level=ERROR msg=\"login failed\" user=alice password=hunter2-correct-horse\n",
		"Authorization: Bearer Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA\n",
		"first start: token=" + plantedToken + " file=admin.token\n",
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
		"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIplantedeckeybodyplantedeckeybody1234\n",
		"rqlite url=http://rqlite:s3cretUrlPassw0rd@127.0.0.1:4001/ ready",
		"ranz.exe controller -token Sup3rS3cretFlagValue -listen :443",
		"passwordHash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo",
		"",
	} {
		f.Add(seed, "")
		f.Add("", seed)
	}
	f.Fuzz(func(t *testing.T, prefix, suffix string) {
		text := prefix + suffix
		out, n := Redact(text)
		if n < 0 || (n == 0 && out != text) {
			t.Fatalf("Redact(%q) = %q, %d: text changed that was not counted", text, out, n)
		}
		if strings.Contains(text, "-----BEGIN PRIVATE KEY-----") && strings.Contains(out, "-----BEGIN PRIVATE KEY-----") {
			t.Fatalf("Redact(%q) = %q: the private key is still there", text, out)
		}
		planted, _ := Redact(prefix + plantedToken + suffix)
		if strings.Contains(planted, plantedToken) {
			t.Fatalf("Redact(%q) = %q: the token of the API is still there", prefix+plantedToken+suffix, planted)
		}
	})
}

// FuzzRedactJSON is ADR-0040 item 1 for the JSON documents of a bundle that RedactJSON decodes: a
// document that it takes comes out as JSON again, and one that it refuses is an error, not a panic.
func FuzzRedactJSON(f *testing.F) {
	for _, seed := range []string{
		`{"users": [{"name": "alice", "passwordHash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"}], "count": 3}`,
		`{"token": {"id": 7, "value": "` + plantedToken + `"}, "psk": 12345678, "empty": "", "off": false}`,
		`[1, 2.5, "three", null, true, {"a": [[]]}]`,
		`"a string"`,
		`12345678901234567890123456789`,
		`{"a": 1} {"b": 2}`,
		`{"a": 1`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, n, err := RedactJSON(data)
		if err != nil {
			return
		}
		if n < 0 || !json.Valid(out) {
			t.Fatalf("RedactJSON(%q) = %q, %d: not a JSON document", data, out, n)
		}
	})
}
