package bundle

import (
	"encoding/json"
	"strings"
	"testing"
)

// Each secret has the name that is written before it, or a form of its own, and Redact replaces
// it, whatever surrounds it; what is no secret stays as it was written.
func TestRedactReplacesWhatIsSecret(t *testing.T) {
	for _, c := range []struct {
		name   string
		in     string
		secret string
		keep   string
	}{
		{"a password", `level=ERROR msg="login failed" user=alice password=hunter2-correct-horse`, "hunter2-correct-horse", "user=alice"},
		{"a quoted password", `msg="x" password="two words here" rest`, "two words here", "rest"},
		{"a token of the API", `first start: token=ranz_ABCDEFGHIJKLMNOPQRSTUVWX23 file=admin.token`, "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23", "file=admin.token"},
		{"a token of the API without a name", `the secret was ranz_ABCDEFGHIJKLMNOPQRSTUVWX23 and then`, "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23", "and then"},
		{"a bearer token", `Authorization: Bearer Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA done`, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA", "done"},
		{"a bearer token without a header", `sent Bearer Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA to it`, "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA", "to it"},
		{"basic credentials", `Authorization: Basic dXNlcjpwbGFudGVkcGFzc3dvcmQ=`, "dXNlcjpwbGFudGVkcGFzc3dvcmQ=", "Authorization"},
		{"a password hash", `user created passwordHash=$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo ok`, "c2FsdHNhbHRzYWx0", "ok"},
		{"a password hash without a name", `stored $2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456 for`, "abcdefghijklmnopqrstuu", "for"},
		{"a derived key", `hash pbkdf2-sha256$600000$c2FsdA$ZGVyaXZlZGtleWRlcml2ZWRrZXk end`, "ZGVyaXZlZGtleWRlcml2ZWRrZXk", "end"},
		{"a private key in PEM", "before\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA\nplantedkeybodyplantedkeybody==\n-----END PRIVATE KEY-----\nafter\n", "plantedkeybody", "before"},
		{"a private key of RSA in PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAplantedrsakeybody1234567890\n-----END RSA PRIVATE KEY-----", "plantedrsakeybody", ""},
		{"a private key whose end is cut", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIplantedeckeybodyplantedeckeybody1234\nMoreBase64LinesMoreBase64LinesMoreBase64Lines\nINFO next line", "plantedeckeybody", "INFO next line"},
		{"a private key in JSON text", `{"key": "-----BEGIN PRIVATE KEY-----\nMIIEvQplantedjsonkeybody\n-----END PRIVATE KEY-----\n"}`, "plantedjsonkeybody", ""},
		{"a web token", `jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwbGFudGVkIn0.c2lnbmF0dXJlcGxhbnRlZA fin`, "eyJzdWIiOiJwbGFudGVkIn0", "fin"},
		{"a licence key", `licence key/eyJ0aWVyIjoiYnVzaW5lc3MiLCJub2RlcyI6NTB9.c2lnbmF0dXJlcGxhbnRlZGxpY2VuY2U ok`, "eyJ0aWVyIjoiYnVzaW5lc3Mi", "ok"},
		{"a password in a URL", `rqlite url=http://rqlite:s3cretUrlPassw0rd@127.0.0.1:4001/ ready`, "s3cretUrlPassw0rd", "127.0.0.1:4001"},
		{"a token of a code host", `pushed with ghp_0123456789abcdefghijABCDEFGHIJ0123 today`, "ghp_0123456789abcdefghijABCDEFGHIJ0123", "today"},
		{"a name in JSON text", `{"event": "x", "apiKey": "Sup3rS3cretApiKeyValue", "ok": true}`, "Sup3rS3cretApiKeyValue", `"ok": true`},
		{"a name with a colon", `client_secret: Sup3rS3cretClientValue next`, "Sup3rS3cretClientValue", "next"},
		{"a flag with a space", `ranz.exe controller -token Sup3rS3cretFlagValue -listen :443`, "Sup3rS3cretFlagValue", "-listen :443"},
		{"a flag with an equal sign", `ranz.exe --password=Sup3rS3cretFlagValue2 -listen :443`, "Sup3rS3cretFlagValue2", "-listen :443"},
		{"a signature header", `X-Ranz-Signature: sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`, "0123456789abcdef0123456789abcdef", "X-Ranz-Signature"},
		{"a cookie", `Cookie: session=Sup3rS3cretSessionValue`, "Sup3rS3cretSessionValue", "Cookie"},
	} {
		out, n := Redact(c.in)
		if strings.Contains(out, c.secret) {
			t.Errorf("%s: the secret %q is still in\n%s", c.name, c.secret, out)
		}
		if n == 0 || !strings.Contains(out, Replacement) {
			t.Errorf("%s: %d secrets replaced in\n%s", c.name, n, out)
		}
		if c.keep != "" && !strings.Contains(out, c.keep) {
			t.Errorf("%s: %q is gone from\n%s", c.name, c.keep, out)
		}
	}
}

// What is not a secret is left as it is, and nothing is counted: the public key of a node, a
// fingerprint, a file named by a flag, and the words of a line.
func TestRedactLeavesPlainTextAlone(t *testing.T) {
	for _, in := range []string{
		"2026-10-23T10:00:00.000Z INFO controller keys publicKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MDEyMzQ1Njc4OTA= tlsFingerprint=0123456789abcdef\n",
		"node refused: unknown static key remote=127.0.0.1:50000\n",
		"ranz.exe controller -token-file C:\\ProgramData\\Ranz\\controller\\admin.token -listen :443\n",
		"listening on :443, protocols ranz-control/1, h2, http/1.1\r\n",
		"key/value pairs are written as name=value\n",
		"",
	} {
		if out, n := Redact(in); out != in || n != 0 {
			t.Errorf("Redact(%q) = %q, %d: nothing in it is a secret", in, out, n)
		}
	}
}

// A name in a JSON document that holds a secret loses its value whatever the value is, and the
// strings elsewhere go through the rules of text; the rest of the document stays.
func TestRedactJSON(t *testing.T) {
	in := `{
	  "users": [{"name": "alice", "passwordHash": "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", "mfa": {"totpSecret": "JBSWY3DPEHPK3PXP"}}],
	  "nodes": [{"name": "branch-1", "publicKey": "cHVibGljS2V5", "privateKey": "cHJpdmF0ZUtleQ==", "psk": 12345678, "empty": "", "secretOff": false}],
	  "token": {"id": 7, "value": "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23"},
	  "message": "the call with ranz_ABCDEFGHIJKLMNOPQRSTUVWX23 failed",
	  "count": 3
	}`
	out, n, err := RedactJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, secret := range []string{"c2FsdA", "JBSWY3DPEHPK3PXP", "cHJpdmF0ZUtleQ==", "12345678", "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23"} {
		if strings.Contains(text, secret) {
			t.Errorf("%q is still in\n%s", secret, text)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, text)
	}
	for _, keep := range []string{`"alice"`, `"branch-1"`, `"cHVibGljS2V5"`, `"count": 3`, `"empty": ""`, `"secretOff": false`} {
		if !strings.Contains(text, keep) {
			t.Errorf("%s is gone from\n%s", keep, text)
		}
	}
	// passwordHash, totpSecret, privateKey, psk, token, and the token in the message
	if n != 6 {
		t.Errorf("%d secrets replaced, want 6:\n%s", n, text)
	}
}

// A document that is not one JSON value is refused, so that the caller redacts it as text.
func TestRedactJSONRefusesWhatIsNotJSON(t *testing.T) {
	for _, in := range []string{"", "not json", `{"a": 1} {"b": 2}`, `{"a": 1`, `{"a": 1} x`} {
		if out, _, err := RedactJSON([]byte(in)); err == nil {
			t.Errorf("RedactJSON(%q) = %q, want an error", in, out)
		}
	}
}

// The names of the fields of a document that hold a secret are found in every spelling.
func TestSecretName(t *testing.T) {
	for name, want := range map[string]bool{
		"password": true, "passwordHash": true, "Password": true, "x-api-key": true, "apiKey": true, "api_key": true,
		"private_key": true, "privateKey": true, "totpSecret": true, "token": true, "tokens": true, "salt": true,
		"Authorization": true, "signing-key": true, "psk": true,
		"publicKey": false, "tlsFingerprint": false, "name": false, "kind": false, "generation": false, "id": false,
	} {
		if got := secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v", name, got, want)
		}
	}
}
