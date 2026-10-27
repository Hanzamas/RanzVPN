package store

import (
	"context"
	"testing"
	"time"
)

// The URL of an rqlite that another process runs is https, or plain http on loopback.
func TestCheckRqliteURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"http://127.0.0.1:4001":          true,
		"http://127.1.2.3:4001":          true,
		"http://localhost:4001":          true,
		"http://[::1]:4001":              true,
		"https://rqlite.example.com":     true,
		"https://192.0.2.1:4001":         true,
		"http://192.0.2.1:4001":          false,
		"http://rqlite.example.com:4001": false,
		"http://[2001:db8::1]:4001":      false,
		"http://":                        false,
		"ssh://127.0.0.1":                false,
		"":                               false,
	} {
		if err := CheckRqliteURL(url); (err == nil) != ok {
			t.Errorf("CheckRqliteURL(%q) = %v, want accepted %v", url, err, ok)
		}
	}
}

// A CA that is no PEM certificate is refused before the store connects.
func TestOpenWithRefusesABadCA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := OpenWith(ctx, "https://127.0.0.1:1", Access{CA: []byte("not a certificate")}); err == nil {
		t.Error("OpenWith took a CA that holds no certificate")
	}
}
