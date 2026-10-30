//go:build !windows

package main

import "testing"

// trustFingerprint does nothing: the owner and the access list of the fingerprint file are checked on Windows
// (AUD1-DT-14, #496), and elsewhere ranz takes the file of a folder that the test made.
func trustFingerprint(*testing.T, string) {}
