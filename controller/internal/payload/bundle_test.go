package payload

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// repositoryRoot is the root of the repository, seen from this directory.
const repositoryRoot = "../../.."

// npcapFiles are the names of the files that the Npcap installer and its SDK put on a machine: its driver with its INF
// and catalog, its two DLLs with their import libraries, and its helpers. They are compared without case.
var npcapFiles = []string{
	"npcap.sys",
	"npcap.inf",
	"npcap.cat",
	"npcap_wfp.inf",
	"npf.sys",
	"wpcap.dll",
	"packet.dll",
	"wpcap.lib",
	"packet.lib",
	"npfinstall.exe",
	"npcaphelper.exe",
}

// isNpcapFile reports whether a file of the name is a file of Npcap: one of npcapFiles, or an installer or an SDK
// archive of it (npcap-1.79.exe, npcap-sdk-1.13.zip).
func isNpcapFile(name string) bool {
	lower := strings.ToLower(name)
	for _, n := range npcapFiles {
		if lower == n {
			return true
		}
	}
	return strings.HasPrefix(lower, "npcap-") && (strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".zip"))
}

// Npcap is never bundled (ADR-0018 decision 3; CORE-S3-3, #73): the Node uses it only where the operator installed it
// (src/Cedar/NodeL2Npcap.c), so no Npcap OEM licence is needed. No file of Npcap is anywhere in the repository, so
// neither ranz.exe with its payloads, which go:embed reads from the repository, nor the resources of the C executables
// (src/bin/hamcore) can carry one.
func TestNpcapIsNeverBundled(t *testing.T) {
	sawSeLow := false
	err := filepath.WalkDir(repositoryRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == "SeLow_x64.sys" {
			sawSeLow = true
		}
		if isNpcapFile(d.Name()) {
			t.Errorf("%s is a file of Npcap, which Ranz never bundles", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	// The SeLow package is a payload of ranz.exe (selow/) and a resource of hamcore: a walk that did not see it did not
	// look at the payloads
	if !sawSeLow {
		t.Fatalf("the walk of %s saw no SeLow_x64.sys, so it did not reach the payloads", repositoryRoot)
	}
}

func TestIsNpcapFile(t *testing.T) {
	for _, name := range []string{"wpcap.dll", "Packet.dll", "npcap.sys", "NPFInstall.exe", "npcap-1.79.exe", "npcap-sdk-1.13.zip"} {
		if !isNpcapFile(name) {
			t.Errorf("%s is not taken for a file of Npcap", name)
		}
	}
	for _, name := range []string{"SeLow_x64.sys", "xdpapi.dll", "wintun.dll", "NodeL2Npcap.c", "npcap.md", "bundle_test.go"} {
		if isNpcapFile(name) {
			t.Errorf("%s is taken for a file of Npcap", name)
		}
	}
}
