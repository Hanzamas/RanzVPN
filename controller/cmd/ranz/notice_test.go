package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The NOTICE holds the licence text of the GoBGP that go.mod pins, word for word (ONE-1, #310):
// section 4 of the Apache License asks for a copy of it with every program that carries GoBGP, and
// ranz is that program. The text is compared with the LICENSE file of the module that this build
// uses, so a GoBGP whose licence text changed fails here until the NOTICE follows it. Only the
// terms are compared, from the title to "END OF TERMS AND CONDITIONS": the appendix after them is
// a template for the owner of a project, and the spacing of both texts does not count.
func TestNoticeHasTheGoBGPLicence(t *testing.T) {
	const module = "github.com/osrg/gobgp/v4"
	const terminator = "END OF TERMS AND CONDITIONS"
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", module).Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", module, err)
	}
	dir := strings.TrimSpace(string(out))
	b, err := os.ReadFile(filepath.Join(dir, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	licence := strings.Join(strings.Fields(string(b)), " ")
	end := strings.Index(licence, terminator)
	if end < 0 {
		t.Fatalf("the LICENSE of %s in %s has no %q", module, dir, terminator)
	}
	want := licence[:end+len(terminator)]
	have := strings.Join(strings.Fields(notice), " ")
	if !strings.Contains(have, want) {
		t.Errorf("the NOTICE does not hold the terms of the licence of %s word for word: %s",
			module, firstDifference(strings.Fields(have), strings.Fields(want)))
	}
}

// The NOTICE holds the licence text of the rqlite release that CI pins, word for word (ONE-4,
// #313): ranz carries the rqlited.exe of that release as the rqlite member of a Controller, and the
// MIT License asks for its text with every copy. rqlite is no module of ranz, so its LICENSE is not
// in the module cache: the test reads the file that RQLITE_LICENSE names, which the jobs of ranz.yml
// download from the pinned tag, and compares it as the test above does. A new version of rqlite,
// whose licence text may change, so fails here until the NOTICE follows it.
func TestNoticeHasTheRqliteLicence(t *testing.T) {
	file := os.Getenv("RQLITE_LICENSE")
	if file == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("RQLITE_LICENSE is not set: CI must provide the LICENSE of the pinned rqlite tag")
		}
		t.Skip("RQLITE_LICENSE is not set: set it to the LICENSE file of the pinned rqlite tag to run this test")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(b))
	if len(want) == 0 {
		t.Fatalf("%s holds no words", file)
	}
	have := strings.Fields(notice)
	if !strings.Contains(strings.Join(have, " "), strings.Join(want, " ")) {
		t.Errorf("the NOTICE does not hold the licence text of rqlite word for word: %s", firstDifference(have, want))
	}
}

// noticeHasTheLicenceInFile checks that the NOTICE holds the words of the licence in the file that
// the environment variable env names, which the jobs of ranz.yml download from the pinned release
// or tag of what the licence is of (ONE-3, #312). The NOTICE has the licence text word for word,
// so a new version, whose licence text may change, fails here until the NOTICE follows it.
func noticeHasTheLicenceInFile(t *testing.T, env, what string) {
	t.Helper()
	file := os.Getenv(env)
	if file == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s is not set: CI must provide the licence of %s", env, what)
		}
		t.Skipf("%s is not set: set it to the licence file of %s to run this test", env, what)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(b))
	if len(want) == 0 {
		t.Fatalf("%s holds no words", file)
	}
	have := strings.Fields(notice)
	if !strings.Contains(strings.Join(have, " "), strings.Join(want, " ")) {
		t.Errorf("the NOTICE does not hold the licence text of %s word for word: %s", what, firstDifference(have, want))
	}
}

// The NOTICE holds the Prebuilt Binaries License of the Wintun release that CI pins (ONE-3, #312):
// ranz carries its wintun.dll, and the licence asks for its text to go with the DLL.
func TestNoticeHasTheWintunLicence(t *testing.T) {
	noticeHasTheLicenceInFile(t, "WINTUN_LICENSE", "the pinned Wintun release")
}

// The NOTICE holds the MIT License of the XDP for Windows release that CI pins (ONE-3, #312): ranz
// carries the files of its runtime.
func TestNoticeHasTheXDPLicence(t *testing.T) {
	noticeHasTheLicenceInFile(t, "XDP_LICENSE", "the pinned XDP for Windows release")
}

// The NOTICE holds the licence statement of SoftEther VPN as the hamcore of the C build holds it
// (src/bin/hamcore/legal.txt): the copyright lines, the Apache License reference and the
// disclaimer, word for word. SeLow is part of SoftEther VPN, and ranz carries its driver package
// (ONE-3, #312). The text of the Apache License itself is in the NOTICE already, in the section of
// GoBGP.
func TestNoticeHasTheSeLowLicence(t *testing.T) {
	b, err := os.ReadFile("../../../src/bin/hamcore/legal.txt")
	if err != nil {
		t.Fatal(err)
	}
	legal := string(b)
	start := strings.Index(legal, "SoftEther VPN:")
	if start < 0 {
		t.Fatal("legal.txt has no section of SoftEther VPN")
	}
	section := legal[start:]
	if end := strings.Index(section, "-------------------"); end >= 0 {
		section = section[:end]
	}
	paragraphs := regexp.MustCompile(`\r?\n[ \t]*\r?\n`).Split(strings.TrimSpace(section), -1)
	// The copyright lines, the licence and the disclaimer; the fourth paragraph says where the
	// licence text is in legal.txt, which is not where it is in the NOTICE
	if len(paragraphs) < 3 {
		t.Fatalf("the section of SoftEther VPN in legal.txt has %d paragraphs, want at least 3", len(paragraphs))
	}
	have := strings.Join(strings.Fields(notice), " ")
	for _, p := range paragraphs[:3] {
		if !strings.Contains(have, strings.Join(strings.Fields(p), " ")) {
			t.Errorf("the NOTICE does not hold this paragraph of the SoftEther VPN section of legal.txt: %.80s", strings.TrimSpace(p))
		}
	}
	if !strings.Contains(have, "SeLow_x64.sys") || !strings.Contains(have, "SeLow_Win10_x64.cat") || !strings.Contains(have, "SeLow_x64.inf") {
		t.Error("the NOTICE does not name the files of the SeLow package")
	}
}

// The NOTICE names the version of each Payload that CI pins, as the fetch script of that Payload
// pins it (ONE-3, #312), so a new pin fails here until the NOTICE follows it.
func TestNoticeNamesThePinnedPayloads(t *testing.T) {
	pinned := regexp.MustCompile(`\$Version\s*=\s*'([0-9.]+)'`)
	have := strings.Join(strings.Fields(notice), " ")
	for _, c := range []struct{ script, phrase string }{
		{"fetch-wintun.ps1", "Wintun release "},
		{"fetch-xdp.ps1", "Microsoft.XDP-for-Windows.Runtime.x64 "},
	} {
		b, err := os.ReadFile("../../../.github/scripts/" + c.script)
		if err != nil {
			t.Fatal(err)
		}
		m := pinned.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s pins no version with $Version = '...'", c.script)
		}
		if want := c.phrase + string(m[1]); !strings.Contains(have, want) {
			t.Errorf("%s pins %s, and the NOTICE has no %q", c.script, m[1], want)
		}
	}
}

// firstDifference tells where the words of want stop matching the words of have, for the failure
// message. It aligns the two at the first run of ten words that they share, because the NOTICE has
// a heading of its own before the licence text.
func firstDifference(have, want []string) string {
	const run = 10
	for start := range have {
		n := 0
		for n < len(want) && start+n < len(have) && have[start+n] == want[n] {
			n++
		}
		if n < run {
			continue
		}
		if n == len(want) {
			return "no difference"
		}
		got := "the end of the NOTICE"
		if start+n < len(have) {
			got = strconv.Quote(have[start+n])
		}
		return fmt.Sprintf("word %d of the licence is %q, and the NOTICE has %s there", n+1, want[n], got)
	}
	return "the NOTICE has no run of ten words of the licence"
}

// `ranz notice` prints the NOTICE as it is, and takes no arguments.
func TestRunNotice(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runNotice(nil, &out, &errOut); code != 0 || out.String() != notice || errOut.Len() != 0 {
		t.Errorf("ranz notice: exit code %d, %d bytes of %d, stderr %q", code, out.Len(), len(notice), errOut.String())
	}
	out.Reset()
	if code := runNotice([]string{"extra"}, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
		t.Errorf("ranz notice extra: exit code %d, stdout %q, stderr %q, want 2, nothing and a message", code, out.String(), errOut.String())
	}
}
