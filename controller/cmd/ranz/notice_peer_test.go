package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The NOTICE holds the licence notices of libjuice and libplum (CORE-S5-6, #412): ranz.exe carries
// ranz-node.exe, which links both, and the Mozilla Public License 2.0 asks that a recipient is told
// under which licence they are and where their source is (section 3.2). The NOTICE names the commit
// of each submodule that the build pins, so a new pin fails here until the NOTICE follows it, and the
// copyright notice of each. The LICENSE file of each, the text of the licence, is in the NOTICE word
// for word: the test reads it from the submodule when the checkout has it, else from the file of the
// pinned commit that the jobs of ranz.yml download and name in LIBJUICE_LICENSE and LIBPLUM_LICENSE.
// The file that Ranz VPN changes in each keeps the notices of the file that it stands in for and of
// the licence (section 3.4).
func TestNoticeHasTheLicencesOfLibjuiceAndLibplum(t *testing.T) {
	const root = "../../.."
	have := strings.Join(strings.Fields(notice), " ")
	for _, lib := range []struct {
		name, env, copyright, changed, changedCopyright string
	}{
		{"libjuice", "LIBJUICE_LICENSE", "libjuice: Copyright (c) 2020-2022 Paul-Louis Ageneau", "juice-peer.c", "Copyright (c) 2022 Paul-Louis Ageneau"},
		{"libplum", "LIBPLUM_LICENSE", "libplum: Copyright (c) 2021 Paul-Louis Ageneau", "plum-xml.c", "Copyright (c) 2021 Paul-Louis Ageneau"},
	} {
		t.Run(lib.name, func(t *testing.T) {
			path := "src/Core/3rdparty/" + lib.name
			out, err := exec.Command("git", "-C", root, "ls-tree", "HEAD", path).Output()
			fields := strings.Fields(string(out))
			if err != nil || len(fields) < 3 || fields[1] != "commit" || len(fields[2]) < 12 {
				if os.Getenv("CI") != "" {
					t.Fatalf("git ls-tree HEAD %s: %v, %q: the checkout must have the pin of the submodule", path, err, out)
				}
				t.Skipf("git ls-tree HEAD %s: %v: run the test in a git checkout", path, err)
			}
			if pin := "the commit " + fields[2][:12]; !strings.Contains(have, lib.name) || !strings.Contains(have, pin) {
				t.Errorf("the build pins %s at %s, and the NOTICE has no %q", lib.name, fields[2], pin)
			}
			if !strings.Contains(have, lib.copyright) {
				t.Errorf("the NOTICE has no %q", lib.copyright)
			}

			licence := filepath.Join(root, path, "LICENSE")
			if _, err := os.Stat(licence); err != nil {
				licence = os.Getenv(lib.env)
			}
			if licence == "" {
				if os.Getenv("CI") != "" {
					t.Fatalf("%s is not set and the checkout has no submodule %s: CI must provide the LICENSE of its pinned commit", lib.env, path)
				}
				t.Skipf("%s is not set: check out the submodule %s, or set it to the LICENSE of its pinned commit", lib.env, path)
			}
			b, err := os.ReadFile(licence)
			if err != nil {
				t.Fatal(err)
			}
			want := strings.Fields(string(b))
			if len(want) == 0 || !strings.Contains(have, strings.Join(want, " ")) {
				t.Errorf("the NOTICE does not hold the LICENSE of %s word for word: %s", lib.name, firstDifference(strings.Fields(notice), want))
			}

			src, err := os.ReadFile(filepath.Join(root, "src/Core/3rdparty", lib.changed))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Join(strings.Fields(string(src)), " ")
			mpl := "This Source Code Form is subject to the terms of the Mozilla Public * License, v. 2.0."
			if !strings.Contains(have, lib.changed) || !strings.Contains(text, lib.changedCopyright) || !strings.Contains(text, mpl) {
				t.Errorf("%s, which Ranz VPN changes, is not named in the NOTICE, or lacks %q or the notice of the licence", lib.changed, lib.changedCopyright)
			}
		})
	}
}
