package controller_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
)

// The rows of the threat model that AUD1-DT-20 (#522) corrects, as tests. The page is written for a person, so each test looks
// for what the criterion names in the row that it is about, with the white space of the row folded into one space, and ties what
// the row points at, a model or a test, to what exists: a row that loses a phrase, or that names a model or a test that is gone,
// fails here until the page and the code agree again.

// repoFile returns the text of a file of the repository, which is three levels up from this package, with the line endings that a
// checkout on Windows may have changed (core.autocrlf) made into line feeds.
func repoFile(t *testing.T, elem ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", ".."}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// threatModelRow returns the row of the threat model, or of the register of its gaps, whose id is id, with its white space folded.
func threatModelRow(t *testing.T, id string) string {
	t.Helper()
	for _, l := range strings.Split(repoFile(t, "docs", "threat-model.md"), "\n") {
		if strings.HasPrefix(l, "| "+id+" |") {
			return strings.Join(strings.Fields(l), " ")
		}
	}
	t.Fatalf("the threat model has no row %s", id)
	return ""
}

// formalModels returns the variants of the formal models that tests/formal/expected.tsv gives the answers of.
func formalModels(t *testing.T) map[string]bool {
	t.Helper()
	models := map[string]bool{}
	for _, l := range strings.Split(repoFile(t, "tests", "formal", "expected.tsv"), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			models[f[0]] = true
		}
	}
	return models
}

// checkRowSays fails the test for each phrase that the row id of the threat model does not hold.
func checkRowSays(t *testing.T, id string, phrases ...string) {
	t.Helper()
	row := threatModelRow(t, id)
	for _, want := range phrases {
		if !strings.Contains(row, want) {
			t.Errorf("the row %s of the threat model does not say %q", id, want)
		}
	}
}

// checkRowNamesModels fails the test for each model that the row id does not name in backquotes, or that has no answers in
// tests/formal/expected.tsv, which the jobs of the formal models check.
func checkRowNamesModels(t *testing.T, id string, models ...string) {
	t.Helper()
	row := threatModelRow(t, id)
	known := formalModels(t)
	for _, m := range models {
		if !strings.Contains(row, "`"+m+"`") {
			t.Errorf("the row %s of the threat model does not name the model `%s`", id, m)
		}
		if !known[m] {
			t.Errorf("the row %s names the model `%s`, which tests/formal/expected.tsv has no answers of", id, m)
		}
	}
}

// checkRowNamesTests fails the test for each test that the row id does not name in backquotes, or that no test file of the
// Controller defines.
func checkRowNamesTests(t *testing.T, id string, tests ...string) {
	t.Helper()
	row := threatModelRow(t, id)
	defined := map[string]bool{}
	// The code of the Controller is the directory two levels up from this package
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, name := range tests {
			if strings.Contains(string(b), "func "+name+"(") {
				defined[name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range tests {
		if !strings.Contains(row, "`"+name+"`") {
			t.Errorf("the row %s of the threat model does not name the test `%s`", id, name)
		}
		if !defined[name] {
			t.Errorf("the row %s names the test `%s`, which no test file of the Controller defines", id, name)
		}
	}
}

// TestThreatModelCS6ListsTheLoadOfChangedPins is the second criterion of AUD1-DT-20: the row CS-6 lists a changed Pins report that
// comes again and again as a threat, and answers it with the interval of the Controller, which it quotes as the constant has it, and
// with the tests that show the limit.
func TestThreatModelCS6ListsTheLoadOfChangedPins(t *testing.T) {
	checkRowSays(t, "CS-6",
		"reports a changed `Pins` again and again",
		"costs a write to the store, a compile of the whole intent and a commit while the Controller holds its lock, and a Generation for each client of the server",
		fmt.Sprintf("The Controller applies one change of the keys of a Node in `PinsInterval` (%d s)", int(controller.PinsInterval/time.Second)),
		"A report that comes sooner is held, a later one replaces it, and one that returns to the keys in force voids it",
	)
	checkRowNamesTests(t, "CS-6", "TestMimicChangedKeysAreAppliedOncePerInterval", "TestMimicKeysThatComeBackVoidTheReportThatWaits")
}

// TestThreatModelCS5SaysWhatTheClientStatesHold is the third criterion of AUD1-DT-20: the row CS-5 says what the states of a client
// hold now, the link of each mimic server that it dials, and names the case of a stolen client key with the model that shows it; it
// no longer says that the desired state holds no secret.
func TestThreatModelCS5SaysWhatTheClientStatesHold(t *testing.T) {
	checkRowSays(t, "CS-5",
		"its mimic links (the address, the server name, the public key and the short id of each mimic server that it dials)",
		"The link of a client holds, for each mimic server that it dials, the address, the first server name, the public key of the server and its short id",
		"So whoever steals the key of a client holds a link",
		"it learns that the server is no decoy (model `mimic-link`",
	)
	if row := threatModelRow(t, "CS-5"); strings.Contains(row, "holds no secret today") {
		t.Error("the row CS-5 of the threat model still says that the desired state holds no secret today")
	}
	checkRowNamesModels(t, "CS-5", "mimic-link", "control-node-client")
}

// TestThreatModelTR9NamesTheFormalModelOfTheMimicPath is the fourth criterion of AUD1-DT-20: the row TR-9 names the formal model of the
// mimic path, each of its four variants, which have a file in tests/formal/mimic, and says what the models cover and leave out; it no
// longer says that the formal model has no mimic path, and the register of the gaps no longer says that the path has no model.
func TestThreatModelTR9NamesTheFormalModelOfTheMimicPath(t *testing.T) {
	variants := []string{"mimic-none", "mimic-link", "mimic-key", "mimic-nobinding-key"}
	checkRowSays(t, "TR-9",
		"The formal model of the path is `tests/formal/mimic`",
		"The models cover ",
		"They leave out ",
	)
	checkRowNamesModels(t, "TR-9", variants...)
	for _, v := range variants {
		if _, err := os.Stat(filepath.Join("..", "..", "..", "tests", "formal", "mimic", v+".pv")); err != nil {
			t.Errorf("the row TR-9 names the model `%s`, which has no file in tests/formal/mimic: %v", v, err)
		}
	}
	if row := threatModelRow(t, "TR-9"); strings.Contains(row, "no mimic path") {
		t.Error("the row TR-9 of the threat model still says that the formal model has no mimic path")
	}
	if row := threatModelRow(t, "G-11"); strings.Contains(row, "no formal model") {
		t.Error("the row G-11 of the threat model still says that the mimic path has no formal model")
	}
}
