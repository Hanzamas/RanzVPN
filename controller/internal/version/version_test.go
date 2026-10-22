package version

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The controller has the version of the C build: the major.minor of VERSION in CMakeLists.txt.
func TestMatchesCMake(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "CMakeLists.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`VERSION "(\d+\.\d+)\.\$\{BUILD_NUMBER\}"`).FindSubmatch(b)
	if m == nil {
		t.Fatal(`CMakeLists.txt has no VERSION "major.minor.${BUILD_NUMBER}"`)
	}
	if string(m[1]) != Version {
		t.Errorf("Version is %s, and CMakeLists.txt has version %s", Version, m[1])
	}
}
