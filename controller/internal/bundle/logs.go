package bundle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// DefaultLogBytes is how much of the log files of one source a bundle holds at most: the newest
// records. The limits of the logs themselves (internal/logfile, LogWriter.c) keep the files on the
// disk within their disk limit, which is larger than what a person reads in a bundle.
const DefaultLogBytes = 16 << 20

// Matching returns the paths of the files in dir whose names match one of the patterns (path.Match,
// compared without case), by name. The names of log files hold their date, so their order is the
// order of their records. A directory that does not exist has none.
func Matching(dir string, patterns ...string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		for _, p := range patterns {
			if ok, _ := path.Match(strings.ToLower(p), name); ok {
				out = append(out, filepath.Join(dir, e.Name()))
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return out, nil
}

// LogFiles returns the log files at paths, which are in the order of their records, the oldest
// first, as the parts dir/NAME. The newest are taken first, whole, until budget bytes are used;
// the oldest that is taken then holds only its last lines, under a line that says so, and the older
// ones are left out. The error names the files that could not be read and the ones that the budget
// left out; the parts are the others.
func LogFiles(dir string, paths []string, budget int64) ([]Part, error) {
	var parts []Part
	var problems []error
	left := budget
	for i := len(paths) - 1; i >= 0; i-- {
		if left <= 0 {
			problems = append(problems, fmt.Errorf("%d older log files are left out: the bundle holds the newest %d bytes of the logs", i+1, budget))
			break
		}
		data, skipped, err := readTail(paths[i], left)
		if err != nil {
			problems = append(problems, fmt.Errorf("reading %s: %w", paths[i], err))
			continue
		}
		if skipped > 0 {
			data = append([]byte(fmt.Sprintf("[the first %d bytes of this file are left out of the bundle]\n", skipped)), data...)
		}
		left -= int64(len(data))
		parts = append(parts, Part{Name: path.Join(dir, FileName(paths[i])), Data: data})
	}
	slices.Reverse(parts)
	return parts, errors.Join(problems...)
}

// LogSource returns the source that gives the log files that list returns when the bundle is made,
// in the order of their records, as the parts dir/NAME (LogFiles), within DefaultLogBytes.
func LogSource(name, dir string, list func() ([]string, error)) Source {
	return Source{Name: name, Collect: func(context.Context) ([]Part, error) {
		paths, err := list()
		if err != nil {
			return nil, err
		}
		return LogFiles(dir, paths, DefaultLogBytes)
	}}
}
