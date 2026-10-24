// Package bundle is the diagnostics bundle of Ranz (SDN-54, #247, user story 58 of #224): the logs,
// the configuration and the status of a Controller or of the host of a Node, collected into one ZIP
// archive that a support engineer reads without a remote desktop. `ranz doctor --bundle` makes the
// bundle of the host it runs on, and an operator pulls the bundle of the Controller from the web UI
// (the API call POST /api/v1/diagnostics/bundle).
//
// A bundle holds no secrets. It is built from Sources, each of which names the parts it gives (the
// log files of a directory, the status as JSON, the intent), so nothing that nobody named goes in:
// not the keys of the Controller, not the token file, not the store. Every part then goes through
// Redact or, for JSON, RedactJSON, which replace the values of fields whose names hold a secret and
// the secrets that have a form of their own, and the manifest of the bundle says how many each part
// held.
package bundle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	// ManifestName is the name of the part that lists the others.
	ManifestName = "manifest.json"
	// MaxPartBytes is the most that one part may hold; a larger one is left out.
	MaxPartBytes = 16 << 20
	// MaxBytes is the most that all the parts together may hold. A part that would pass it is left
	// out.
	MaxBytes = 48 << 20
	// maxName is the longest name of a part.
	maxName = 200
)

// Part is one file of a bundle.
type Part struct {
	// Name is its path in the archive, with slashes: logs/controller.log.
	Name string
	// Data is its content.
	Data []byte
}

// Source collects some parts of a bundle: the logs of a program, its status, its configuration. A
// source that returns an error and parts as well gives both: the parts go in, and the error is
// named in the manifest.
type Source struct {
	// Name is what the manifest calls the source.
	Name string
	// Collect returns its parts.
	Collect func(ctx context.Context) ([]Part, error)
}

// ManifestPart is what the manifest says of one part.
type ManifestPart struct {
	// Name is the name of the part in the archive.
	Name string `json:"name"`
	// Source is the name of the source that gave it.
	Source string `json:"source"`
	// Size is its size in bytes, as it is in the archive.
	Size int `json:"size"`
	// SHA256 is the hash of its content, in hex.
	SHA256 string `json:"sha256"`
	// Redactions is how many secrets were replaced in it.
	Redactions int `json:"redactions,omitempty"`
}

// Manifest is the part ManifestName: what the bundle holds, where it comes from, and what went
// wrong while it was made.
type Manifest struct {
	// Product is Ranz.
	Product string `json:"product"`
	// Kind is controller for the bundle of a Controller and host for the one of a host.
	Kind string `json:"kind"`
	// Created is when it was made.
	Created time.Time `json:"created"`
	// Host is the name of the host it was made on.
	Host string `json:"host"`
	// Version is the version of ranz that made it.
	Version string `json:"version,omitempty"`
	// Redaction says what was left out.
	Redaction string `json:"redaction"`
	// Parts are the parts of the archive, in the order of their names, without the manifest.
	Parts []ManifestPart `json:"parts"`
	// Problems are the sources that failed and the parts that were left out, and why.
	Problems []string `json:"problems,omitempty"`
}

// redactionNote is what the manifest says of the secrets.
const redactionNote = "No secret is in this bundle. The values of fields whose names hold a secret (password, token, key, " +
	"hash, ...) and the secrets that have a form of their own (bearer tokens, API tokens, private keys, password hashes, " +
	"passwords in URLs) are replaced by " + Replacement + "; the counts are in the parts below."

// Info tells Build what the bundle is for.
type Info struct {
	// Kind is controller or host.
	Kind string
	// Version is the version of ranz.
	Version string
	// Host is the name of the host; the host name of this one when it is empty.
	Host string
	// Now is the clock of the bundle; time.Now when it is nil.
	Now func() time.Time
}

// Build collects the parts of sources, puts each through the rules of redaction and writes the
// archive to w, the manifest first. A source that fails, a part whose name is not one, one that is
// too large and one that would take the bundle over MaxBytes are named in the manifest and left
// out; the others go in. It fails when ctx ends or w cannot be written.
func Build(ctx context.Context, w io.Writer, info Info, sources ...Source) (Manifest, error) {
	now := time.Now()
	if info.Now != nil {
		now = info.Now()
	}
	now = now.UTC().Truncate(time.Second)
	host := info.Host
	if host == "" {
		host, _ = os.Hostname()
	}
	m := Manifest{Product: "Ranz", Kind: info.Kind, Created: now, Host: host, Version: info.Version, Redaction: redactionNote, Parts: []ManifestPart{}}
	problem := func(format string, args ...any) {
		text, _ := Redact(fmt.Sprintf(format, args...))
		m.Problems = append(m.Problems, text)
	}

	var parts []Part
	from := map[string]string{}
	total := 0
	for _, s := range sources {
		got, err := s.Collect(ctx)
		if ctx.Err() != nil {
			return Manifest{}, ctx.Err()
		}
		if err != nil {
			problem("%s: %v", s.Name, err)
		}
		for _, p := range got {
			switch {
			case !validName(p.Name) || p.Name == ManifestName:
				problem("%s: %q is not a name that a part may have: left out", s.Name, p.Name)
				continue
			case from[p.Name] != "":
				problem("%s: the part %s is in the bundle already, from %s: left out", s.Name, p.Name, from[p.Name])
				continue
			case len(p.Data) > MaxPartBytes:
				problem("%s: the part %s is %d bytes, more than %d: left out", s.Name, p.Name, len(p.Data), MaxPartBytes)
				continue
			}
			red, n := redactPart(p)
			if total+len(red.Data) > MaxBytes {
				problem("%s: the part %s would take the bundle over %d bytes: left out", s.Name, p.Name, MaxBytes)
				continue
			}
			total += len(red.Data)
			from[p.Name] = s.Name
			sum := sha256.Sum256(red.Data)
			m.Parts = append(m.Parts, ManifestPart{Name: p.Name, Source: s.Name, Size: len(red.Data), SHA256: hex.EncodeToString(sum[:]), Redactions: n})
			parts = append(parts, red)
		}
	}
	sort.Slice(m.Parts, func(i, j int) bool { return m.Parts[i].Name < m.Parts[j].Name })
	sort.Slice(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })

	doc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	zw := zip.NewWriter(w)
	for _, p := range append([]Part{{Name: ManifestName, Data: append(doc, '\n')}}, parts...) {
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: p.Name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return Manifest{}, err
		}
		if _, err := fw.Write(p.Data); err != nil {
			return Manifest{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// redactPart returns the part p with its secrets replaced, and how many: JSON by the names of its
// fields, anything else as text.
func redactPart(p Part) (Part, int) {
	if strings.EqualFold(path.Ext(p.Name), ".json") {
		if data, n, err := RedactJSON(p.Data); err == nil {
			return Part{Name: p.Name, Data: data}, n
		}
	}
	text, n := Redact(string(p.Data))
	return Part{Name: p.Name, Data: []byte(text)}, n
}

// validName reports whether name can be the name of a part: a clean relative path of letters,
// digits and a few marks, which no program that unpacks the archive can take for a path outside
// its folder.
func validName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > maxName || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._~-/", r):
		default:
			return false
		}
	}
	return true
}

// FileName returns name as the last element of the name of a part: the characters that a name may
// not have are replaced by underscores.
func FileName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._~-", r):
			return r
		}
		return '_'
	}, path.Base(strings.ReplaceAll(name, `\`, "/")))
}

// JSON returns the part name that holds v as indented JSON.
func JSON(name string, v any) (Part, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return Part{}, fmt.Errorf("the part %s: %w", name, err)
	}
	return Part{Name: name, Data: append(b, '\n')}, nil
}

// Text returns the part name that holds text.
func Text(name, text string) Part {
	return Part{Name: name, Data: []byte(text)}
}

// JSONSource returns the source that gives the part name, the JSON of what get returns.
func JSONSource(source, name string, get func(ctx context.Context) (any, error)) Source {
	return Source{Name: source, Collect: func(ctx context.Context) ([]Part, error) {
		v, err := get(ctx)
		if err != nil {
			return nil, err
		}
		p, err := JSON(name, v)
		if err != nil {
			return nil, err
		}
		return []Part{p}, nil
	}}
}

// readTail returns the last limit bytes of the file at filePath, cut at the start of a line, and
// how many bytes before them were left out. A file that is not larger than limit is returned
// whole. A window that holds no line end is returned as it is, from the middle of its line.
func readTail(filePath string, limit int64) ([]byte, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if size <= limit {
		b, err := io.ReadAll(io.LimitReader(f, size))
		return b, 0, err
	}
	skipped := size - limit
	// The window starts one byte early, to tell whether it starts at the start of a line.
	if _, err := f.Seek(skipped-1, io.SeekStart); err != nil {
		return nil, 0, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 {
		return nil, skipped, err
	}
	atLineStart := b[0] == '\n'
	b = b[1:]
	if !atLineStart {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			skipped += int64(i) + 1
			b = b[i+1:]
		}
	}
	return b, skipped, nil
}
