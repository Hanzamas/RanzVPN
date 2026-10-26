package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// `ranz doctor --bundle` writes the diagnostics bundle of the host it runs on (SDN-54, #247, user
// story 58 of #224): the logs, the configuration and the status of the Node and of the Controller
// that run there, so that a support engineer diagnoses a host without a remote desktop. An admin
// pulls the bundle of a Controller from the web UI (the Diagnostics page).
//
// The bundle holds what its sources name and nothing else: the host and its services, the report of
// the checks, the log files of the Node and of the Controller, and the text dump of the Node's
// configuration store. It does not hold the keys, the token file or the stores, which no source names.
// Every part goes through the redaction of internal/bundle.

// nodeConfigFile is the text dump of its configuration store that the Node writes into its data
// directory (CsDump of src/Cedar/ConfigStore.c): the settings, the networks, the users without their
// password hashes, the listeners, the certificates and the admins.
const nodeConfigFile = "node_config.txt"

// maxConfigBytes is the most of a configuration file that a bundle holds.
const maxConfigBytes = 1 << 20

// defaultNodeDir returns the data directory of the Node of this host, %ProgramData%\Hanzcodes\Ranz
// VPN (NodeDefaultDataDir of src/Cedar/Node.c), where its log is in node_log. It is empty on a host
// with no ProgramData folder, which is every host but Windows.
func defaultNodeDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		return ""
	}
	return filepath.Join(base, "Hanzcodes", "Ranz VPN")
}

// hostSources returns the sources of the bundle of this host: the host and its services, the report
// of the checks that ranz doctor made, and, for a Node data directory and a Controller data
// directory that are not empty, their log files and the configuration of the Node. A directory that
// does not exist gives no part.
func hostSources(report, nodeDir, controllerDir string) []bundle.Source {
	sources := []bundle.Source{
		bundle.SystemSource(),
		bundle.ServicesSource(),
		{Name: "doctor", Collect: func(context.Context) ([]bundle.Part, error) {
			return []bundle.Part{bundle.Text("doctor.txt", report)}, nil
		}},
	}
	if nodeDir != "" {
		sources = append(sources,
			bundle.LogSource("node log", "node/logs", func() ([]string, error) {
				return bundle.Matching(filepath.Join(nodeDir, "node_log"), "node_*.log", "ranz-bgp*.log", "ranz-mimic*.log")
			}),
			fileSource("node configuration", "node/config.txt", filepath.Join(nodeDir, nodeConfigFile)),
		)
	}
	if controllerDir != "" {
		sources = append(sources, bundle.LogSource("controller log", "controller/logs", func() ([]string, error) {
			return bundle.Matching(controllerDir, "controller*.log")
		}))
	}
	return sources
}

// fileSource returns the source of the part name, the file at path: no part when the file is not
// there, and the start of it when it is larger than maxConfigBytes.
func fileSource(source, name, path string) bundle.Source {
	return bundle.Source{Name: source, Collect: func(context.Context) ([]bundle.Part, error) {
		f, err := os.Open(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes))
		if err != nil {
			return nil, err
		}
		return []bundle.Part{{Name: name, Data: data}}, nil
	}}
}

// writeBundle makes the bundle of sources as a kind host and writes it to the file path, which must
// not exist yet: the bundle is for the person who runs the command, not for a file that was there
// before. A bundle that fails leaves no file.
func writeBundle(ctx context.Context, path string, sources []bundle.Source) (bundle.Manifest, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return bundle.Manifest{}, err
	}
	m, err := bundle.Build(ctx, f, bundle.Info{Kind: "host", Version: version.Version + "." + build}, sources...)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return bundle.Manifest{}, err
	}
	return m, nil
}

// defaultBundleFile returns the name of the file of a bundle that is made at now when -o names
// none, in the current directory: ranz-host-NAME-TIME.zip.
func defaultBundleFile(now time.Time) string {
	host, _ := os.Hostname()
	return bundle.Manifest{Kind: "host", Host: host, Created: now}.ArchiveName()
}

// reportBundle prints what writeBundle made to out: the file, its size, and what the manifest says
// went wrong.
func reportBundle(out io.Writer, path string, m bundle.Manifest) {
	var size int64
	if info, err := os.Stat(path); err == nil {
		size = info.Size()
	}
	fmt.Fprintf(out, "\nDiagnostics bundle written to %s: %d parts, %d bytes. It holds no secret; manifest.json in it lists every part with the number of secrets replaced in it.\n",
		path, len(m.Parts), size)
	for _, p := range m.Problems {
		fmt.Fprintf(out, "  not complete: %s\n", p)
	}
}
