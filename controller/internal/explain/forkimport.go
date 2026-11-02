package explain

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Hanzamas/RanzVPN/controller/internal/forkimport"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ForkImport asks a scenario for the resources that the import of a fork Config file makes (SDN-27, #203; package
// forkimport). The scenario then judges its packets by the Policies that an operator gets from `ranz import-config`,
// with the Nodes of its own added, in explain and in the data plane of the harness, and a change of the import changes
// the scenario: the intent that it runs cannot drift from the import.
type ForkImport struct {
	// Config is the path of the Config file, relative to the directory of the file of the scenario.
	Config string `json:"config"`
	// Hubs are the Virtual Hubs to import, by name; every one when it is left out.
	Hubs []string `json:"hubs,omitempty"`
	// Pools are the IPv4 pools of their Networks, by name of the Virtual Hub.
	Pools map[string]string `json:"pools,omitempty"`
}

// resources returns the resources of the import, the Config file read relative to the directory dir.
func (f ForkImport) resources(dir string) ([]intent.Resource, error) {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Config)))
	if err != nil {
		return nil, err
	}
	root, err := forkimport.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Config, err)
	}
	res, err := forkimport.Import(root, forkimport.Options{Hubs: f.Hubs, Pools: f.Pools})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Config, err)
	}
	return res.Document.Resources, nil
}
