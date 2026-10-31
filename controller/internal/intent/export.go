package intent

import (
	"io"
	"net/netip"

	"sigs.k8s.io/yaml"
)

// The export and the import of the whole intent (SDN-52, #245). `ranz export` writes the intent
// as one document, each resource with the values the controller filled in (the id and the ULA of
// a VRF among them), and `ranz import -f` makes such a document the whole intent again, so the
// intent moves to another controller, or back to this one, and compiles there to the same desired
// state of every node.

// OpImport is the operation of a revision that `ranz import` made.
const OpImport = "import"

// YAML returns d in YAML, which ParseDocument reads back as d: the form of `ranz export -o yaml`.
// It is the JSON of d converted to YAML (sigs.k8s.io/yaml), the way back of ParseDocument.
func (d Document) YAML() ([]byte, error) {
	return yaml.Marshal(d)
}

// Replace returns the intent that doc declares as a whole: the resources of doc, completed and
// validated as Apply completes and validates them, and none of the resources of in that doc
// leaves out; in itself is not changed. A VRF that in holds keeps the id and the ULA that doc
// leaves out of it, as with Apply; where doc declares another id or ULA, the VRF takes that one,
// so an import renumbers a VRF only where its document says so.
func Replace(in Intent, doc Document, random io.Reader) (Intent, error) {
	declared := map[string]Resource{}
	for _, r := range doc.Resources {
		declared[r.Kind+"/"+r.Name] = r
	}
	base := in.Clone()
	for name, v := range base.VRFs {
		r, ok := declared[KindVRF+"/"+name]
		if !ok {
			delete(base.VRFs, name)
			continue
		}
		// A spec that does not decode keeps v: Apply refuses it.
		var d VRF
		if decodeSpec(r.Spec, &d) == nil {
			if d.ID != 0 {
				v.ID = d.ID
			}
			if p, err := netip.ParsePrefix(d.ULA); err == nil {
				d.ULA = p.String()
			}
			if d.ULA != "" {
				v.ULA = d.ULA
			}
			base.VRFs[name] = v
		}
	}
	for name := range base.Networks {
		if _, ok := declared[KindNetwork+"/"+name]; !ok {
			delete(base.Networks, name)
		}
	}
	for name := range base.Nodes {
		if _, ok := declared[KindNode+"/"+name]; !ok {
			delete(base.Nodes, name)
		}
	}
	for name := range base.Policies {
		if _, ok := declared[KindPolicy+"/"+name]; !ok {
			delete(base.Policies, name)
		}
	}
	for name := range base.Mirrors {
		if _, ok := declared[KindMirror+"/"+name]; !ok {
			delete(base.Mirrors, name)
		}
	}
	for name := range base.Controllers {
		if _, ok := declared[KindController+"/"+name]; !ok {
			delete(base.Controllers, name)
		}
	}
	for name := range base.NATs {
		if _, ok := declared[KindNAT+"/"+name]; !ok {
			delete(base.NATs, name)
		}
	}
	for name := range base.DNSRecords {
		if _, ok := declared[KindDNSRecord+"/"+name]; !ok {
			delete(base.DNSRecords, name)
		}
	}
	for name := range base.Listeners {
		if _, ok := declared[KindListener+"/"+name]; !ok {
			delete(base.Listeners, name)
		}
	}
	for name := range base.Devices {
		if _, ok := declared[KindDevice+"/"+name]; !ok {
			delete(base.Devices, name)
		}
	}
	for name := range base.Stretches {
		if _, ok := declared[KindStretch+"/"+name]; !ok {
			delete(base.Stretches, name)
		}
	}
	base.dropUndeclaredUsers(declared)
	next, err := Apply(base, doc, random)
	if err != nil {
		return in, err
	}
	return next, nil
}
