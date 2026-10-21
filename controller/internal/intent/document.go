package intent

import (
	"bytes"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"
)

// ParseDocument reads an intent document in JSON or in YAML, as `ranz apply -f` takes it. YAML
// is converted to JSON first (sigs.k8s.io/yaml) and then read like JSON, so both give the same
// document; JSON stays the canonical form, the one the API takes and the controller stores. A
// document whose first character is "{" is JSON, any other is YAML.
func ParseDocument(b []byte) (Document, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' {
		j, err := yaml.YAMLToJSON(b)
		if err != nil {
			return Document{}, fmt.Errorf("YAML: %w", err)
		}
		b = j
	}
	var doc Document
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return Document{}, err
	}
	return doc, nil
}
