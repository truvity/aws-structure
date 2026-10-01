package registry

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"go.yaml.in/yaml/v3"
)

// Parse reads one registry document, refusing unknown keys, a second
// document and trailing content, and validates the result. The returned
// error lists every problem at once.
func Parse(data []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var r Registry
	if err := dec.Decode(&r); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("registry: the file is empty")
		}
		return nil, fmt.Errorf("registry: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("registry: the file holds more than one YAML document; a registry is exactly one")
	}

	r.applyDefaults()
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Load reads and parses the named file from fsys, typically an embed.FS.
func Load(fsys fs.FS, name string) (*Registry, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	return Parse(data)
}

// applyDefaults fills the only defaults the schema has, and each is the
// safe side: SCPs dormant, groups manual.
func (r *Registry) applyDefaults() {
	if r.SCPEnforcement == "" {
		r.SCPEnforcement = SCPDormant
	}
	for i := range r.IdentityCenter.Groups {
		if r.IdentityCenter.Groups[i].Source == "" {
			r.IdentityCenter.Groups[i].Source = "manual"
		}
	}
	for i := range r.IdentityCenter.Assignments {
		if r.IdentityCenter.Assignments[i].PrincipalType == "" {
			r.IdentityCenter.Assignments[i].PrincipalType = "group"
		}
	}
}
