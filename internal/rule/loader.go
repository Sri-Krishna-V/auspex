package rule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// maxRuleFileSize caps a single rule file to keep loading bounded against a
// malformed or hostile rule file on disk.
const maxRuleFileSize = 4 * 1024 * 1024

// LoadSource decodes one YAML rule file from r. The public file format is one
// top-level Rule per file; the returned Source is only the internal container the
// engine uses for source labeling. LoadSource does not compile rules; pass the
// result to NewEngine for strict compilation.
func LoadSource(reader io.Reader, name string) (Source, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxRuleFileSize+1))
	if err != nil {
		return Source{}, fmt.Errorf("read rule file %q: %w", name, err)
	}
	if len(data) > maxRuleFileSize {
		return Source{}, fmt.Errorf("read rule file %q: exceeds %d bytes", name, maxRuleFileSize)
	}

	if err := rejectNonSingleRuleShape(data, name); err != nil {
		return Source{}, err
	}
	var rule Rule
	if err := decodeRuleYAML(data, name, &rule); err != nil {
		return Source{}, err
	}
	if err := validateRuleVersion(rule, name); err != nil {
		return Source{}, err
	}
	return Source{
		Name:  strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)),
		Rules: []Rule{rule},
	}, nil
}

func rejectNonSingleRuleShape(data []byte, name string) error {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("decode rule file %q: %w", name, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode rule file %q: multiple YAML documents are not supported", name)
		}
		return fmt.Errorf("decode rule file %q: %w", name, err)
	}
	keys := topLevelKeys(&doc)
	if _, hasRules := keys["rules"]; hasRules {
		return fmt.Errorf("decode rule file %q: top-level rules is not supported; use one rule per file", name)
	}
	if _, hasName := keys["name"]; hasName {
		return fmt.Errorf("decode rule file %q: top-level name is not supported; use one rule per file", name)
	}
	return nil
}

func topLevelKeys(doc *yaml.Node) map[string]struct{} {
	keys := map[string]struct{}{}
	node := doc
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return keys
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys[node.Content[i].Value] = struct{}{}
	}
	return keys
}

func decodeRuleYAML(data []byte, name string, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode rule file %q: %w", name, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode rule file %q: multiple YAML documents are not supported", name)
		}
		return fmt.Errorf("decode rule file %q: %w", name, err)
	}
	return nil
}

func validateRuleVersion(r Rule, sourceName string) error {
	if strings.TrimSpace(r.Version) != "" {
		return nil
	}
	id := strings.TrimSpace(r.ID)
	if id == "" {
		id = "<missing id>"
	}
	return fmt.Errorf("rule file %q rule %s: missing version", sourceName, id)
}

// IsRuleTestFile reports whether path follows the companion test filename
// convention used by `auspex rules check`.
func IsRuleTestFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(path), ext)
	return strings.HasSuffix(base, "_tests")
}

// LoadSourcesFS loads every *.yaml / *.yml rule file under dir in fsys, sorted
// by path for deterministic ordering. It is the shared entry point for both
// embedded built-in files and operator-supplied rule directories.
func LoadSourcesFS(fsys fs.FS, dir string) ([]Source, error) {
	var paths []string
	walkErr := fs.WalkDir(fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if IsRuleTestFile(p) {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml":
			paths = append(paths, p)
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk rules %q: %w", dir, walkErr)
	}
	sort.Strings(paths)

	sources := make([]Source, 0, len(paths))
	for _, p := range paths {
		f, err := fsys.Open(p)
		if err != nil {
			return nil, fmt.Errorf("open rule file %q: %w", p, err)
		}
		source, decErr := LoadSource(f, p)
		closeErr := f.Close()
		if decErr != nil || closeErr != nil {
			return nil, errors.Join(decErr, closeErr)
		}
		source.Path = p
		sources = append(sources, source)
	}
	return sources, nil
}
