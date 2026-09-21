package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

type filePolicy struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// fileRule is kept as an ALIAS (not a second struct) so validator and
// test code compile unchanged — there is exactly one canonical rule
// representation: Rule.
type fileRule = Rule

func LoadStoreFromFile(filePath string, versionHint string) (*Store, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	store, err := ParseStore(data, versionHint)
	if err != nil {
		return nil, err
	}
	store.SetFilePath(filePath)
	return store, nil
}

// ParseStore is the ONE canonical policy parser. Every load path —
// file, candidate, simulate, distribution — must go through it so rule
// semantics are identical everywhere. Unknown fields are rejected so a
// typo'd key can never silently widen a rule.
func ParseStore(data []byte, versionHint string) (*Store, error) {
	fp, err := parseFilePolicyStrict(data)
	if err != nil {
		return nil, err
	}

	version := fp.Version
	if version == "" {
		version = versionHint
	}
	if version == "" {
		version = "v1-default"
	}

	return &Store{version: version, rules: fp.Rules}, nil
}

// parseFilePolicyStrict decodes a policy file with full strictness:
//   - unknown fields rejected (DisallowUnknownFields)
//   - duplicate keys rejected — `{"resource":"x","resource":""}` must not
//     silently last-win a scoped rule into a global allow
//   - `null` for a string rule field rejected — JSON null decodes to ""
//     which would widen "resource" to match-everything
//
// Decoding happens per-rule over RawMessage so the token scan can see
// duplicates and nulls that encoding/json would otherwise erase.
func parseFilePolicyStrict(data []byte) (*filePolicy, error) {
	var raw struct {
		Version string            `json:"version"`
		Rules   []json.RawMessage `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}
	fp := &filePolicy{Version: raw.Version}
	for i, rm := range raw.Rules {
		if err := scanRuleStrict(rm, i); err != nil {
			return nil, err
		}
		var r Rule
		dec := json.NewDecoder(bytes.NewReader(rm))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("failed to parse policy JSON: rule %d: %w", i, err)
		}
		fp.Rules = append(fp.Rules, r)
	}
	return fp, nil
}

// scanRuleStrict token-scans one rule object for duplicate keys and for
// `null` on fields where null silently becomes "" (widening resource) or
// erases intent. Keys inside nested objects (conditions) are ignored —
// conditions is operator metadata, never evaluated for authorization.
func scanRuleStrict(raw json.RawMessage, idx int) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("failed to parse policy JSON: rule %d: %w", idx, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("failed to parse policy JSON: rule %d must be an object", idx)
	}
	seen := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("failed to parse policy JSON: rule %d: %w", idx, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("failed to parse policy JSON: rule %d: non-string key", idx)
		}
		if seen[key] {
			return fmt.Errorf("failed to parse policy JSON: rule %d: duplicate key %q — refusing to guess which wins", idx, key)
		}
		seen[key] = true
		valTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("failed to parse policy JSON: rule %d: %w", idx, err)
		}
		if valTok == nil && key == "resource" {
			return fmt.Errorf("failed to parse policy JSON: rule %d: \"resource\": null is not allowed — it would widen the rule to match every resource; omit the field or use \"*\"", idx)
		}
		// Skip nested containers' contents: a '{' or '[' opener means the
		// rest is consumed structurally below.
		if d, ok := valTok.(json.Delim); ok && (d == '{' || d == '[') {
			depth := 1
			for depth > 0 {
				t, err := dec.Token()
				if err != nil {
					return fmt.Errorf("failed to parse policy JSON: rule %d: %w", idx, err)
				}
				if dd, ok := t.(json.Delim); ok {
					switch dd {
					case '{', '[':
						depth++
					case '}', ']':
						depth--
					}
				}
			}
		}
	}
	return nil
}