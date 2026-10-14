package policy

import (
	"fmt"
	"os"
	"strings"

	"ovara.runtime.gateway/pkg/baseline"
)

// An organisation's baseline is a policy document the project's policy
// may only narrow (the evaluator layers them). It loads like any policy
// file; when a public key is pinned, the bytes must carry a signature in
// <file>.sig, so a project cannot swap the baseline for a looser one.

// LoadBaseline reads the baseline at path. pubKeyHex, when not empty, is
// the Ed25519 public key (hex) that the detached signature in path+".sig"
// must verify under; a missing or wrong signature refuses the file.
func LoadBaseline(path, pubKeyHex, versionHint string) (*Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator's own file, named in config.json
	if err != nil {
		return nil, fmt.Errorf("policy baseline: %w", err)
	}
	if pubKeyHex != "" {
		sig, err := os.ReadFile(baseline.SigPath(path)) //nolint:gosec // next to the operator's own file
		if err != nil {
			return nil, fmt.Errorf("policy baseline %s: no signature to verify (%s): %w", path, baseline.SigPath(path), err)
		}
		if err := baseline.Verify(data, strings.TrimSpace(string(sig)), pubKeyHex); err != nil {
			return nil, fmt.Errorf("policy baseline %s: %w", path, err)
		}
	}
	store, err := ParseStore(data, versionHint)
	if err != nil {
		return nil, fmt.Errorf("policy baseline %s: %w", path, err)
	}
	store.SetFilePath(path)
	return store, nil
}
