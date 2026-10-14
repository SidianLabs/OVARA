package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"ovara.runtime.gateway/pkg/baseline"
)

// auditBaseline checks the organisation's baseline named in config.json:
// it is there, it is a policy, and, with a key pinned, its signature
// verifies; without a key, a warning: whoever can write the file can
// loosen it.
func auditBaseline(dir, file, pubHex string) []check {
	path := inDir(dir, file)
	data, err := os.ReadFile(path) //nolint:gosec // the operator's own file, named in config.json
	if err != nil {
		return []check{{"policy baseline", checkFail, "policy_baseline_file " + path + " cannot be read: " + err.Error()}}
	}
	var doc struct {
		Version string           `json:"version"`
		Rules   []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return []check{{"policy baseline", checkFail, path + " is not valid JSON: " + err.Error()}}
	}
	what := fmt.Sprintf("%s: %d rule(s) (%s) that the project policy may only narrow", path, len(doc.Rules), doc.Version)
	if pubHex == "" {
		return []check{{"policy baseline", checkWarn, what + "; unsigned: whoever can write the file can loosen it (ovara policy baseline keygen, sign; pin policy_baseline_pubkey)"}}
	}
	sig, err := os.ReadFile(baseline.SigPath(path)) //nolint:gosec // next to the operator's own file
	if err != nil {
		return []check{{"policy baseline", checkFail, what + "; a key is pinned but there is no " + baseline.SigPath(path) + ": the gateway will refuse to start"}}
	}
	if err := baseline.Verify(data, strings.TrimSpace(string(sig)), pubHex); err != nil {
		return []check{{"policy baseline", checkFail, what + "; " + err.Error() + ": the gateway will refuse to start"}}
	}
	return []check{{"policy baseline", checkPass, what + "; signature verifies under policy_baseline_pubkey"}}
}
