package action

import (
	"fmt"
	"path/filepath"
	"strings"
)

// canonPath normalizes a filesystem resource inside the sandbox's
// mount view (spec §3.3): absolute form, symlinks resolved by the
// caller's view (here: lexical only — runtime hook resolves symlinks
// at enforcement time), traversal collapsed or rejected.
//
// Canonical form: absolute path. `~` and `$VAR` expansions are NOT
// performed by the canonicalizer (the agent's env is untrusted);
// resources containing them are rejected — the seam resolves them
// against the sandbox's known env instead.
func canonPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("action: empty path")
	}
	if len(raw) > 4096 { // PATH_MAX — unbounded resources bloat audit
		return "", fmt.Errorf("action: path over 4096 bytes")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", fmt.Errorf("action: control byte in path")
		}
	}
	if strings.HasPrefix(raw, "~") || strings.Contains(raw, "$") {
		return "", fmt.Errorf("action: unexpanded env/home in path %q — must be concrete", raw)
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("action: relative path %q not allowed (must be absolute)", raw)
	}
	clean := filepath.Clean(raw)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("action: traversal survived clean in %q", raw)
	}
	if !isCanonicalForm(clean) {
		// leading/trailing whitespace can't survive re-canonicalization
		// (input is trimmed) — a non-idempotent form is not canonical
		return "", fmt.Errorf("action: path %q not canonicalizable", raw)
	}
	return clean, nil
}
