// TEMPORARY AUDIT HARNESS (P1 gate) — exercises tamper classes against
// verifyChain. Not a regression suite: it documents what the receipt
// chain does and does NOT prove today. Delete or promote after P1.
package receipts

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"os"
	"path/filepath"
	"testing"
)

func mkChain(t *testing.T, dir, name string, n int) (string, ed25519.PublicKey) {
	t.Helper()
	path := filepath.Join(dir, name)
	keyF := filepath.Join(dir, name+".key")
	pubF := filepath.Join(dir, name+".pub")
	c, err := LoadOrCreate(path, keyF, pubF)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := c.Record("GET", "https://x/"+string(rune('a'+i)), "allow", 200, ""); err != nil {
			t.Fatal(err)
		}
	}
	pubBytes, _ := os.ReadFile(pubF)
	pub, _ := hex.DecodeString(strings.TrimSpace(string(pubBytes)))
	return path, ed25519.PublicKey(pub)
}

func tamperLines(t *testing.T, path string, fn func(lines []string) []string) string {
	data, _ := os.ReadFile(path)
	var lines []string
	for _, l := range splitLines(string(data)) {
		lines = append(lines, l)
	}
	out := filepath.Join(filepath.Dir(path), "tampered.jsonl")
	os.WriteFile(out, []byte(joinLines(fn(lines))), 0644)
	return out
}
func splitLines(s string) []string {
	var o []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			o = append(o, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		o = append(o, cur)
	}
	return o
}
func joinLines(ls []string) string {
	s := ""
	for _, l := range ls {
		s += l + "\n"
	}
	return s
}

func TestAudit_TamperMatrix(t *testing.T) {
	dir := t.TempDir()
	path, pub := mkChain(t, dir, "r.jsonl", 5)

	check := func(name, p string, pk ed25519.PublicKey) {
		r := VerifyFile(p, pk)
		status := "DETECTED"
		if r.Valid {
			status = "UNDETECTED"
		}
		t.Logf("%-38s -> %s (total=%d reason=%s)", name, status, r.Total, r.Reason)
	}

	check("baseline", path, pub)
	check("delete first", tamperLines(t, path, func(l []string) []string { return l[1:] }), pub)
	check("delete middle", tamperLines(t, path, func(l []string) []string { return append(l[:2], l[3:]...) }), pub)
	check("delete last (tail truncate)", tamperLines(t, path, func(l []string) []string { return l[:4] }), pub)
	check("reorder", tamperLines(t, path, func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }), pub)
	check("duplicate middle", tamperLines(t, path, func(l []string) []string { return append(l[:2], append([]string{l[2]}, l[2:]...)...) }), pub)

	// whole-chain rewrite with attacker key
	p2, pub2 := mkChain(t, dir, "rewritten.jsonl", 5)
	check("whole-chain rewrite + attacker key", p2, pub2)
	check("whole-chain rewrite + original key", p2, pub)

	// restore old snapshot: truncate to first 3, then append continues?
	check("truncate head kept", tamperLines(t, path, func(l []string) []string { return l[:3] }), pub)
}
