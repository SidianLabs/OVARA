package action

import "testing"

// Canonicalize must never panic and must be deterministic —
// malformed input may error but must fail closed.
func FuzzCanonicalize(f *testing.F) {
	f.Add("http.request", "GET https://api.github.com/x")
	f.Add("shell.exec", "rm -rf /; cat /etc/passwd")
	f.Add("fs.delete", "/tmp/../etc/passwd")
	f.Add("weird.type", "anything")
	f.Add("http.request", "https://user:pw@host/")
	f.Add("net.egress", "https://2130706433/")
	f.Add("git.push", "refs/heads/main")
	f.Fuzz(func(t *testing.T, typ, res string) {
		a1, e1 := Canonicalize(typ, res)
		a2, e2 := Canonicalize(typ, res)
		if (e1 == nil) != (e2 == nil) || a1 != a2 {
			t.Fatalf("non-deterministic: (%v,%v) vs (%v,%v)", a1, e1, a2, e2)
		}
		if e1 == nil && a1.Type != TypeRawUnknown {
			// canonical form must be idempotent
			b, err := Canonicalize(string(a1.Type), a1.Resource)
			if err != nil {
				t.Fatalf("canonical form re-parse failed: %q → %q: %v",
					res, a1.Resource, err)
			}
			if b.Resource != a1.Resource || b.Type != a1.Type {
				t.Fatalf("non-idempotent: %q → %q → %q", res, a1.Resource, b.Resource)
			}
		}
	})
}
