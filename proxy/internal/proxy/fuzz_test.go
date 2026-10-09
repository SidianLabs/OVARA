package proxy

import (
	"testing"
)

// parseRefUpdates reads an agent-controlled request body. Whatever it is
// fed, it must not panic or hang. (Whether "incomplete" parses are treated
// as a deny is the caller's job and is covered by the git gate tests.)
func FuzzParseRefUpdates(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("0000"))
	f.Add([]byte("0067" + "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/main\x00 report-status"))
	f.Add([]byte("zzzz not pkt-line"))
	f.Add([]byte("ffff"))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = parseRefUpdates(body)
	})
}

func FuzzNormalizeHost(f *testing.F) {
	for _, s := range []string{"", "a.b", "A.B.", "[::1]:443", "host:99999", "..", "x:y:z", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a := normalizeHost(s)
		// Idempotent: normalizing twice must not change the result, or two
		// code paths could disagree about whether a host is "sensitive".
		if b := normalizeHost(a); b != a {
			t.Fatalf("normalizeHost not idempotent: %q -> %q -> %q", s, a, b)
		}
	})
}
