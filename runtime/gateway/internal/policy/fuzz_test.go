package policy

import (
	"testing"
	"time"
)

// Policy patterns and resources are attacker-influenced strings. Matching
// must never panic and must terminate promptly (no exponential glob
// backtracking an agent could use to stall every decision).
func FuzzMatchCanonicalResource(f *testing.F) {
	f.Add("GET https://github.com/*", "GET https://github.com/a/b")
	f.Add("POST *git-upload-pack", "POST https://x/y/git-upload-pack")
	f.Add("*://*.example.com/*", "https://a.example.com/")
	f.Add("*a*a*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pattern, resource string) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = MatchCanonicalResource(pattern, resource)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("matching did not terminate: pattern=%q resource=%q", pattern, resource)
		}
	})
}
