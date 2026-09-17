package execution

import "regexp"

// maxResponseBodyBytes bounds HTTP response bodies read by the CI/GitHub
// executors so a hostile or broken endpoint cannot exhaust memory.
const maxResponseBodyBytes = 10 << 20 // 10 MiB

// secretPatterns matches common secret material that can leak into captured
// stdout/stderr/error strings: Authorization headers, Bearer tokens, and
// key=value style credentials. Applied before execution output is stored or
// returned so secrets are not persisted in the execution store, audit
// exports, or API responses.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)authorization:\s*\S+`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`),
	regexp.MustCompile(`(?i)(token|api[_-]?key|secret|password|passwd|credential)(=|:)\s*\S+`),
}

// Redact replaces common secret patterns in s with a fixed marker. Output is
// capped patterns only — it is a best-effort scrub, not a guarantee.
func Redact(s string) string {
	if s == "" {
		return s
	}
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
