package workspace

import (
	"bytes"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The file names in secretPatterns are the fast path. A secret under any
// other name is caught by what it says: after the copy every file in it is
// read, and one that holds a known key format is left out too. A false
// positive costs the agent a file it can ask for; a false negative hands
// it a key.

// scanLimit is how much of each file is read; scanBinaryProbe how much of
// it decides that a file is binary (a NUL byte), and is not read further.
const (
	scanLimit       = 2 << 20
	scanBinaryProbe = 8 << 10
)

// secretFinding names one kind of secret in a file's content.
type secretFinding struct {
	what string
	re   *regexp.Regexp
	// check, when set, must also accept the match (submatch 1 when the
	// expression has one, else the whole match)
	check func(string) bool
}

var secretContent = []secretFinding{
	{"a private key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`), nil},
	{"an AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), nil},
	{"an AWS secret key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})`), nil},
	{"a GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`), nil},
	{"a GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}`), nil},
	{"a Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`), nil},
	{"a Slack webhook", regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}`), nil},
	{"an npm auth token", regexp.MustCompile(`(?m)_auth(?:Token)?\s*=\s*["']?([^\s"']{16,})`), looksRandom},
	{"a .netrc password", regexp.MustCompile(`(?m)^\s*machine\s+\S+(?:\s+login\s+\S+)?\s+password\s+\S+`), nil},
	{"a URL with a password", regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@"']+:([^/\s@"']+)@[^\s/"']+`), looksRandom},
	{"a cloud service-account key", regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]*"private_key"|"private_key"[\s\S]*"type"\s*:\s*"service_account"`), nil},
	{"a cloud refresh token", regexp.MustCompile(`"refresh_token"\s*:\s*"([^"]{16,})"`), looksRandom},
	{"an Azure storage key", regexp.MustCompile(`AccountKey=([A-Za-z0-9+/=]{40,})`), nil},
	{"an Azure access token", regexp.MustCompile(`"accessToken"\s*:\s*"([^"]{40,})"`), looksRandom},
	{"a kubeconfig credential", regexp.MustCompile(`(?m)^\s*(?:token|client-key-data|password)\s*:\s*["']?([^\s"']{8,})`), nil},
	{"a key-like variable", regexp.MustCompile(`(?mi)^\s*(?:(?:export|const|let|var|val|final|static|private|public|protected|readonly|define)\s+)*(?:\$|this\.|self\.)?["']?[a-z0-9_.-]*(?:key|token|secret|passwd|password|pwd|credential|auth)[a-z0-9_.-]*["']?\s*(?::=|[=:]|=>)\s*["']?([A-Za-z0-9/+_\-.=~]{16,})`), looksRandom},
	// the same in a JSON, JS or PHP literal anywhere on a line
	{"a key-like field", regexp.MustCompile(`(?i)["'][a-z0-9_.-]*(?:key|token|secret|passwd|password|pwd|credential|auth)[a-z0-9_.-]*["']\s*(?:[:,]|=>)\s*["']([A-Za-z0-9/+_\-.=~]{16,})["']`), looksRandom},
	// a token written into a request: a curl line, a script, an HTTP file
	{"a bearer token", regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{16,}=*)`), looksRandom},
	{"an API key header", regexp.MustCompile(`(?i)\b(?:x-api-key|api-key|x-auth-token|private-token)["']?\s*[:=,]\s*["']?([A-Za-z0-9._\-]{16,})`), looksRandom},
}

// kubeconfig credentials count only in a kubeconfig
var kubeConfig = regexp.MustCompile(`(?m)^kind:\s*Config\s*$`)

// scanSecret reports what secret, if any, the start of b looks like it
// holds; "" for none.
func scanSecret(b []byte) string {
	for _, f := range secretContent {
		if f.what == "a kubeconfig credential" && !kubeConfig.Match(b) {
			continue
		}
		for _, m := range f.re.FindAllSubmatch(b, -1) {
			v := m[0]
			if len(m) > 1 && m[1] != nil {
				v = m[1]
			}
			if f.check == nil || f.check(string(v)) {
				return f.what
			}
		}
	}
	return ""
}

// looksRandom tells a generated value (a key, a token) from a name or a
// placeholder: long enough, digits among the letters (several of them, or
// both cases of letter), and enough different characters.
func looksRandom(v string) bool {
	v = strings.Trim(v, `"'`)
	if len(v) < 16 || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "<") {
		return false
	}
	var lower, upper, digits, hexOnly = 0, 0, 0, true
	freq := map[rune]float64{}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= 'A' && r <= 'Z':
			upper++
		}
		if !strings.ContainsRune("0123456789abcdef", r) {
			hexOnly = false
		}
		freq[r]++
	}
	if hexOnly && len(v) >= 32 {
		return true
	}
	if lower+upper == 0 || digits < 2 || !((lower > 0 && upper > 0) || digits*5 >= len(v)) {
		return false
	}
	var h float64
	n := float64(len([]rune(v)))
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h >= 3.3
}

// scanFile reads up to scanLimit of a regular file and reports what secret
// it looks like it holds ("" for none, or for a binary file).
func scanFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, scanLimit))
	if err != nil {
		return ""
	}
	if bytes.IndexByte(b[:min(len(b), scanBinaryProbe)], 0) >= 0 {
		return ""
	}
	return scanSecret(b)
}

// scanSecrets walks the copy (not .git) and returns each file whose
// content looks like a secret, with what it looks like.
func scanSecrets(dir string) map[string]string {
	found := map[string]string{}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error { // best effort: an unreadable file is not scanned
		if err != nil {
			return nil //nolint:nilerr // skipped, not fatal
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if what := scanFile(p); what != "" {
			rel, _ := filepath.Rel(dir, p)
			found[filepath.ToSlash(rel)] = what
		}
		return nil
	})
	return found
}

// urlCredentials is the user[:password]@ part of a URL.
var urlCredentials = regexp.MustCompile(`([a-z][a-z0-9+.-]*://)[^/\s@]+@`)

// scrubGitConfig removes credentials embedded in URLs (remotes, pushurl,
// insteadOf) from the copy's .git/config. It reports whether it changed it.
func scrubGitConfig(dir string) (bool, error) {
	p := filepath.Join(dir, ".git", "config")
	b, err := os.ReadFile(p)
	if err != nil {
		return false, err
	}
	out := urlCredentials.ReplaceAll(b, []byte("$1"))
	if bytes.Equal(out, b) {
		return false, nil
	}
	return true, os.WriteFile(p, out, 0o600)
}
