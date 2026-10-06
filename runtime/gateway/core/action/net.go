package action

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// canonNet normalizes a network resource to
// `scheme://host[:port]/path-prefix`. Rules (spec §3.1):
//   - scheme+host lower-cased; default port stripped; explicit
//     non-default port retained.
//   - userinfo is a hard reject (v1 corpus: it was evaluatable — v2
//     treats credentials-in-URL as malformed input).
//   - host must be a valid DNS name or IP literal — IDNA applied via
//     url.Parse + explicit host extraction.
//   - missing scheme is a hard reject (ambiguous).
func canonNet(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("action: empty net resource")
	}
	if len(raw) > 8192 {
		return "", fmt.Errorf("action: net resource over 8192 bytes")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", fmt.Errorf("action: control byte in net resource")
		}
	}
	// strip a leading METHOD token (v1 corpus used "GET https://...")
	if i := strings.IndexByte(raw, ' '); i > 0 {
		maybe := raw[:i]
		if strings.ToUpper(maybe) == maybe && len(maybe) <= 10 {
			raw = strings.TrimSpace(raw[i+1:])
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("action: bad URL %q: %w", raw, err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("action: net resource %q lacks scheme", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("action: userinfo in resource %q rejected", raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("action: empty host in %q", raw)
	}
	if !validHost(host) {
		return "", fmt.Errorf("action: malformed host %q", host)
	}
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	out := scheme + "://"
	if strings.Contains(host, ":") {
		out += "[" + host + "]" // IPv6 literal needs brackets to re-parse
	} else {
		out += host
	}
	if port != "" && port != defaultPort(scheme) {
		out += ":" + port
	}
	// path: keep the raw path prefix shape for prefix matching —
	// canonicalize by cleaning ../ and duplicate slashes. Decoded
	// control bytes (%00, %0a…) can't survive re-parse — reject.
	for i := 0; i < len(u.Path); i++ {
		if u.Path[i] < 0x20 || u.Path[i] == 0x7f {
			return "", fmt.Errorf("action: control byte in path %q", u.Path)
		}
	}
	p := cleanURLPath(u.Path)
	if p != "/" {
		out += p
	}
	if !isCanonicalForm(out) {
		return "", fmt.Errorf("action: net resource %q not canonicalizable", raw)
	}
	return out, nil
}

func defaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ftp":
		return "21"
	}
	return ""
}

func validHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	// Numeric-ish hosts that aren't literal IPs are ambiguous spellings
	// (decimal-int, hex, octal, short dotted) — DNS resolves them via
	// inet_aton semantics, e.g. "2130706433" == 169.254.169.254. The
	// canonical form only permits literal IPs; anything else numeric is
	// a deny-bypass vector against IP-keyed rules.
	if looksNumericish(host) {
		return false
	}
	if len(host) > 253 || host == "localhost" {
		return host == "localhost" // localhost is a valid literal host
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
			if i == 0 && c == '-' {
				return false
			}
		}
	}
	return true
}

func cleanURLPath(p string) string {
	if p == "" {
		return "/"
	}
	// collapse /../ and /./ literally — no filesystem semantics here,
	// just string normalization for stable prefix matching
	segs := strings.Split(p, "/")
	var stack []string
	for _, s := range segs {
		switch s {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, s)
		}
	}
	return "/" + strings.Join(stack, "/")
}

func looksNumericish(host string) bool {
	sawDigit := false
	for _, c := range host {
		switch {
		case c >= '0' && c <= '9':
			sawDigit = true
		case c == '.' || c == 'x' || c == 'X' ||
			(c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return sawDigit
}
