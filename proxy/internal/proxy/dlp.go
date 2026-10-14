package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"ovara.proxy/internal/config"
)

// The content rule. A request a rule allowed can still carry out what
// should never leave: a private key, a cloud or API key, a JWT, a card
// number, or whatever pattern the operator names. Before such a request
// goes out, a person is asked (content.sensitive on
// "content:<kinds> <METHOD> <url>") and sees what kinds were found and
// how many, never the values. The detectors are high-confidence shapes:
// a prose that happens to look like a key is the price of catching one.

const actionContent = "content.sensitive"

type dlpDetector struct {
	name  string
	re    *regexp.Regexp
	check func(match string) bool // an extra test on a match, nil for none
}

var builtinDetectors = []dlpDetector{
	{name: "private_key", re: regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----`)},
	{name: "cloud_key", re: regexp.MustCompile(`\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b`)},
	{name: "api_token", re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})`)},
	{name: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{name: "card_number", re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), check: luhn},
}

// luhn reports whether the digits of s (separators dropped) pass the Luhn
// check, as card numbers do.
func luhn(s string) bool {
	sum, alt, n := 0, false, 0
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
		n++
	}
	return n >= 13 && n <= 19 && sum%10 == 0
}

type dlpScanner struct {
	detectors  []dlpDetector
	exempt     []string
	modelCalls bool // scan the model API's requests too
}

// SetDLP turns the content rule on or off (default on), with the
// operator's own patterns (config.DLP.Validate is the caller's), the URL
// globs never scanned, and whether the model API's requests are scanned.
func (s *Server) SetDLP(on bool, custom []config.DLPPattern, exempt []string, modelCalls bool) {
	if !on {
		s.dlp = nil
		return
	}
	d := &dlpScanner{detectors: append([]dlpDetector(nil), builtinDetectors...), exempt: exempt, modelCalls: modelCalls}
	for _, p := range custom {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue // refused at config load; never reached
		}
		d.detectors = append(d.detectors, dlpDetector{name: p.Name, re: re})
	}
	s.dlp = d
}

// sensitiveContent scans the query and body of r for the kinds the
// detectors know. It returns the kinds found, sorted and comma-joined (the
// resource's form), and what the person is shown ("private_key ×1,
// api_token ×2"); "" when nothing was found or the rule does not apply.
func (s *Server) sensitiveContent(r *http.Request, hb *heldBody) (kinds, shown string) {
	d := s.dlp
	if d == nil || isUploadPackPost(r) {
		return "", ""
	}
	if !d.modelCalls && s.isModelHost(normalizeHost(r.URL.Hostname())) {
		return "", ""
	}
	if len(d.exempt) > 0 && matchAny(d.exempt, matchURL(r)) {
		return "", ""
	}
	var texts []string
	if q := r.URL.RawQuery; q != "" {
		texts = append(texts, q)
	}
	if hb != nil && hb.size > 0 {
		if data, ok := s.readableBody(r, hb); ok {
			texts = append(texts, string(data))
		}
	}
	if len(texts) == 0 {
		return "", ""
	}
	counts := map[string]int{}
	for _, det := range d.detectors {
		for _, t := range texts {
			for _, m := range det.re.FindAllString(t, 64) {
				if det.check == nil || det.check(m) {
					counts[det.name]++
				}
			}
		}
	}
	if len(counts) == 0 {
		return "", ""
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s ×%d", n, counts[n]))
	}
	return strings.Join(names, ","), strings.Join(parts, ", ")
}
