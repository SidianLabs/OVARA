package proxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// What a human approver can see about a request beyond its URL. The URL path
// is policy's business; the QUERY and the BODY are where data actually
// leaves, and they are deliberately kept out of the policy resource string and
// out of receipts (they can hold secrets). So they are shown, redacted and
// bounded, only to the person being asked, and recorded nowhere else.
const (
	maxPreviewQuery = 300
	maxPreviewBody  = 400
)

var secretShapes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`\b(ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{16,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{16,}`),
	// key=value / "key":"value" for names that mean "secret"
	regexp.MustCompile(`(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|auth|credential|private[_-]?key)["']?\s*[:=]\s*["']?)[^"'&\s,}]+`),
	// a long unbroken run of base64/hex is more likely a key than prose
	regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`),
}

// redactPreview hides the VALUE of anything that looks like a credential or an
// encoded blob, but never hides the fact that one is there: each is replaced
// by a visible marker with its size. A silent "[redacted]" would read as
// "Ovara took care of it" when it means "something secret-shaped is being
// sent", which is exactly what the approver must notice.
func redactPreview(s string) string {
	out, _ := redactPreviewCount(s)
	return out
}

// redactPreviewCount is redactPreview plus how many values it masked.
func redactPreviewCount(s string) (string, int) {
	n := 0
	for i, re := range secretShapes {
		switch i {
		case 6: // key=value for a secret-sounding key: keep the key
			s = re.ReplaceAllStringFunc(s, func(m string) string {
				sub := re.FindStringSubmatch(m)
				n++
				return sub[1] + fmt.Sprintf("[⚠ secret-named value, %d chars]", len(m)-len(sub[1]))
			})
		case 7:
			s = re.ReplaceAllStringFunc(s, func(m string) string {
				n++
				return fmt.Sprintf("[⚠ opaque encoded blob, %d chars]", len(m))
			})
		default:
			s = re.ReplaceAllStringFunc(s, func(m string) string {
				n++
				return fmt.Sprintf("[⚠ credential-shaped value, %d chars]", len(m))
			})
		}
	}
	return s, n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// never cut a UTF-8 sequence in half
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func isTextual(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mt, "text/") || strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml") ||
		mt == "application/json" || mt == "application/x-www-form-urlencoded" || mt == "application/xml" ||
		mt == "application/graphql"
}

// requestContext builds the approver-facing preview for r, whose body (if
// any) has already been held in full as hb. The gateway keeps at most 12
// keys; this sets at most 9: query, method_override, headers, content_type,
// body_bytes, body_sha256, body_preview, body_note, warning.
func requestContext(r *http.Request, hb *heldBody) map[string]string {
	out := map[string]string{}
	masked := 0
	if q := r.URL.RawQuery; q != "" {
		rq, n := redactPreviewCount(q)
		masked += n
		out["query"] = truncate(rq, maxPreviewQuery)
	}
	for _, h := range methodOverrideHeaders {
		if v := r.Header.Get(h); v != "" {
			out["method_override"] = h + ": " + truncate(v, 20) + " (not forwarded)"
			break
		}
	}
	if h, n := headerSummary(r.Header); h != "" {
		out["headers"] = h
		masked += n
	}
	if hb != nil && hb.size > 0 {
		ct := r.Header.Get("Content-Type")
		if ct != "" {
			out["content_type"] = truncate(ct, 80)
		}
		out["body_bytes"] = strconv.FormatInt(hb.size, 10)
		// The exact bytes that will be sent if this is allowed: the body is
		// held, so nothing can be added to it after the answer.
		out["body_sha256"] = hb.sha256Hex()
		preview, note, n := bodyPreview(hb, ct, r.Header.Values("Content-Encoding"))
		masked += n
		if preview != "" {
			out["body_preview"] = preview
		}
		if note != "" {
			out["body_note"] = note
		}
	}
	if masked > 0 {
		out["warning"] = fmt.Sprintf("this request carries %d credential-shaped or encoded value(s), masked below: data in this form may be leaving", masked)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// maxPreviewInflate bounds how much of a gzip body is decompressed for the
// preview, so a small compressed bomb costs at most this much.
const maxPreviewInflate = 64 << 10

// bodyPreview returns a redacted text preview of a held body, a note saying
// what the person is (and is not) being shown, and how many values were
// masked. A body that cannot be shown always gets a note saying so: silence
// would read as "nothing to see".
func bodyPreview(hb *heldBody, ct string, encodings []string) (preview, note string, masked int) {
	size := hb.size
	kind := "undeclared type"
	if mt, _, err := mime.ParseMediaType(ct); err == nil {
		kind = mt
	} else if ct != "" {
		kind = truncate(ct, 60)
	}
	var enc []string
	for _, v := range encodings {
		for _, tok := range strings.Split(v, ",") {
			if t := strings.ToLower(strings.TrimSpace(tok)); t != "" && t != "identity" {
				enc = append(enc, t)
			}
		}
	}
	gz := len(enc) == 1 && (enc[0] == encGzip || enc[0] == encXGzip)
	if len(enc) > 0 && !gz {
		return "", fmt.Sprintf("contents not shown: %d bytes of %s, encoded %s", size, kind, truncate(strings.Join(enc, ", "), 40)), 0
	}
	if !isTextual(ct) {
		return "", fmt.Sprintf("contents not shown: %d bytes of %s", size, kind), 0
	}
	data, total, more := hb.head, size, false
	if gz {
		zr, err := gzip.NewReader(hb.reader())
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(zr, maxPreviewInflate+1))
		}
		if err != nil {
			return "", fmt.Sprintf("contents not shown: %d bytes of gzip that does not decompress", size), 0
		}
		more = len(data) > maxPreviewInflate
		total = int64(len(data))
	}
	p := data[:min(len(data), maxPreviewBody)]
	// Cut at a whole character: a multi-byte one split at the edge is not
	// "invalid text".
	for i := 0; i < utf8.UTFMax && len(p) > 0 && !utf8.Valid(p) && len(p) < len(data); i++ {
		p = p[:len(p)-1]
	}
	if len(p) == 0 || !utf8.Valid(p) {
		return "", fmt.Sprintf("contents not shown: %d bytes of %s that are not valid UTF-8 text", size, kind), 0
	}
	rp, masked := redactPreviewCount(string(p))
	preview = truncate(rp, maxPreviewBody)
	var notes []string
	if int64(len(p)) < total || more {
		preview += " …"
		of := strconv.FormatInt(total, 10)
		if more {
			of = "more than " + of
		}
		notes = append(notes, fmt.Sprintf("showing first %d of %s bytes", len(p), of))
	}
	if gz {
		notes = append(notes, fmt.Sprintf("(gzip, %d bytes sent, decompressed for preview)", size))
	}
	return preview, strings.Join(notes, " "), masked
}

// headerSummary lists the request headers a person should see: everything
// but the standard ones, the hop-by-hop ones and the proxy's own credential.
// A credential's value is never shown, only its size. It returns the summary
// and how many values in it were masked as secret-shaped.
func headerSummary(h http.Header) (string, int) {
	names := make([]string, 0, len(h))
	total := 0
	for k, vv := range h {
		ck := http.CanonicalHeaderKey(k)
		if standardHeaders[ck] || notForwarded(ck) {
			continue
		}
		names = append(names, k)
		for _, v := range vv {
			total += len(k) + len(v)
		}
	}
	if len(names) == 0 {
		return "", 0
	}
	sort.Strings(names)
	masked := 0
	var b strings.Builder
	fmt.Fprintf(&b, "%d header(s), %d bytes: ", len(names), total)
	for i, k := range names {
		v := strings.Join(h[k], ", ")
		if isCredentialHeader(k) {
			v = fmt.Sprintf("[⚠ credential, %d chars]", len(v))
		} else {
			var n int
			v, n = redactPreviewCount(v)
			masked += n
			v = truncate(v, 60)
		}
		entry := k + ": " + v
		if b.Len()+len(entry) > maxHeaderSummary {
			fmt.Fprintf(&b, "… (+%d more)", len(names)-i)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(entry)
	}
	return b.String(), masked
}

// maxHeaderSummary keeps the header list inside the gateway's 600-character
// limit for one context value.
const maxHeaderSummary = 560

// isCredentialHeader reports whether a header's value is a credential that
// must not be shown, only counted.
func isCredentialHeader(name string) bool {
	for _, c := range credentialHeaders {
		if strings.EqualFold(name, c) {
			return true
		}
	}
	n := strings.ToLower(name)
	for _, w := range []string{"auth", "token", "secret", "api-key", "apikey", "cookie", "session", "password", "signature"} {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}
