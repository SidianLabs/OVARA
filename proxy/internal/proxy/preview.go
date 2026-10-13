package proxy

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
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
	maxPeekBodySize = 1 << 20 // do not even look at bodies larger than this
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

// requestContext builds the approver-facing preview for r. It may read a
// bounded prefix of the body and puts it back, so the upstream still receives
// the whole stream. It never blocks on a body of unknown length.
func requestContext(r *http.Request) map[string]string {
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
	ct := r.Header.Get("Content-Type")
	if ct != "" && (r.ContentLength != 0) {
		out["content_type"] = truncate(ct, 80)
	}
	switch {
	case r.ContentLength > 0:
		out["body_bytes"] = strconv.FormatInt(r.ContentLength, 10)
	case r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody:
		out["body_bytes"] = "unknown (streamed)"
	}
	// Preview only text, only when the size is known and modest: a known
	// length means reading min(n, length) bytes cannot stall on a client that
	// is waiting for our answer.
	if r.ContentLength > 0 && r.ContentLength <= maxPeekBodySize && isTextual(ct) && r.Body != nil {
		n := int(minInt64(r.ContentLength, maxPreviewBody))
		buf := make([]byte, n)
		got, _ := io.ReadFull(r.Body, buf)
		rest := r.Body
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf[:got]), rest), rest}
		if got > 0 && utf8.Valid(buf[:got]) {
			rp, n := redactPreviewCount(string(buf[:got]))
			masked += n
			p := truncate(rp, maxPreviewBody)
			if r.ContentLength > int64(got) {
				p += " …"
			}
			out["body_preview"] = p
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

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
