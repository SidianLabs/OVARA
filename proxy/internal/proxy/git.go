package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// The gzip content codings (RFC 9110 lists "x-gzip" as an alias).
const (
	encGzip  = "gzip"
	encXGzip = "x-gzip"
)

// gitBodyPeek is the max bytes of a receive-pack body parsed for ref names.
// Ref-update header lines live at the start of the body; pack data follows
// the flush pkt (0000) and is never inspected.
const gitBodyPeek = 1 << 20 // 1MB

// RefUpdate is one ref update parsed from a git-receive-pack request body.
type RefUpdate struct {
	Ref    string // e.g. refs/heads/main
	OldSHA string
	NewSHA string
	Delete bool // NewSHA is all zeros (branch/tag delete)
}

// looksLikePush reports whether r is shaped like a git smart-HTTP push. The
// test is deliberately loose (any POST whose path mentions git-receive-pack,
// whatever its Content-Type or trailing characters): a push the gate does
// not recognise loses its ref names, and with them every ref-level rule.
func looksLikePush(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL != nil &&
		strings.Contains(strings.ToLower(r.URL.EscapedPath()), "git-receive-pack")
}

// parseRefUpdates extracts ref updates from the pkt-line header of a
// receive-pack body. Parsing stops at the flush pkt (0000) that precedes
// the pack data; complete reports whether that flush was seen. Malformed
// input yields whatever refs parsed before the error (possibly none); it
// never panics.
func parseRefUpdates(body []byte) (refs []RefUpdate, complete bool) {
	br := bufio.NewReader(bytes.NewReader(body))
	for {
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(br, hdr); err != nil {
			break
		}
		n, err := strconv.ParseUint(string(hdr), 16, 32)
		if err != nil {
			break
		}
		if n == 0 { // flush pkt: end of ref header, pack data follows
			return refs, true
		}
		if n < 4 || n > gitBodyPeek {
			break
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(br, payload); err != nil {
			break
		}
		line := strings.TrimRight(string(payload), "\n")
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i] // first line carries capabilities after NUL
		}
		f := strings.Fields(line)
		if len(f) < 3 || !strings.HasPrefix(f[2], "refs/") {
			continue
		}
		refs = append(refs, RefUpdate{
			OldSHA: f[0],
			NewSHA: f[1],
			Ref:    f[2],
			Delete: strings.Trim(f[1], "0") == "",
		})
	}
	return refs, false
}

// Markers the gateway's resource grammar accepts in place of a ref list
// (runtime/gateway/internal/policy isRefList). Anything else after the URL
// makes the resource unparseable, and an unparseable resource matches no rule
// but the catch-all: a deny on refs/heads/main would quietly stop applying.
const (
	pushUnparsed  = " git-receive-pack"
	pushTruncated = " git-receive-pack(truncated)"
)

// gitResourceSuffix returns " refs/a,refs/b" for appending to the policy
// resource string, a marker for a push whose refs cannot be listed, or ""
// for a request that is not a push. hb is the request's held body.
func (s *Server) gitResourceSuffix(r *http.Request, hb *heldBody) string {
	if !s.gitGate || !looksLikePush(r) {
		return ""
	}
	if hb == nil || encodedValue(r.Header.Values("Content-Encoding")) != "" {
		return pushUnparsed
	}
	refs, complete := parseRefUpdates(hb.head)
	if !complete && hb.size > int64(len(hb.head)) {
		// Ref header ran past the 1MB buffer without a flush pkt: we cannot
		// see all the refs being pushed — flag it honestly rather than
		// evaluate a partial push.
		return pushTruncated
	}
	if !complete || len(refs) == 0 {
		return pushUnparsed // a push we couldn't parse: still flag it
	}
	var b strings.Builder
	b.WriteByte(' ')
	for i, u := range refs {
		if !gatewayRefChars(u.Ref) {
			// The gateway would refuse to parse this ref name; flag the
			// push as unparsed instead of handing it an unmatchable string.
			return pushUnparsed
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(u.Ref)
		if u.Delete {
			b.WriteString("(delete)")
		}
	}
	return b.String()
}

// gatewayRefChars mirrors the ref names the gateway's grammar accepts.
func gatewayRefChars(ref string) bool {
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '/' || c == '.' || c == '_' || c == '-' || c == '~') {
			return false
		}
	}
	return strings.HasPrefix(ref, "refs/")
}

// git clone/fetch is a POST, so policy allows POSTs to git-upload-pack on
// trusted git hosts as "reading". That allow only holds for what git really
// sends there: a small pkt-line negotiation of object ids. Anything else
// posted to such a path is data leaving under a read's label.

// isUploadPackPost reports whether r is a POST aimed at git-upload-pack.
func isUploadPackPost(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		strings.Contains(strings.ToLower(r.URL.EscapedPath()), "git-upload-pack")
}

// uploadPackRefusal returns "not_git_upload_pack" unless r is a genuine
// smart-HTTP upload-pack request no larger than limit: the final path
// segment, the content type and a pkt-line body that only negotiates.
func uploadPackRefusal(r *http.Request, hb *heldBody, limit int64) string {
	const no = "not_git_upload_pack"
	// The escaped path, so ".../x%2Fgit-upload-pack" is not a final segment.
	if !strings.HasSuffix(r.URL.EscapedPath(), "/git-upload-pack") {
		return no
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mt, "application/x-git-upload-pack-request") {
		return no
	}
	if hb == nil || hb.size > limit {
		return no
	}
	var body io.Reader = hb.reader()
	switch enc := strings.ToLower(encodedValue(r.Header.Values("Content-Encoding"))); enc {
	case "":
	case encGzip, encXGzip:
		// git gzips negotiations over 1KB. Decompressed size is bounded by
		// the same limit, so a small bomb cannot balloon here.
		zr, err := gzip.NewReader(body)
		if err != nil {
			return no
		}
		body = zr
	default:
		return no
	}
	b, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil || int64(len(b)) > limit || !validUploadPackRequest(b) {
		return no
	}
	return ""
}

// Words an upload-pack request may contain, protocol v0/v1 and v2 (fetch and
// ls-refs arguments). Free-text values (agent, filter, ref-prefix) are short
// and printable; the body cap bounds them together.
var uploadPackWords = map[string]bool{
	"want": true, "have": true, "done": true, "shallow": true, "deepen": true,
	"deepen-since": true, "deepen-not": true, "deepen-relative": true, "filter": true,
	"thin-pack": true, "no-progress": true, "include-tag": true, "ofs-delta": true,
	"sideband-all": true, "packfile-uris": true, "wait-for-done": true, "want-ref": true,
	"peel": true, "symrefs": true, "ref-prefix": true, "unborn": true,
}

// v2 capability lines that precede the delimiter packet.
var uploadPackV2Caps = map[string]bool{
	"command": true, "agent": true, "object-format": true, "server-option": true, "session-id": true,
}

// validUploadPackRequest reports whether b is entirely pkt-lines that make up
// a fetch negotiation: v0 "want <oid>"/"have <oid>"/"done" and friends, or v2
// "command=fetch"/"command=ls-refs" with their arguments.
func validUploadPackRequest(b []byte) bool {
	v2, inArgs, sawWant, first := false, false, false, true
	for len(b) > 0 {
		if len(b) < 4 || !isHex(b[:4]) {
			return false
		}
		n, _ := strconv.ParseUint(string(b[:4]), 16, 16)
		switch {
		case n == 0: // flush
			b = b[4:]
			continue
		case n == 1 || n == 2: // v2 delimiter / response end
			if !v2 {
				return false
			}
			inArgs = true
			b = b[4:]
			continue
		case n < 4 || int(n) > len(b):
			return false
		}
		line := strings.TrimSuffix(string(b[4:n]), "\n")
		b = b[n:]
		if line == "" || !printableASCII(line) {
			return false
		}
		if first {
			first = false
			if cmd, ok := strings.CutPrefix(line, "command="); ok {
				if cmd != "fetch" && cmd != "ls-refs" {
					return false
				}
				v2 = true
				continue
			}
		}
		if v2 && !inArgs {
			key, _, _ := strings.Cut(line, "=")
			if !uploadPackV2Caps[key] || key == "command" {
				return false
			}
			continue
		}
		word, rest, _ := strings.Cut(line, " ")
		if !uploadPackWords[word] {
			return false
		}
		if word == "want" || word == "have" {
			oid, _, _ := strings.Cut(rest, " ") // v0: capabilities follow the first want
			if (len(oid) != 40 && len(oid) != 64) || !isHex([]byte(oid)) {
				return false
			}
			sawWant = sawWant || word == "want"
		}
	}
	return v2 || sawWant
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(b) > 0
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
