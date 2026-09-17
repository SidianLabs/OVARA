package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// gitBodyPeek is the max bytes buffered to detect/parse a receive-pack
// request. Ref-update header lines live at the start of the body; pack data
// follows the flush pkt (0000) and is never inspected.
const gitBodyPeek = 1 << 20 // 1MB

// RefUpdate is one ref update parsed from a git-receive-pack request body.
type RefUpdate struct {
	Ref    string // e.g. refs/heads/main
	OldSHA string
	NewSHA string
	Delete bool // NewSHA is all zeros (branch/tag delete)
}

// isReceivePack reports whether r is a git smart-HTTP push request.
func isReceivePack(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL == nil {
		return false
	}
	if !strings.HasSuffix(r.URL.Path, "/git-receive-pack") {
		return false
	}
	ct := r.Header.Get("Content-Type")
	return ct == "" || strings.HasPrefix(ct, "application/x-git-receive-pack-request")
}

// peekReceivePack buffers up to gitBodyPeek bytes of r.Body, restores r.Body
// so the full stream (peek + remainder) still reaches upstream, and returns
// the buffered header bytes for parsing. Returns nil if not a push.
func peekReceivePack(r *http.Request) []byte {
	if !isReceivePack(r) || r.Body == nil {
		return nil
	}
	peek, err := io.ReadAll(io.LimitReader(r.Body, gitBodyPeek))
	if err != nil {
		return nil
	}
	// Reconstruct Body: buffered head + whatever remains of the original.
	r.Body = struct {
		io.Reader
		io.Closer
	}{Reader: io.MultiReader(bytes.NewReader(peek), r.Body), Closer: r.Body}
	return peek
}

// parseRefUpdates extracts ref updates from the pkt-line header of a
// receive-pack body. Parsing stops at the flush pkt (0000) that precedes the
// pack data. Malformed input yields whatever refs parsed before the error
// (possibly none); it never panics.
func parseRefUpdates(body []byte) []RefUpdate {
	var refs []RefUpdate
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
			break
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
	return refs
}

// gitResourceSuffix returns " refs/a,refs/b" for appending to the policy
// resource string, or "" for non-push requests / unparseable bodies.
func (s *Server) gitResourceSuffix(r *http.Request) string {
	if !s.gitGate {
		return ""
	}
	peek := peekReceivePack(r)
	if peek == nil {
		return ""
	}
	refs := parseRefUpdates(peek)
	if len(refs) == 0 {
		return " git-receive-pack" // a push we couldn't parse: still flag it
	}
	var b strings.Builder
	fmt.Fprint(&b, " ")
	for i, u := range refs {
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
