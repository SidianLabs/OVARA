package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// A request body is read in full before anyone is asked about the request,
// and exactly those bytes are what goes upstream. Otherwise a person approves
// a preview while the agent, still holding the connection, writes the rest of
// the body only after the answer: the approval would cover bytes nobody saw.
// The hash of the held bytes goes into the approval context so the person can
// tell two otherwise identical requests apart. A body the model or MCP gate
// reads as JSON is replaced by its canonical form before anyone is asked
// (canonical.go): then those are the held bytes, hashed and sent.

const (
	defaultMaxHeldBody   = 1 << 20   // ordinary request bodies
	defaultMaxPushBytes  = 256 << 20 // git push packs
	defaultMaxUploadPack = 1 << 20   // git fetch negotiation
	// Bodies up to this size stay in memory; larger ones (pushes, big model
	// requests) are spilled to a temporary file while they are held.
	heldInMemory = 8 << 20
	// heldHeadBytes of every body are kept in memory for the preview and the
	// git ref parser, whatever the body's size.
	heldHeadBytes = gitBodyPeek
)

var errBodyTooLarge = errors.New("request body larger than the review limit")

// heldBody is a request body read in full, with its SHA-256.
type heldBody struct {
	size int64
	sum  []byte
	head []byte   // first heldHeadBytes bytes
	mem  []byte   // the whole body, when kept in memory
	file *os.File // the whole body, when spilled
}

// reader returns a fresh reader over the whole held body.
func (h *heldBody) reader() io.Reader {
	if h.file != nil {
		return io.NewSectionReader(h.file, 0, h.size)
	}
	return bytes.NewReader(h.mem)
}

func (h *heldBody) sha256Hex() string { return hex.EncodeToString(h.sum) }

// close releases a spilled body's temporary file. Safe on nil.
func (h *heldBody) close() {
	if h == nil || h.file == nil {
		return
	}
	name := h.file.Name()
	h.file.Close()
	os.Remove(name)
}

// bodyLimit is how many bytes of r's body may be held for review. Pushes and
// model calls are legitimately large; everything else gets the ordinary cap.
func (s *Server) bodyLimit(r *http.Request) int64 {
	p := strings.ToLower(r.URL.EscapedPath())
	switch {
	case r.Method == http.MethodPost && strings.Contains(p, "git-receive-pack"):
		return s.limits.maxPush
	case r.Method == http.MethodPost && strings.Contains(p, "git-upload-pack"):
		// Never less than an ordinary body: an escalated POST to such a path
		// is not a fetch and gets the ordinary limit. A fetch the policy
		// allowed is held to max_upload_pack_bytes in allowedGitRefusal.
		return max(s.limits.maxHeldBody, s.limits.maxUploadPack)
	case r.Method != http.MethodGet && r.Method != http.MethodHead && s.isModelHost(r.URL.Hostname()):
		// A model conversation resends its whole context every turn.
		return max(s.limits.maxHeldBody, maxModelBody)
	}
	return s.limits.maxHeldBody
}

// holdBody reads r's whole body (at most limit bytes), replaces r.Body with
// the held bytes, and fixes the framing so exactly those bytes are sent:
// Content-Length set, Transfer-Encoding cleared. It returns nil for a request
// without a body, and errBodyTooLarge (having read no more than limit+1
// bytes) for one over the limit, declared or streamed.
func holdBody(r *http.Request, limit int64) (*heldBody, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if r.ContentLength > limit {
		return nil, errBodyTooLarge
	}
	src := &io.LimitedReader{R: r.Body, N: limit + 1}
	sum := sha256.New()
	var buf bytes.Buffer
	if _, err := io.Copy(io.MultiWriter(&buf, sum), io.LimitReader(src, heldInMemory)); err != nil {
		return nil, err
	}
	h := &heldBody{size: int64(buf.Len())}
	if h.size == heldInMemory && src.N > 0 {
		if err := h.spill(&buf, src, sum); err != nil {
			h.close()
			return nil, err
		}
	} else {
		h.mem = buf.Bytes()
		h.head = h.mem[:min(len(h.mem), heldHeadBytes)]
	}
	if h.size > limit {
		h.close()
		return nil, errBodyTooLarge
	}
	h.sum = sum.Sum(nil)
	if h.size == 0 {
		r.Body, r.ContentLength, r.TransferEncoding, r.GetBody = http.NoBody, 0, nil, nil
		return nil, nil
	}
	r.Body = io.NopCloser(h.reader())
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(h.reader()), nil }
	r.ContentLength = h.size
	r.TransferEncoding = nil
	return h, nil
}

// replace makes data the held body and the body r sends: the canonical form
// of a body Ovara read as JSON (canonical.go). Every later reader (the
// approval context, the receipt, the request upstream) sees data and its
// hash. The body as the agent sent it is gone; nothing of it is forwarded.
func (h *heldBody) replace(r *http.Request, data []byte) {
	if h.file != nil {
		name := h.file.Name()
		h.file.Close()
		os.Remove(name)
		h.file = nil
	}
	sum := sha256.Sum256(data)
	h.mem, h.size, h.sum = data, int64(len(data)), sum[:]
	h.head = h.mem[:min(len(h.mem), heldHeadBytes)]
	r.Body = io.NopCloser(h.reader())
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(h.reader()), nil }
	r.ContentLength = h.size
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	// The body is decoded already (a gzip MCP request) or was never
	// encoded: what goes out is the plain canonical bytes.
	r.Header.Del("Content-Encoding")
}

// spill moves a body that outgrew memory into a temporary file and reads
// the rest of it there.
func (h *heldBody) spill(buf *bytes.Buffer, rest io.Reader, sum hash.Hash) error {
	f, err := os.CreateTemp("", "ovara-held-body-*")
	if err != nil {
		log.Printf("hold body: %v", err)
		return err
	}
	h.file = f
	h.head = append([]byte(nil), buf.Bytes()[:heldHeadBytes]...)
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	n, err := io.Copy(io.MultiWriter(f, sum), rest)
	h.size += n
	return err
}
