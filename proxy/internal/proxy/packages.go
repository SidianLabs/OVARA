package proxy

import (
	"context"
	"crypto/sha1" //nolint:gosec // see newDigestReader
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"log"
	"strings"
	"sync"

	"ovara.proxy/internal/lockfiles"
)

// Package installs, strict profile (docs/box.md §9). When the gate is on, the
// download of a package artifact from a pinned registry is a second question
// after the URL policy: is this package one the project already pinned? The
// ones in its lockfiles when the box started go through; any other asks the
// gateway (action_type "package.install", resource "npm:name@version"), which
// normally pauses for a person. An approved package is allowed for the rest
// of the run, so each new dependency pauses once.
//
// A request to a registry that is neither metadata nor an artifact the
// gate can name is asked about the same way (resource "download:<host><path>",
// once per URL): what cannot be named is not let through as if it were
// metadata.
//
// Where the lockfile records a digest for a package, the download is checked
// against it as it streams: the last bytes are held back until the digest
// matches, and on a mismatch the response is cut and a refusal recorded.

const actionPackageInstall = "package.install"

// package-check outcomes
const (
	pkgAllow    = "allow"
	pkgDeny     = "deny"
	pkgApproved = "approved"
	pkgTimeout  = "timeout"
	pkgAborted  = "aborted"
	pkgError    = "error"

	gwEscalate = "escalate" // the gateway's decision string
)

type pkgResult struct {
	done       chan struct{}
	outcome    string
	approvalID string
}

type packageGate struct {
	mu      sync.Mutex
	allowed map[string]bool
	pending map[string]*pkgResult // one question per package, however many downloads ask
	digests map[string][]string   // lockfile digests per ref (SRI form); read-only after set
}

// SetPackageGate turns the strict-install check on, with the packages the
// project's lockfiles pin (lockfiles.Ref form).
func (s *Server) SetPackageGate(allowed []string) {
	pins := make(map[string][]string, len(allowed))
	for _, r := range allowed {
		pins[r] = nil
	}
	s.SetPackageGatePins(pins)
}

// SetPackageGatePins turns the strict-install check on with pinned packages
// and the digests their lockfiles record (lockfiles.ScanPins).
func (s *Server) SetPackageGatePins(pins map[string][]string) {
	g := &packageGate{allowed: map[string]bool{}, pending: map[string]*pkgResult{}, digests: map[string][]string{}}
	for r, d := range pins {
		g.allowed[r] = true
		if len(d) > 0 {
			g.digests[r] = d
		}
	}
	s.pkgGate = g
}

// unrecognisedPrefix marks a package-gate question about a registry request
// that is neither metadata nor a nameable artifact.
const unrecognisedPrefix = "download:"

// packageDownload names what the package gate asks about for a request, if
// the gate is on and the request is a package artifact (its ref) or an
// unrecognised registry download ("download:<host><path>").
func (s *Server) packageDownload(host, path string) (string, bool) {
	if s.pkgGate == nil {
		return "", false
	}
	switch kind, ref := lockfiles.Classify(host, path); kind {
	case lockfiles.Artifact:
		return ref, true
	case lockfiles.Unrecognised:
		return unrecognisedPrefix + strings.ToLower(host) + path, true
	}
	return "", false
}

// packageDigests are the lockfile digests a download of ref must match;
// none when the lockfile recorded none.
func (s *Server) packageDigests(ref string) []string {
	if s.pkgGate == nil {
		return nil
	}
	return s.pkgGate.digests[ref]
}

// checkPackage decides one download of package ref. It returns pkgAllow
// (pinned, allowed by policy, or approved now or earlier in the run),
// pkgDeny, pkgTimeout, pkgAborted or pkgError, and the approval id if a
// person was asked.
func (s *Server) checkPackage(ctx context.Context, ref, url string) (string, string) {
	g := s.pkgGate
	g.mu.Lock()
	if g.allowed[ref] {
		g.mu.Unlock()
		return pkgAllow, ""
	}
	if p, ok := g.pending[ref]; ok {
		g.mu.Unlock()
		select {
		case <-p.done:
			if p.outcome == pkgApproved {
				return pkgAllow, p.approvalID
			}
			return p.outcome, p.approvalID
		case <-ctx.Done():
			return pkgAborted, ""
		}
	}
	p := &pkgResult{done: make(chan struct{})}
	g.pending[ref] = p
	g.mu.Unlock()

	p.outcome, p.approvalID = s.askPackage(ctx, ref, url)
	g.mu.Lock()
	if p.outcome == pkgAllow || p.outcome == pkgApproved {
		g.allowed[ref] = true
	}
	delete(g.pending, ref)
	g.mu.Unlock()
	close(p.done)
	if p.outcome == pkgApproved {
		return pkgAllow, p.approvalID
	}
	return p.outcome, p.approvalID
}

func (s *Server) askPackage(ctx context.Context, ref, url string) (string, string) {
	if strings.HasPrefix(ref, unrecognisedPrefix) {
		return s.askAction(ctx, actionPackageInstall, ref, map[string]string{
			"download": url,
			"why":      "unrecognised registry download: neither metadata nor a package the gate can name",
		}, "is an unrecognised registry download")
	}
	return s.askAction(ctx, actionPackageInstall, ref, map[string]string{
		"package":  ref,
		"download": url,
		"why":      "not in the project's lockfiles when the box started",
	}, "is not in the project's lockfiles")
}

// errDigestMismatch ends a package download whose bytes are not what the
// lockfile pinned.
var errDigestMismatch = errors.New("package download does not match the lockfile's digest")

// digestReader passes a download through while hashing it, and holds back
// the most recent chunk until the end: only a body whose digest matches one
// of want is delivered whole. On a mismatch it returns errDigestMismatch
// instead of the last chunk and EOF.
type digestReader struct {
	src     io.Reader
	want    []string // SRI: "sha512-<base64>"
	hashes  map[string]hash.Hash
	held    []byte
	out     []byte
	done    bool
	err     error
	matched bool
}

func newDigestReader(src io.Reader, want []string) *digestReader {
	d := &digestReader{src: src, want: want, hashes: map[string]hash.Hash{}}
	for _, w := range want {
		algo, _, _ := strings.Cut(w, "-")
		if _, ok := d.hashes[algo]; ok {
			continue
		}
		switch algo {
		case "sha1":
			d.hashes[algo] = sha1.New() //nolint:gosec // npm's older lockfiles record sha1; it is matched, not trusted alone
		case "sha256":
			d.hashes[algo] = sha256.New()
		case "sha384":
			d.hashes[algo] = sha512.New384()
		case "sha512":
			d.hashes[algo] = sha512.New()
		}
	}
	return d
}

func (d *digestReader) Read(p []byte) (int, error) {
	for len(d.out) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		buf := make([]byte, 32<<10)
		n, err := d.src.Read(buf)
		if n > 0 {
			for _, h := range d.hashes {
				h.Write(buf[:n])
			}
			d.out, d.held = d.held, append([]byte(nil), buf[:n]...)
		}
		if err == io.EOF {
			if d.check() {
				d.out = append(d.out, d.held...)
				d.held = nil
				d.done = true
			} else {
				d.out, d.held = nil, nil
				d.err = errDigestMismatch
			}
		} else if err != nil {
			d.out, d.held = nil, nil // never the last bytes of a body that did not end
			d.err = err
		}
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}

func (d *digestReader) check() bool {
	for _, w := range d.want {
		algo, b64, _ := strings.Cut(w, "-")
		h, ok := d.hashes[algo]
		if !ok {
			continue
		}
		if base64.StdEncoding.EncodeToString(h.Sum(nil)) == b64 {
			d.matched = true
			return true
		}
	}
	return false
}

// askAction is the second question the proxy asks about a request the URL
// policy allowed: a gateway check of its own action type, held for a person
// when the answer is escalate (the gateway opens approvals only for decisions
// it recorded as escalate). It returns pkgAllow (policy allowed it),
// pkgApproved, pkgDeny, pkgTimeout, pkgAborted or pkgError, and the approval
// id if a person was asked. why is for the log line.
func (s *Server) askAction(ctx context.Context, actionType, resource string, preview map[string]string, why string) (string, string) {
	d, err := s.gw.CheckAction(ctx, actionType, resource, preview)
	if err != nil {
		log.Printf("%s: gateway check for %s failed: %v", actionType, resource, err)
		return pkgError, ""
	}
	switch d.Decision {
	case pkgAllow:
		return pkgAllow, ""
	case gwEscalate:
		log.Printf("%s: %s %s; waiting for approval", actionType, resource, why)
		outcome, id := s.holdForApproval(ctx, resource, func() (string, error) {
			if d.ApprovalID != "" {
				return d.ApprovalID, nil
			}
			return s.gw.CreateApprovalFor(ctx, d, actionType, resource)
		})
		switch outcome {
		case pkgApproved, pkgTimeout, pkgAborted: // holdForApproval's outcomes share these names
			return outcome, id
		}
		return pkgDeny, id
	}
	return pkgDeny, ""
}
