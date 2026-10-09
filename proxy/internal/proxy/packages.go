package proxy

import (
	"context"
	"log"
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

const actionPackageInstall = "package.install"

// package-check outcomes
const (
	pkgAllow    = "allow"
	pkgDeny     = "deny"
	pkgApproved = "approved"
	pkgTimeout  = "timeout"
	pkgAborted  = "aborted"
	pkgError    = "error"
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
}

// SetPackageGate turns the strict-install check on, with the packages the
// project's lockfiles pin (lockfiles.Ref form).
func (s *Server) SetPackageGate(allowed []string) {
	g := &packageGate{allowed: map[string]bool{}, pending: map[string]*pkgResult{}}
	for _, r := range allowed {
		g.allowed[r] = true
	}
	s.pkgGate = g
}

// packageDownload names the package a request downloads, if the gate is on
// and it is one.
func (s *Server) packageDownload(host, path string) (string, bool) {
	if s.pkgGate == nil {
		return "", false
	}
	return lockfiles.Download(host, path)
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
	d, err := s.gw.CheckAction(ctx, actionPackageInstall, ref, map[string]string{
		"package":  ref,
		"download": url,
		"why":      "not in the project's lockfiles when the box started",
	})
	if err != nil {
		log.Printf("package gate: gateway check for %s failed: %v", ref, err)
		return pkgError, ""
	}
	switch d.Decision {
	case "allow":
		return pkgAllow, ""
	case "escalate":
		log.Printf("package gate: %s is not in the project's lockfiles; waiting for approval", ref)
		outcome, id := s.holdForApproval(ctx, ref, func() (string, error) {
			if d.ApprovalID != "" {
				return d.ApprovalID, nil
			}
			return s.gw.CreateApprovalFor(ctx, d, actionPackageInstall, ref)
		})
		switch outcome {
		case "approved":
			return pkgApproved, id
		case "timeout":
			return pkgTimeout, id
		case "aborted":
			return pkgAborted, id
		}
		return pkgDeny, id
	}
	return pkgDeny, ""
}
