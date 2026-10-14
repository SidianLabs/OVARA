package approval

import (
	"errors"
	"testing"
	"time"
)

// A request approved after its caller stopped waiting is not asked again:
// the next identical request from the same agent gets that approval back,
// once. Open hands it out while it is unused; Claim marks it used, so an
// identical request after that opens a new approval.
func TestOpen_ReusesAnApprovedUnusedApprovalOnce(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	ctx := map[string]string{"body_sha256": "abc", "body_bytes": "10"}
	const deploy = "POST https://x.example/deploy"

	a, reused, err := svc.Open(openReq("dec_1", "agent-1", deploy, ctx))
	if err != nil || reused {
		t.Fatal(err, reused)
	}
	if _, err := svc.Approve(a.ApprovalID, "operator"); err != nil {
		t.Fatal(err)
	}
	// The retry: same agent, same request, a new decision.
	b, reused, err := svc.Open(openReq("dec_2", "agent-1", deploy, ctx))
	if err != nil || !reused || b.ApprovalID != a.ApprovalID || b.Status != StatusApproved {
		t.Fatalf("retry after a late approval: err=%v reused=%v id=%s status=%s (want %s approved)", err, reused, b.ApprovalID, b.Status, a.ApprovalID)
	}
	// Claimed once.
	c, claimed, err := svc.Claim(a.ApprovalID)
	if err != nil || !claimed || c.Status != StatusApproved || c.ResumedAt == nil {
		t.Fatalf("first claim: err=%v claimed=%v %+v", err, claimed, c)
	}
	if _, claimed, err := svc.Claim(a.ApprovalID); claimed || !errors.Is(err, ErrApprovalUsed) {
		t.Fatalf("second claim: claimed=%v err=%v, want ErrApprovalUsed", claimed, err)
	}
	// A third identical request is a new question.
	d, reused, err := svc.Open(openReq("dec_3", "agent-1", deploy, ctx))
	if err != nil || reused || d.ApprovalID == a.ApprovalID || d.Status != StatusPending {
		t.Fatalf("after the approval was used: err=%v reused=%v id=%s status=%s", err, reused, d.ApprovalID, d.Status)
	}
}

// Only the identical request gets an approval back: another body, another
// resource, another agent, or a request whose gateway digest differs opens
// its own.
func TestOpen_ReusesApprovedOnlyForTheIdenticalRequest(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	ctx := map[string]string{"body_sha256": "abc", "body_bytes": "10"}
	const deploy = "POST https://x.example/deploy"
	req := openReq("dec_1", "agent-1", deploy, ctx)
	req.RequestHash = "digest-1"
	a, _, err := svc.Open(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(a.ApprovalID, "operator"); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*CreateRequest{
		"another body":     openReq("dec_b", "agent-1", deploy, map[string]string{"body_sha256": "def", "body_bytes": "10"}),
		"another resource": openReq("dec_r", "agent-1", "POST https://x.example/other", ctx),
		"another agent":    openReq("dec_a", "agent-2", deploy, ctx),
	} {
		got, reused, err := svc.Open(r)
		if err != nil {
			t.Fatal(name, err)
		}
		if reused || got.ApprovalID == a.ApprovalID {
			t.Errorf("%s: got the approved approval back (reused=%v)", name, reused)
		}
	}
	// The identical request with the same digest gets it back (still unused).
	same := openReq("dec_s", "agent-1", deploy, ctx)
	same.RequestHash = "digest-1"
	if got, reused, err := svc.Open(same); err != nil || !reused || got.ApprovalID != a.ApprovalID {
		t.Fatalf("identical request: err=%v reused=%v", err, reused)
	}
	// The same key but another gateway digest is not the same request: it
	// opens its own, pending, approval.
	other := openReq("dec_h", "agent-1", deploy, ctx)
	other.RequestHash = "digest-2"
	if got, reused, err := svc.Open(other); err != nil || reused || got.ApprovalID == a.ApprovalID || got.Status != StatusPending {
		t.Fatalf("another digest: err=%v reused=%v status=%s", err, reused, got.Status)
	}
}

// A late approval is reusable for as long as a pending one would have been
// approvable (the pending TTL), and no longer. With expiry off, the default
// TTL bounds it.
func TestOpen_ApprovedReuseWindowFollowsThePendingTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, 2 * time.Minute} {
		now := time.Now().UTC()
		svc := NewService(NewInMemoryStore())
		svc.SetNow(clockAt(&now))
		svc.SetPendingTTL(ttl)
		ctx := map[string]string{"body_sha256": "abc"}
		a, _, err := svc.Open(openReq("dec_1", "agent-1", "POST https://x.example/deploy", ctx))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Approve(a.ApprovalID, "operator"); err != nil {
			t.Fatal(err)
		}
		window := ttl
		if window <= 0 {
			window = DefaultPendingTTL
		}
		now = now.Add(window - time.Second)
		if _, reused, _ := svc.Open(openReq("dec_2", "agent-1", "POST https://x.example/deploy", ctx)); !reused {
			t.Errorf("ttl %v: inside the window the approval should come back", ttl)
		}
		now = now.Add(2 * time.Second)
		if got, reused, _ := svc.Open(openReq("dec_3", "agent-1", "POST https://x.example/deploy", ctx)); reused || got.Status != StatusPending {
			t.Errorf("ttl %v: past the window a new approval should open (reused=%v status=%s)", ttl, reused, got.Status)
		}
	}
}

// Claim is for approved approvals only: a pending, denied or expired one is
// reported as it is and nothing is marked.
func TestClaim_OnlyAnApprovedApprovalIsClaimable(t *testing.T) {
	now := time.Now().UTC()
	svc := NewService(NewInMemoryStore())
	svc.SetNow(clockAt(&now))
	svc.SetPendingTTL(time.Minute)
	pending := pendingFor(t, svc, "dec_p")
	if got, claimed, err := svc.Claim(pending.ApprovalID); err != nil || claimed || got.Status != StatusPending {
		t.Fatalf("pending: err=%v claimed=%v status=%s", err, claimed, got.Status)
	}
	denied := pendingFor(t, svc, "dec_d")
	if _, err := svc.Deny(denied.ApprovalID, "operator", "no"); err != nil {
		t.Fatal(err)
	}
	if got, claimed, err := svc.Claim(denied.ApprovalID); err != nil || claimed || got.Status != StatusDenied {
		t.Fatalf("denied: err=%v claimed=%v status=%s", err, claimed, got.Status)
	}
	expired := pendingFor(t, svc, "dec_e")
	now = now.Add(2 * time.Minute)
	if got, claimed, err := svc.Claim(expired.ApprovalID); err != nil || claimed || got.Status != StatusExpired {
		t.Fatalf("expired: err=%v claimed=%v status=%s", err, claimed, got.Status)
	}
	if _, _, err := svc.Claim("apr_nope"); err == nil {
		t.Fatal("unknown approval: want an error")
	}
}
