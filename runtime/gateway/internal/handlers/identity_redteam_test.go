package handlers

// P1 identity red-team suite: exercises the REAL path —
// Bearer token -> auth middleware -> principal -> handler -> evaluator.
// Tests assert security properties (which principal the system acted
// on), not merely HTTP status codes.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"ovara.runtime.gateway/internal/approval"
	"ovara.runtime.gateway/internal/auth"
	"ovara.runtime.gateway/internal/config"
	"ovara.runtime.gateway/internal/enrollment"
	"ovara.runtime.gateway/internal/evaluator"
	"ovara.runtime.gateway/internal/identity"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/policy"
	"ovara.runtime.gateway/internal/receipts"
	"ovara.runtime.gateway/internal/trust"
)

const (
	rtOpToken    = "rt-operator-token"
	rtAgentATok  = "rt-agent-a-token"
	rtAgentBTok  = "rt-agent-b-token"
	rtGatewayAud = "gw-identity-test"
)

// principalFor mirrors auth.principalID: role prefix + sha256(token)[:16].
func principalFor(prefix, token string) string {
	sum := sha256.Sum256([]byte(token))
	return prefix + hex.EncodeToString(sum[:])[:16]
}

func agentAPrincipal() string { return principalFor("ag_", rtAgentATok) }
func agentBPrincipal() string { return principalFor("ag_", rtAgentBTok) }

// rtStack is the wired test gateway: middleware -> mux -> handlers.
type rtStack struct {
	srv        *httptest.Server
	keys       map[string]ed25519.PrivateKey
	trustedPub map[string][]byte
	handler    *Handler
}

func newRTStack(t *testing.T) *rtStack {
	t.Helper()
	policyStore := policy.NewStore("rt-v1")
	policyStore.AddRule(policy.Rule{
		ActionType:  "shell",
		Environment: "*",
		Allow:       true,
	})
	shieldStore := trust.NewShieldStore()
	eval := evaluator.NewWithShield(policyStore, shieldStore)

	pub, priv, _ := ed25519.GenerateKey(nil)
	st := &rtStack{
		keys:       map[string]ed25519.PrivateKey{"ovara": priv},
		trustedPub: map[string][]byte{"ovara": pub},
	}
	v := identity.NewValidatorWithTrustedKeys(st.trustedPub)
	v.SetExpectedAudience(rtGatewayAud)
	eval.SetValidator(v)

	receiptsStore := receipts.NewInMemoryStore()
	cfg := config.Default()
	h := New(eval, nil, cfg, receiptsStore)
	enr := enrollment.NewLocalService(t.TempDir() + "/enrollment.json")
	if err := enr.Initialize("dev"); err != nil {
		t.Fatalf("enrollment init: %v", err)
	}
	h.SetEnrollment(enr)
	st.handler = h

	approvalStore := approval.NewInMemoryStore()
	approvalHandler := NewApprovalHandler(approval.NewService(approvalStore))
	approvalHandler.SetDecisionLookup(h.LookupDecision)

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	approvalHandler.RegisterRoutes(mux)

	mw := auth.NewMiddlewareWithAgents(
		[]string{rtOpToken}, []string{rtAgentATok, rtAgentBTok}, true)
	st.srv = httptest.NewServer(mw.Authenticate(mux))
	t.Cleanup(st.srv.Close)
	return st
}

// check fires a real /v1/runtime/check and returns (status, decision resp).
func (st *rtStack) check(t *testing.T, token string, req models.ActionRequest) (int, *models.DecisionResponse) {
	t.Helper()
	b, _ := json.Marshal(req)
	r, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/runtime/check", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("check request: %v", err)
	}
	defer resp.Body.Close()
	var dr models.DecisionResponse
	_ = json.NewDecoder(resp.Body).Decode(&dr)
	return resp.StatusCode, &dr
}

func baseReq(subject string) models.ActionRequest {
	return models.ActionRequest{
		Nonce:       uuid.NewString(),
		IssuedAt:    time.Now(),
		ActionType:  "shell",
		Resource:    "echo hi",
		Environment: models.EnvironmentDev,
		AgentIdentity: &models.AgentIdentity{
			Issuer: "ovara", SubjectID: subject,
		},
	}
}

// escalateReq uses an unmatched action so the default escalate fires.
func escalateReq(subject string) models.ActionRequest {
	r := baseReq(subject)
	r.ActionType = "network_egress"
	r.Resource = "https://example.com/x"
	return r
}

// IDENTITY-01: valid credential + matching subject works.
func TestRT01_MatchingIdentity(t *testing.T) {
	st := newRTStack(t)
	status, dr := st.check(t, rtAgentATok, baseReq(agentAPrincipal()))
	if status != 200 || dr.Decision != models.DecisionAllow {
		t.Fatalf("matching identity should allow: status=%d decision=%s reasons=%v",
			status, dr.Decision, dr.ReasonCodes)
	}
}

// IDENTITY-02: valid credential + DIFFERENT subject_id -> rejected.
// The caller cannot select another principal.
func TestRT02_ForeignSubjectRejected(t *testing.T) {
	st := newRTStack(t)
	status, _ := st.check(t, rtAgentATok, baseReq("agent-B-self-asserted"))
	if status != 400 {
		t.Fatalf("foreign subject must be rejected with 400, got %d", status)
	}
}

// IDENTITY-03: omitting agent_identity normalizes to the credential
// principal — never anonymous, never caller-chosen.
func TestRT03_MissingIdentityNormalized(t *testing.T) {
	st := newRTStack(t)
	r := baseReq("")
	r.AgentIdentity = nil
	status, dr := st.check(t, rtAgentATok, r)
	if status != 200 || dr.Decision != models.DecisionAllow {
		t.Fatalf("identity-less request should normalize+allow: %d %s %v",
			status, dr.Decision, dr.ReasonCodes)
	}
}

// IDENTITY-04/05: agent-B cannot create an approval on agent-A's
// decision — the decision is owned by A's authenticated principal.
func TestRT04_CrossAgentApprovalCreate(t *testing.T) {
	st := newRTStack(t)

	// A gets an escalated decision.
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	if dr.Decision != models.DecisionEscalate {
		t.Fatalf("expected escalate, got %s %v", dr.Decision, dr.ReasonCodes)
	}

	// B tries to mint an approval on A's decision -> 403.
	b, _ := json.Marshal(map[string]string{"decision_id": dr.DecisionID})
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/approval/create", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtAgentBTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-agent approval create must be 403, got %d", resp.StatusCode)
	}

	// A (the owner) CAN create it -> 201.
	req2, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/approval/create", bytes.NewReader(b))
	req2.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != 201 {
		t.Fatalf("owner approval create should be 201, got %d", resp2.StatusCode)
	}
}

// IDENTITY-06/13: agent-B cannot READ agent-A's approval — foreign IDs
// answer 404 (existence-hiding).
func TestRT06_CrossAgentApprovalGet(t *testing.T) {
	st := newRTStack(t)
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	b, _ := json.Marshal(map[string]string{"decision_id": dr.DecisionID})
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/approval/create", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp, _ := http.DefaultClient.Do(req)
	var ap struct {
		ID      string `json:"approval_id"`
		AgentID string `json:"agent_id"`
	}
	json.NewDecoder(resp.Body).Decode(&ap)
	resp.Body.Close()
	if ap.ID == "" {
		t.Fatal("approval create failed")
	}
	if ap.AgentID != agentAPrincipal() {
		t.Fatalf("approval must be owned by the authenticated principal %q, got %q",
			agentAPrincipal(), ap.AgentID)
	}

	// B reads A's approval -> 404.
	rg, _ := http.NewRequest(http.MethodGet, st.srv.URL+"/v1/approval/"+ap.ID, nil)
	rg.Header.Set("Authorization", "Bearer "+rtAgentBTok)
	rgResp, _ := http.DefaultClient.Do(rg)
	rgResp.Body.Close()
	if rgResp.StatusCode != 404 {
		t.Fatalf("foreign approval GET must be 404, got %d", rgResp.StatusCode)
	}

	// A reads own approval -> 200.
	rg2, _ := http.NewRequest(http.MethodGet, st.srv.URL+"/v1/approval/"+ap.ID, nil)
	rg2.Header.Set("Authorization", "Bearer "+rtAgentATok)
	rgResp2, _ := http.DefaultClient.Do(rg2)
	rgResp2.Body.Close()
	if rgResp2.StatusCode != 200 {
		t.Fatalf("owner approval GET should be 200, got %d", rgResp2.StatusCode)
	}
}

// IDENTITY-07: a lease minted for subject-B presented by agent-A denies.
func TestRT07_LeaseSubjectMismatch(t *testing.T) {
	st := newRTStack(t)
	priv := st.keys["ovara"]

	lease := &models.CapabilityLease{
		LeaseID: "lse-b", Issuer: "ovara", Subject: agentBPrincipal(),
		AllowedActions: []string{"shell"}, ResourceScope: "*",
		Expiry: time.Now().Add(time.Hour), IssuedAt: time.Now(),
		Audience: rtGatewayAud,
	}
	payload := fmt.Sprintf("%s|%s|%s|%v|%s|%d|%d|%d|%s",
		lease.LeaseID, lease.Issuer, lease.Subject, lease.AllowedActions,
		lease.ResourceScope, lease.Expiry.Unix(), lease.DelegationDepth,
		lease.IssuedAt.Unix(), lease.Audience)
	lease.Signature = ed25519.Sign(priv, []byte(payload))

	r := baseReq(agentAPrincipal())
	r.CapabilityLease = lease
	status, dr := st.check(t, rtAgentATok, r)
	if status != 200 || dr.Decision != models.DecisionDeny {
		t.Fatalf("foreign lease must deny: status=%d decision=%s", status, dr.Decision)
	}
}

// IDENTITY-08: self-minted (unsigned) delegation denies.
func TestRT08_SelfMintedDelegation(t *testing.T) {
	st := newRTStack(t)
	r := baseReq(agentAPrincipal())
	r.DelegationChain = &models.DelegationChain{
		Authorities: []models.Authority{
			{Issuer: "ovara", SubjectID: agentAPrincipal(), Nonce: "dn1"},
		},
		Depth: 1,
	}
	status, dr := st.check(t, rtAgentATok, r)
	if status != 200 || dr.Decision != models.DecisionDeny {
		t.Fatalf("self-minted delegation must deny: %d %s", status, dr.Decision)
	}
}

// IDENTITY-15: a batch item claiming a foreign subject rejects the batch.
func TestRT15_BatchForeignSubject(t *testing.T) {
	st := newRTStack(t)
	good := baseReq(agentAPrincipal())
	evil := baseReq("agent-B-claimed")
	body := map[string]any{"requests": []models.ActionRequest{good, evil}}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/runtime/batch-check", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("batch with foreign subject must be 400, got %d", resp.StatusCode)
	}
}

// Batch parity: all-own subjects work end-to-end with per-item decisions.
func TestRT15b_BatchOwnSubjects(t *testing.T) {
	st := newRTStack(t)
	body := map[string]any{"requests": []models.ActionRequest{
		baseReq(agentAPrincipal()), baseReq(agentAPrincipal()),
	}}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/runtime/batch-check", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("batch request: %v", err)
	}
	defer resp.Body.Close()
	var br struct {
		Responses []models.DecisionResponse `json:"decisions"`
	}
	json.NewDecoder(resp.Body).Decode(&br)
	if resp.StatusCode != 200 || len(br.Responses) != 2 {
		t.Fatalf("own-subject batch should produce 2 decisions: %d %+v", resp.StatusCode, br)
	}
	for i, d := range br.Responses {
		if d.Decision != models.DecisionAllow {
			t.Fatalf("item %d should allow, got %s %v", i, d.Decision, d.ReasonCodes)
		}
	}
}

// IDENTITY-16: agent credential on an operator route -> 403.
func TestRT16_AgentOnOperatorRoute(t *testing.T) {
	st := newRTStack(t)
	req, _ := http.NewRequest(http.MethodGet, st.srv.URL+"/v1/approvals", nil)
	req.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("agent on operator route must be 403, got %d", resp.StatusCode)
	}
}

// IDENTITY-17/18/19: unknown/garbage credential -> 401, fail closed.
func TestRT17_InvalidToken(t *testing.T) {
	st := newRTStack(t)
	status, _ := st.check(t, "forged-token-not-in-registry", baseReq(agentAPrincipal()))
	if status != 401 {
		t.Fatalf("unknown credential must be 401, got %d", status)
	}
}

// IDENTITY-24: metadata mutation after decision — divergent approval
// fields are tamper-evident (existing SEC-0016 battery covers; this
// asserts subject-mutation specifically can't redirect ownership).
func TestRT24_SubjectMutationAfterDecision(t *testing.T) {
	st := newRTStack(t)
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	// Caller claims the decision belongs to agent-B via agent_id field.
	b, _ := json.Marshal(map[string]string{
		"decision_id": dr.DecisionID, "agent_id": "agent-B",
	})
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/approval/create", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtAgentATok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	// agent_id divergence is tamper -> 400; NOT silently rebound.
	if resp.StatusCode != 400 {
		t.Fatalf("agent_id mutation must be 400, got %d", resp.StatusCode)
	}
}

// Operator spans agents by design: operator creates on A's decision.
func TestRT_OperatorSpansAgents(t *testing.T) {
	st := newRTStack(t)
	_, dr := st.check(t, rtAgentATok, escalateReq(agentAPrincipal()))
	b, _ := json.Marshal(map[string]string{"decision_id": dr.DecisionID})
	req, _ := http.NewRequest(http.MethodPost, st.srv.URL+"/v1/approval/create", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+rtOpToken)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("operator approval create should be 201, got %d", resp.StatusCode)
	}
}

// Trust poisoning probe: repeated foreign-subject attempts must NOT
// accrue trust/containment state to the claimed identity — bindIdentity
// rejects before the evaluator ever sees the claim.
func TestRT_ContainmentPoisoningDead(t *testing.T) {
	st := newRTStack(t)
	for i := 0; i < 5; i++ {
		status, _ := st.check(t, rtAgentATok, baseReq("victim-agent"))
		if status != 400 {
			t.Fatalf("attempt %d: foreign subject must be rejected, got %d", i, status)
		}
	}
}
