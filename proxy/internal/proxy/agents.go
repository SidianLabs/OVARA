package proxy

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ovara.proxy/internal/config"
	"ovara.proxy/internal/receipts"
)

// Named agents. Each agent the operator runs gets its own proxy token
// (proxy.json "agents": name -> token), so receipts, approvals, the taint
// rule and the model budget can tell agents apart, and one agent can be
// stopped (`ovara kill -agent NAME`) without stopping the others. The
// single agent_token of older deployments keeps working as the agent
// named "default"; its receipts keep the token-hash label they always had.

// agentIdentity is who a proxy client authenticated as.
type agentIdentity struct {
	// name is the operator's name for the agent: a key of "agents",
	// "default" for agent_token, "" when client authentication is off.
	name string
	// label is what receipts record: the name, or for agent_token the
	// hash of the token ("pt_..."), as before named agents existed.
	label string
	// token is the credential the client presented. It is kept (in
	// memory only) so that requests inside a tunnel can be re-checked
	// against the agents configured now, not those of when it opened.
	token string
}

type agentCtxKey struct{}

// withAgent returns r carrying id for everything that handles it later
// (the requests inside a CONNECT tunnel carry the tunnel's identity).
func withAgent(r *http.Request, id agentIdentity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), agentCtxKey{}, id))
}

// agentOf returns the identity ctx carries, or the zero identity.
func agentOf(ctx context.Context) agentIdentity {
	id, _ := ctx.Value(agentCtxKey{}).(agentIdentity)
	return id
}

// agentRegistry holds the named agents' tokens and the stopped names. Both
// can change while the proxy runs (WatchAgentFiles).
type agentRegistry struct {
	mu      sync.RWMutex
	tokens  map[string]string // name -> token
	stopped map[string]bool   // names, or config.AllAgents
	// scopes narrow named agents (config.AgentScope): what each may act
	// on, its parent, who it acts for.
	scopes map[string]config.AgentScope
	// authOn says client authentication is required. It is set as soon as
	// any client credential is configured (agent_token or an agent) and
	// never cleared while the proxy runs: removing the last agent leaves
	// a proxy that refuses everyone, never one that accepts anyone.
	authOn bool
	// refusals bounds the receipts a stopped agent's retries can write.
	refusals *rateLimiter
}

func newAgentRegistry() *agentRegistry {
	return &agentRegistry{tokens: map[string]string{}, stopped: map[string]bool{}, scopes: map[string]config.AgentScope{}, refusals: newRateLimiter(20, 1)}
}

// SetAgentScopes replaces the agents' scopes (config.ValidateAgentScopes
// is the caller's: a scope here is taken as valid).
func (s *Server) SetAgentScopes(scopes map[string]config.AgentScope) {
	m := make(map[string]config.AgentScope, len(scopes))
	for k, v := range scopes {
		m[k] = v
	}
	s.ids.mu.Lock()
	s.ids.scopes = m
	s.ids.mu.Unlock()
}

// scopeOf returns the agent's scope, if it has one.
func (r *agentRegistry) scopeOf(name string) (config.AgentScope, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sc, ok := r.scopes[name]
	return sc, ok
}

// outOfScope reports the agent behind ctx when resource is outside its
// scope: a scoped agent acts only on the resources its allow list names.
func (s *Server) outOfScope(ctx context.Context, resource string) (string, bool) {
	name := agentOf(ctx).name
	sc, ok := s.ids.scopeOf(name)
	if !ok || sc.InScope(resource) {
		return "", false
	}
	return name, true
}

// forOf is who the agent acts for, "" when its scope does not say.
func (s *Server) forOf(name string) string {
	sc, _ := s.ids.scopeOf(name)
	return sc.For
}

// scopeRefusal answers a request outside the agent's scope.
func scopeRefusal(name string) map[string]any {
	return map[string]any{
		"error":   "outside the scope of agent " + name,
		"reasons": []string{"agent_scope"},
		"hint":    "the agent's allow list (agent_scopes in proxy.json) decides this; a sub-agent's list can only narrow its parent's",
	}
}

// SetAgents replaces the named agents (name -> token). Invalid entries are
// the caller's to refuse (config.ValidateAgents).
func (s *Server) SetAgents(agents map[string]string) {
	m := make(map[string]string, len(agents))
	for k, v := range agents {
		m[k] = v
	}
	s.ids.mu.Lock()
	s.ids.tokens = m
	if len(m) > 0 {
		s.ids.authOn = true
	}
	refuseAll := s.ids.authOn && len(m) == 0 && s.agentToken == ""
	s.ids.mu.Unlock()
	if refuseAll {
		log.Printf("CRITICAL: agents: no agent token is configured any more; client authentication stays on and every client is refused until an agent is added (ovara agent add NAME)")
	}
}

// accepted reports whether id is still a client the proxy accepts: with
// authentication on, its token must still be the one configured for its
// name. A tunnel outlives the check made when it was opened; this is the
// check for each request inside it.
func (s *Server) accepted(id agentIdentity) bool {
	s.ids.mu.RLock()
	defer s.ids.mu.RUnlock()
	if !s.ids.authOn {
		return true
	}
	if id.token == "" {
		return false
	}
	if id.name == config.DefaultAgentName && s.agentToken != "" &&
		subtle.ConstantTimeCompare([]byte(id.token), []byte(s.agentToken)) == 1 {
		return true
	}
	t, ok := s.ids.tokens[id.name]
	return ok && subtle.ConstantTimeCompare([]byte(id.token), []byte(t)) == 1
}

// SetStoppedAgents replaces the set of stopped agent names.
func (s *Server) SetStoppedAgents(names []string) {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	s.ids.mu.Lock()
	s.ids.stopped = m
	s.ids.mu.Unlock()
}

// isStopped reports whether the agent named name has been stopped, itself
// or through a parent: stopping an agent stops its sub-agents.
func (r *agentRegistry) isStopped(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped[config.AllAgents] {
		return true
	}
	for n, depth := name, 0; n != "" && depth < 32; n, depth = r.scopes[n].Parent, depth+1 {
		if r.stopped[n] {
			return true
		}
	}
	return false
}

// proxyCredential returns the token a client presented in
// Proxy-Authorization (Bearer, or the password of Basic), or "".
func proxyCredential(r *http.Request) string {
	h := r.Header.Get("Proxy-Authorization")
	if f, ok := strings.CutPrefix(h, "Bearer "); ok {
		return f
	}
	if f, ok := strings.CutPrefix(h, "Basic "); ok {
		if b, err := base64.StdEncoding.DecodeString(f); err == nil {
			if _, p, ok := strings.Cut(string(b), ":"); ok {
				return p
			}
		}
	}
	return ""
}

// authenticate checks the client credential and says who presented it.
// Every configured token is compared, in constant time, whatever matched
// first: the time taken does not say which agent a guess was close to.
// Client authentication is off only while no client credential has ever
// been configured; once on, it stays on (an empty set refuses everyone).
func (s *Server) authenticate(r *http.Request) (agentIdentity, bool) {
	s.ids.mu.RLock()
	tokens := s.ids.tokens
	authOn := s.ids.authOn
	s.ids.mu.RUnlock()
	if !authOn {
		return agentIdentity{}, true
	}
	tok := []byte(proxyCredential(r))
	var id agentIdentity
	found := 0
	if s.agentToken != "" && subtle.ConstantTimeCompare(tok, []byte(s.agentToken)) == 1 {
		id = agentIdentity{name: config.DefaultAgentName, label: agentLabel(s.agentToken), token: s.agentToken}
		found++
	}
	for name, t := range tokens {
		if subtle.ConstantTimeCompare(tok, []byte(t)) == 1 {
			id = agentIdentity{name: name, label: name, token: t}
			found++
		}
	}
	if len(tok) == 0 || found != 1 {
		return agentIdentity{}, false
	}
	return id, true
}

// agentStoppedMessage is what a stopped agent is told.
const agentStoppedMessage = "this agent was stopped by its operator"

// refuseStopped answers a request from a stopped agent with 403 and a
// receipt (rate limited: a stopped agent retrying in a loop must not grow
// the log without bound). It reports whether it did.
func (s *Server) refuseStopped(w http.ResponseWriter, r *http.Request, id agentIdentity) bool {
	if !s.ids.isStopped(id.name) {
		return false
	}
	s.refuseAgent(w, r, id, "agent_stopped", agentStoppedMessage)
	return true
}

// agentRemovedMessage is what a client whose token was taken away is told.
const agentRemovedMessage = "this agent's token is no longer accepted"

// refuseRemoved answers a request inside a tunnel whose agent has since
// been removed (or whose token changed) with 403 and a receipt, and closes
// the tunnel. It reports whether it did.
func (s *Server) refuseRemoved(w http.ResponseWriter, r *http.Request, id agentIdentity) bool {
	if s.accepted(id) {
		return false
	}
	w.Header().Set("Connection", "close")
	s.refuseAgent(w, r, id, "agent_removed", agentRemovedMessage)
	return true
}

// refuseAgent writes the refusal and its (rate-limited) receipt.
func (s *Server) refuseAgent(w http.ResponseWriter, r *http.Request, id agentIdentity, reason, msg string) {
	target := r.Host
	if r.Method != http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		target = redactURL(r.URL)
	}
	if s.ids.refusals.allow() {
		if _, err := s.chain.Append(receipts.Entry{
			Method: r.Method, URL: target, Decision: "deny", Status: http.StatusForbidden,
			Agent: id.label, Reasons: []string{reason},
		}, false); err != nil {
			log.Printf("CRITICAL: receipt record failed for refused agent %q %s %s: %v", id.name, r.Method, target, err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "reasons": []string{reason}})
}

// agentGone reports whether the agent behind ctx has been stopped or
// removed since its request was let through.
func (s *Server) agentGone(ctx context.Context) bool {
	id := agentOf(ctx)
	return s.ids.isStopped(id.name) || !s.accepted(id)
}

// agentStopped reports whether the agent behind ctx has been stopped (a
// request parked on a person stops waiting).
func (s *Server) agentStopped(ctx context.Context) bool {
	return s.ids.isStopped(agentOf(ctx).name)
}

// agentWatchInterval is how often a response in flight checks whether its
// agent is still let through.
var agentWatchInterval = 250 * time.Millisecond

// cutWhenAgentGone calls cancel once the agent behind ctx is stopped or
// removed. Call stop when the response is done; cut reports whether cancel
// was called for that reason.
func (s *Server) cutWhenAgentGone(ctx context.Context, cancel context.CancelFunc) (stop func(), cut func() bool) {
	done := make(chan struct{})
	var gone atomic.Bool
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(agentWatchInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if s.agentGone(ctx) {
				gone.Store(true)
				cancel()
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); <-finished }) }, gone.Load
}

// withAgentPreview adds the agent's name to what the approver sees (and
// what the gateway records with the request), so an approval says which
// agent is asking. The map is copied, never changed in place.
func withAgentPreview(ctx context.Context, preview map[string]string) map[string]string {
	name := agentOf(ctx).name
	if name == "" {
		return preview
	}
	out := make(map[string]string, len(preview)+2)
	for k, v := range preview {
		out[k] = v
	}
	out["agent"] = name
	return out
}

// withForPreview adds who the agent acts for, when its scope says.
func (s *Server) withForPreview(ctx context.Context, preview map[string]string) map[string]string {
	who := s.forOf(agentOf(ctx).name)
	if who == "" {
		return preview
	}
	out := make(map[string]string, len(preview)+1)
	for k, v := range preview {
		out[k] = v
	}
	out["for"] = who
	return out
}

// agentKey is the key per-agent state (taint, model budget) is kept under.
func agentKey(ctx context.Context) string { return agentOf(ctx).name }

// WatchAgentFiles loads the named agents from proxyJSON and the stopped
// agents from revokedFile now, then re-reads both whenever they change,
// checking every interval (a stopped agent is refused within about that
// long). A file that cannot be read or parsed leaves the current state as
// it is, so a broken edit never lets a stopped agent back in. Call the
// returned function to stop watching.
func (s *Server) WatchAgentFiles(proxyJSON, revokedFile string, interval time.Duration) func() {
	type stamp struct {
		mod  time.Time
		size int64
		ok   bool
	}
	statOf := func(p string) stamp {
		fi, err := os.Stat(p)
		if err != nil {
			return stamp{}
		}
		return stamp{fi.ModTime(), fi.Size(), true}
	}
	loadAgents := func() {
		if proxyJSON == "" {
			return
		}
		agents, _, err := config.ReadAgents(proxyJSON)
		if err != nil {
			log.Printf("agents: keeping the current agents: %v", err)
			return
		}
		scopes, err := config.ReadAgentScopes(proxyJSON)
		if err != nil {
			log.Printf("agents: keeping the current agents and scopes: %v", err)
			return
		}
		s.SetAgents(agents)
		s.SetAgentScopes(scopes)
	}
	lastErr := ""
	loadRevoked := func() {
		rv, err := config.LoadRevoked(revokedFile)
		if err != nil {
			if err.Error() != lastErr {
				log.Printf("agents: keeping the current stopped agents: %v", err)
			}
			lastErr = err.Error()
			return
		}
		lastErr = ""
		names := make([]string, 0, len(rv.Stopped))
		for n := range rv.Stopped {
			names = append(names, n)
		}
		s.SetStoppedAgents(names)
	}
	lastA := statOf(proxyJSON)
	loadAgents()
	loadRevoked()
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			if a := statOf(proxyJSON); a != lastA {
				lastA = a
				loadAgents()
			}
			// The stopped list is small and read every time: a change
			// within the file system's timestamp resolution is not missed.
			loadRevoked()
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

// applyAgentConfig sets the named agents, the taint rule and the model
// budget from proxy.json.
func (s *Server) applyAgentConfig(c *config.Config) {
	s.SetAgents(c.Agents)
	s.SetAgentScopes(c.AgentScopes)
	if t := c.Taint; t != nil {
		s.SetTaint(t.On == nil || *t.On, time.Duration(t.WindowMinutes)*time.Minute, t.UntrustedReads, t.ExemptWrites)
	}
	if b := c.ModelBudget; b != nil {
		s.SetModelBudget(!b.Off, b.Requests, b.InputTokens, b.OutputTokens)
	}
}
