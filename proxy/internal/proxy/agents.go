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
	// refusals bounds the receipts a stopped agent's retries can write.
	refusals *rateLimiter
}

func newAgentRegistry() *agentRegistry {
	return &agentRegistry{tokens: map[string]string{}, stopped: map[string]bool{}, refusals: newRateLimiter(20, 1)}
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
	s.ids.mu.Unlock()
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

// isStopped reports whether the agent named name has been stopped.
func (r *agentRegistry) isStopped(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stopped[config.AllAgents] || (name != "" && r.stopped[name])
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
// With no token configured at all, client authentication is off.
func (s *Server) authenticate(r *http.Request) (agentIdentity, bool) {
	s.ids.mu.RLock()
	tokens := s.ids.tokens
	s.ids.mu.RUnlock()
	if s.agentToken == "" && len(tokens) == 0 {
		return agentIdentity{}, true
	}
	tok := []byte(proxyCredential(r))
	var id agentIdentity
	found := 0
	if s.agentToken != "" && subtle.ConstantTimeCompare(tok, []byte(s.agentToken)) == 1 {
		id = agentIdentity{name: config.DefaultAgentName, label: agentLabel(s.agentToken)}
		found++
	}
	for name, t := range tokens {
		if subtle.ConstantTimeCompare(tok, []byte(t)) == 1 {
			id = agentIdentity{name: name, label: name}
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
	target := r.Host
	if r.Method != http.MethodConnect && r.URL != nil && r.URL.Host != "" {
		target = redactURL(r.URL)
	}
	if s.ids.refusals.allow() {
		if _, err := s.chain.Append(receipts.Entry{
			Method: r.Method, URL: target, Decision: "deny", Status: http.StatusForbidden,
			Agent: id.label, Reasons: []string{"agent_stopped"},
		}, false); err != nil {
			log.Printf("CRITICAL: receipt record failed for stopped agent %q %s %s: %v", id.name, r.Method, target, err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": agentStoppedMessage, "reasons": []string{"agent_stopped"}})
	return true
}

// agentStopped reports whether the agent behind ctx has been stopped (a
// request parked on a person stops waiting).
func (s *Server) agentStopped(ctx context.Context) bool {
	return s.ids.isStopped(agentOf(ctx).name)
}

// withAgentPreview adds the agent's name to what the approver sees (and
// what the gateway records with the request), so an approval says which
// agent is asking. The map is copied, never changed in place.
func withAgentPreview(ctx context.Context, preview map[string]string) map[string]string {
	name := agentOf(ctx).name
	if name == "" {
		return preview
	}
	out := make(map[string]string, len(preview)+1)
	for k, v := range preview {
		out[k] = v
	}
	out["agent"] = name
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
		s.SetAgents(agents)
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
	if t := c.Taint; t != nil {
		s.SetTaint(t.On == nil || *t.On, time.Duration(t.WindowMinutes)*time.Minute, t.UntrustedReads, t.ExemptWrites)
	}
	if b := c.ModelBudget; b != nil {
		s.SetModelBudget(!b.Off, b.Requests, b.InputTokens, b.OutputTokens)
	}
}
