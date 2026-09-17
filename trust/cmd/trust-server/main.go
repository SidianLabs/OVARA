package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"ovara.trust/internal/graph"
	"ovara.trust/internal/receipt"
)

type Server struct {
	mux        *http.ServeMux
	graph      *graph.TrustGraph
	store      *graph.GraphStore
	identities map[string]*receipt.FederatedIdentity
	mu         sync.RWMutex
}

func NewServer(dataPath string) *Server {
	s := &Server{
		mux:        http.NewServeMux(),
		graph:      graph.NewTrustGraph(),
		identities: make(map[string]*receipt.FederatedIdentity),
	}
	if dataPath != "" {
		store, g := graph.NewGraphStore(dataPath)
		s.store = store
		s.graph = g
		fmt.Printf("Loaded trust graph from %s\n", dataPath)
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("POST /v1/domains", s.registerDomain)
	s.mux.HandleFunc("GET /v1/domains", s.listDomains)
	s.mux.HandleFunc("GET /v1/domains/", s.getDomain)
	s.mux.HandleFunc("DELETE /v1/domains/", s.removeDomain)
	s.mux.HandleFunc("POST /v1/federations", s.createFederation)
	s.mux.HandleFunc("DELETE /v1/federations/", s.revokeFederation)
	s.mux.HandleFunc("GET /v1/federations", s.listFederations)
	s.mux.HandleFunc("GET /v1/federations/path", s.computePath)
	s.mux.HandleFunc("POST /v1/identities/register", s.registerFederatedIdentity)
	s.mux.HandleFunc("POST /v1/identities/verify", s.verifyFederatedIdentity)
	s.mux.HandleFunc("POST /v1/receipts/verify", s.verifyCrossOrgReceipt)
	s.mux.HandleFunc("GET /v1/trust-status/", s.trustStatus)
	s.mux.HandleFunc("GET /v1/graph", s.graphSnapshot)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "service": "ovara-trust-server"})
}

type registerDomainReq struct {
	Domain  string   `json:"domain"`
	Name    string   `json:"name"`
	PubKeys []string `json:"public_keys"`
}

func (s *Server) registerDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req registerDomainReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Domain == "" || req.Name == "" {
		http.Error(w, "domain and name are required", http.StatusBadRequest)
		return
	}
	if !domainRegex.MatchString(req.Domain) {
		http.Error(w, "invalid domain format", http.StatusBadRequest)
		return
	}
	var pubKeys [][]byte
	for _, k := range req.PubKeys {
		b, err := hex.DecodeString(k)
		if err != nil {
			http.Error(w, "invalid public key hex: "+err.Error(), http.StatusBadRequest)
			return
		}
		pubKeys = append(pubKeys, b)
	}
	err := s.graph.AddOrganization(graph.TrustDomain(req.Domain), req.Name, pubKeys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.save()
	jsonResponse(w, http.StatusCreated, map[string]string{"domain": req.Domain, "status": "registered"})
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	orgs := s.graph.GetAllOrganizations()
	jsonResponse(w, http.StatusOK, map[string]any{
		"organizations": orgs,
		"count":         len(orgs),
	})
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/v1/domains/")
	node, ok := s.graph.GetNode(graph.TrustDomain(domain))
	if !ok {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	neighbors := s.graph.GetNeighbors(graph.TrustDomain(domain))
	jsonResponse(w, http.StatusOK, map[string]any{
		"organization": node,
		"neighbors":    neighbors,
	})
}

func (s *Server) removeDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/v1/domains/")
	err := s.graph.RemoveOrganization(graph.TrustDomain(domain))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.save()
	jsonResponse(w, http.StatusOK, map[string]string{"domain": domain, "status": "removed"})
}

type federationReq struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	TrustLevel float64  `json:"trust_level"`
	TargetKeys []string `json:"target_public_keys"`
}

func (s *Server) createFederation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req federationReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Source == "" || req.Target == "" {
		http.Error(w, "source and target are required", http.StatusBadRequest)
		return
	}
	if req.Source == req.Target {
		http.Error(w, "source and target must be different", http.StatusBadRequest)
		return
	}
	var pubKeys [][]byte
	for _, k := range req.TargetKeys {
		b, err := hex.DecodeString(k)
		if err != nil {
			http.Error(w, "invalid target public key hex: "+err.Error(), http.StatusBadRequest)
			return
		}
		pubKeys = append(pubKeys, b)
	}
	err := s.graph.Federate(graph.TrustDomain(req.Source), graph.TrustDomain(req.Target), req.TrustLevel, pubKeys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rel, _ := s.graph.GetRelationship(graph.TrustDomain(req.Source), graph.TrustDomain(req.Target))
	s.save()
	jsonResponse(w, http.StatusCreated, map[string]any{"status": "federated", "relationship": rel})
}

func (s *Server) revokeFederation(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/federations/")
	source, target, _ := strings.Cut(path, "/")
	if source == "" || target == "" {
		http.Error(w, "source and target domain required", http.StatusBadRequest)
		return
	}
	err := s.graph.RevokeFederation(graph.TrustDomain(source), graph.TrustDomain(target))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.save()
	jsonResponse(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) listFederations(w http.ResponseWriter, r *http.Request) {
	snapshot := s.graph.Snapshot()
	jsonResponse(w, http.StatusOK, snapshot)
}

func (s *Server) computePath(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	target := r.URL.Query().Get("target")
	if source == "" || target == "" {
		http.Error(w, "source and target query params required", http.StatusBadRequest)
		return
	}
	path, err := s.graph.ComputeTrustPath(graph.TrustDomain(source), graph.TrustDomain(target))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"path":        path.Domains,
		"trust_score": path.TrustScore,
		"depth":       path.Depth,
		"direct":      path.IsDirect(),
		"hash":        path.Hash(),
	})
}

type registerIdentityReq struct {
	IdentityDigest string `json:"identity_digest"`
	Domain         string `json:"domain"`
	PublicKey      string `json:"public_key"`
	Signature      string `json:"signature"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
}

func (s *Server) registerFederatedIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req registerIdentityReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.IdentityDigest == "" || req.Domain == "" || req.PublicKey == "" || req.Signature == "" {
		http.Error(w, "identity_digest, domain, public_key, and signature are required", http.StatusBadRequest)
		return
	}
	node, ok := s.graph.GetNode(graph.TrustDomain(req.Domain))
	if !ok {
		http.Error(w, "domain not registered", http.StatusNotFound)
		return
	}
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	// The presented public key must be one of the domain's registered keys.
	if !keyRegistered(node.PublicKeys, pubKeyBytes) {
		http.Error(w, "public key is not registered for domain", http.StatusBadRequest)
		return
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil || len(sigBytes) == 0 {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	issuedAt := now
	if req.IssuedAt != "" {
		t, err := time.Parse(time.RFC3339, req.IssuedAt)
		if err != nil {
			http.Error(w, "invalid issued_at timestamp", http.StatusBadRequest)
			return
		}
		issuedAt = t
	}
	expiresAt := now.Add(24 * time.Hour)
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "invalid expires_at timestamp", http.StatusBadRequest)
			return
		}
		expiresAt = t
	}
	if issuedAt.After(now.Add(5 * time.Minute)) {
		http.Error(w, "issued_at is too far in the future", http.StatusBadRequest)
		return
	}
	if expiresAt.Before(now) || expiresAt.After(now.Add(30*24*time.Hour)) {
		http.Error(w, "expires_at is in the past or more than 30 days out", http.StatusBadRequest)
		return
	}
	fid := &receipt.FederatedIdentity{
		IdentityDigest: req.IdentityDigest,
		Domain:         req.Domain,
		PublicKey:      pubKeyBytes,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		Signature:      sigBytes,
	}
	if !fid.Verify(ed25519.PublicKey(pubKeyBytes)) {
		http.Error(w, "signature verification failed", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.identities[req.Domain+"/"+req.IdentityDigest] = fid
	s.mu.Unlock()
	s.save()
	jsonResponse(w, http.StatusCreated, fid)
}

type verifyIdentityReq struct {
	IdentityDigest string `json:"identity_digest"`
	Domain         string `json:"domain"`
	Signature      string `json:"signature"`
	PubKey         string `json:"public_key"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
}

func (s *Server) verifyFederatedIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req verifyIdentityReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Public keys are resolved from the trust graph — never from the request.
	node, ok := s.graph.GetNode(graph.TrustDomain(req.Domain))
	if !ok {
		http.Error(w, "domain not registered", http.StatusNotFound)
		return
	}
	if req.PubKey != "" {
		if b, err := hex.DecodeString(req.PubKey); err != nil || len(b) != ed25519.PublicKeySize {
			http.Error(w, "invalid public key", http.StatusBadRequest)
			return
		}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature hex", http.StatusBadRequest)
		return
	}
	issuedAt := time.Now().UTC()
	if req.IssuedAt != "" {
		t, err := time.Parse(time.RFC3339, req.IssuedAt)
		if err != nil {
			http.Error(w, "invalid issued_at timestamp", http.StatusBadRequest)
			return
		}
		issuedAt = t
	}
	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			http.Error(w, "invalid expires_at timestamp", http.StatusBadRequest)
			return
		}
		expiresAt = t
	}
	fid := &receipt.FederatedIdentity{
		IdentityDigest: req.IdentityDigest,
		Domain:         req.Domain,
		IssuedAt:       issuedAt,
		ExpiresAt:      expiresAt,
		Signature:      sigBytes,
	}
	valid := false
	for _, k := range node.PublicKeys {
		if fid.Verify(ed25519.PublicKey(k)) {
			valid = true
			break
		}
	}
	now := time.Now().UTC()
	notExpired := now.Before(expiresAt)
	jsonResponse(w, http.StatusOK, map[string]any{
		"valid":       valid && notExpired,
		"signature":   valid,
		"not_expired": notExpired,
		"domain":      req.Domain,
	})
}

type verifyReceiptReq struct {
	ReceiptID      string  `json:"receipt_id"`
	DecisionID     string  `json:"decision_id"`
	IssuingGateway string  `json:"issuing_gateway"`
	IssuingOrg     string  `json:"issuing_org"`
	ActionType     string  `json:"action_type"`
	Resource       string  `json:"resource"`
	Decision       string  `json:"decision"`
	AgentIdentity  string  `json:"agent_identity"`
	TrustScore     float64 `json:"trust_score"`
	Timestamp      string  `json:"timestamp"`
	Signature      string  `json:"signature"`
	PubKey         string  `json:"public_key"`
}

func (s *Server) verifyCrossOrgReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req verifyReceiptReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Public keys are resolved from the trust graph — never from the request.
	node, ok := s.graph.GetNode(graph.TrustDomain(req.IssuingOrg))
	if !ok {
		http.Error(w, "issuing org not registered", http.StatusNotFound)
		return
	}
	if req.PubKey != "" {
		if b, err := hex.DecodeString(req.PubKey); err != nil || len(b) != ed25519.PublicKeySize {
			http.Error(w, "invalid public key", http.StatusBadRequest)
			return
		}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "invalid signature hex", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	timestamp := now
	if req.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, req.Timestamp); err == nil {
			timestamp = t
		}
	}
	// Reject receipts with timestamps outside a reasonable freshness window
	// to prevent replay of old receipts.
	if timestamp.Before(now.Add(-5*time.Minute)) || timestamp.After(now.Add(5*time.Minute)) {
		jsonResponse(w, http.StatusOK, map[string]any{
			"valid":       false,
			"receipt_id":  req.ReceiptID,
			"issuing_org": req.IssuingOrg,
			"reason":      "timestamp outside freshness window",
		})
		return
	}
	receipt := &receipt.CrossOrgReceipt{
		ReceiptID:      req.ReceiptID,
		DecisionID:     req.DecisionID,
		IssuingGateway: req.IssuingGateway,
		IssuingOrg:     req.IssuingOrg,
		ActionType:     req.ActionType,
		Resource:       req.Resource,
		Decision:       req.Decision,
		AgentIdentity:  req.AgentIdentity,
		TrustScore:     req.TrustScore,
		Timestamp:      timestamp,
		Signature:      sigBytes,
	}
	valid := false
	for _, k := range node.PublicKeys {
		if receipt.Verify(k) {
			valid = true
			break
		}
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"valid":       valid,
		"receipt_id":  req.ReceiptID,
		"issuing_org": req.IssuingOrg,
	})
}

func (s *Server) trustStatus(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimPrefix(r.URL.Path, "/v1/trust-status/")
	node, ok := s.graph.GetNode(graph.TrustDomain(domain))
	if !ok {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	neighbors := s.graph.GetNeighbors(graph.TrustDomain(domain))
	var activeCount, totalTrust float64
	for _, n := range neighbors {
		if n.Active {
			activeCount++
			totalTrust += n.TrustLevel
		}
	}
	var avgTrust float64
	if activeCount > 0 {
		avgTrust = totalTrust / activeCount
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"domain":             domain,
		"name":               node.Name,
		"active":             node.Active,
		"federation_count":   len(neighbors),
		"active_federations": activeCount,
		"average_trust":      avgTrust,
		"joined_at":          node.JoinedAt,
	})
}

func (s *Server) graphSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot := s.graph.Snapshot()
	jsonResponse(w, http.StatusOK, snapshot)
}

func (s *Server) save() {
	if s.store != nil {
		if err := s.store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to persist trust graph: %v\n", err)
		}
	}
}

func (s *Server) Serve(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

// keyRegistered reports whether pubKey is among the domain's registered keys.
func keyRegistered(registered [][]byte, pubKey []byte) bool {
	for _, k := range registered {
		if subtle.ConstantTimeCompare(k, pubKey) == 1 {
			return true
		}
	}
	return false
}

func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

var domainRegex = regexp.MustCompile("^[a-zA-Z0-9.-]+$")

func main() {
	addr := flag.String("addr", ":8085", "listen address")
	dataPath := flag.String("data", "trust_graph.json", "path to persist graph data")
	flag.Parse()

	srv := NewServer(*dataPath)
	fmt.Printf("Ovara Trust Server listening on %s\n", *addr)
	if err := srv.Serve(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}
