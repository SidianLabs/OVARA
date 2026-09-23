// signerd — approver-root signing service (C2-B A2 custody
// separation). Holds the approver private key on a host OUTSIDE the
// gateway trust domain. Gateways send canonical envelope payloads
// for signature; signerd authenticates the caller, verifies the
// claimed (domain, gateway, key) identity equals its own configured
// approver identity, signs, and returns the signature. The key never
// leaves this process — the gateway can request signatures but can
// never extract the root.
//
// Production deployments run this behind mTLS or place it inside a
// KMS/HSM — the wire contract is deliberately trivial so either works.
package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"ovara.runtime.gateway/internal/gwidentity"
)

type signRequest struct {
	Payload   string `json:"payload"`
	DomainID  string `json:"domain_id"`
	GatewayID string `json:"gateway_id"`
	KeyID     string `json:"key_id"`
}

func main() {
	var (
		listen  = flag.String("listen", "127.0.0.1:8488", "listen address")
		keyFile = flag.String("key-file", "", "approver private key file (ed25519)")
		token   = flag.String("token", "", "bearer token required on /sign")
		domain  = flag.String("domain", "", "domain id this service signs for")
		gwID    = flag.String("gateway-id", "approver", "principal id this service signs as")
		keyID   = flag.String("key-id", "", "key id this service signs as")
		pubHex  = flag.String("pubkey", "", "expected hex pubkey of key-file (pin check)")
	)
	flag.Parse()
	if *keyFile == "" || *token == "" || *domain == "" || *gwID == "" || *keyID == "" {
		fmt.Fprintln(os.Stderr, "signerd: --key-file --token --domain --gateway-id --key-id are all required")
		os.Exit(2)
	}
	priv, err := gwidentity.LoadOrCreateKey(*keyFile)
	if err != nil {
		log.Fatalf("signerd: load key: %v", err)
	}
	if *pubHex != "" && hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != *pubHex {
		log.Fatalf("signerd: key-file does not match pinned pubkey")
	}
	log.Printf("signerd listening on %s — signs as %s/%s in domain %s", *listen, *gwID, *keyID, *domain)

	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		fail := func(code int, msg string) {
			w.WriteHeader(code)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if r.Method != http.MethodPost {
			fail(http.StatusMethodNotAllowed, "POST only")
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(*token)) != 1 {
			fail(http.StatusUnauthorized, "bad token")
			return
		}
		var req signRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			fail(http.StatusBadRequest, "bad request")
			return
		}
		// identity pin: this service signs for exactly one identity —
		// a caller naming any other domain/principal/key is refused
		if req.DomainID != *domain || req.GatewayID != *gwID || req.KeyID != *keyID {
			fail(http.StatusForbidden, "identity mismatch")
			return
		}
		payload, err := hex.DecodeString(req.Payload)
		if err != nil || len(payload) == 0 {
			fail(http.StatusBadRequest, "bad payload")
			return
		}
		sig := ed25519.Sign(priv, payload)
		json.NewEncoder(w).Encode(map[string]string{"sig": hex.EncodeToString(sig)})
	})
	log.Fatal(http.ListenAndServe(*listen, nil))
}
