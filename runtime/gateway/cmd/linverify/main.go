// linverify is the receiver-side verifier for OVARA action lineage:
// given a bundle, the receiving domain's pinned anchor, and (for the
// strongest check) the request it actually received, it runs the
// fail-closed offline verdict — no contact with the issuing domain.
//
//	linverify -bundle bundle.json -anchor anchor.json [-request request.json]
//
// stdout is the verdict JSON (accept / layer / detail / layers passed);
// exit 0 on accept, 1 on reject, 2 on usage or input errors.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"ovara.runtime.gateway/internal/lineage"
	"ovara.runtime.gateway/internal/models"
	"ovara.runtime.gateway/internal/revocation"
)

// anchorFile is the JSON form of lineage.Anchor: the pinned view of
// the issuing domain — public keys as hex, plus a revocation snapshot.
// Keys inside the bundle are never trusted; this file IS the trust.
type anchorFile struct {
	DomainID         string            `json:"domain_id"`
	GatewayKeys      map[string]string `json:"gateway_keys"`  // "gateway_id|key_id" → hex pub
	IssuerKeys       map[string]string `json:"issuer_keys"`   // issuer → hex pub
	ApproverKeys     map[string]string `json:"approver_keys"` // key_id → hex pub
	LedgerKeys       map[string]string `json:"ledger_keys"`   // ledger_domain → hex pub
	ExpectedAudience string            `json:"expected_audience,omitempty"`
	Revocations      []revocation.Pair `json:"revocations,omitempty"`
	Epoch            uint64            `json:"epoch,omitempty"`
}

func keys(in map[string]string) (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(in))
	for name, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: not hex ed25519 (%d bytes)", name, len(b))
		}
		out[name] = b
	}
	return out, nil
}

func main() {
	bundlePath := flag.String("bundle", "", "JSON lineage bundle (required)")
	anchorPath := flag.String("anchor", "", "JSON pinned anchor (required)")
	requestPath := flag.String("request", "", "JSON delivered request — enables VerifyDelivered (optional)")
	flag.Parse()
	if *bundlePath == "" || *anchorPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	read := func(path string, v any) {
		b, err := os.ReadFile(path)
		if err != nil {
			fatal("read %s: %v", path, err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			fatal("parse %s: %v", path, err)
		}
	}

	var b lineage.Bundle
	read(*bundlePath, &b)

	var af anchorFile
	read(*anchorPath, &af)
	a := &lineage.Anchor{DomainID: af.DomainID, ExpectedAudience: af.ExpectedAudience, Epoch: af.Epoch}
	var err error
	if a.GatewayKeys, err = keys(af.GatewayKeys); err != nil {
		fatal("anchor: %v", err)
	}
	if a.IssuerKeys, err = keys(af.IssuerKeys); err != nil {
		fatal("anchor: %v", err)
	}
	if a.ApproverKeys, err = keys(af.ApproverKeys); err != nil {
		fatal("anchor: %v", err)
	}
	if a.LedgerKeys, err = keys(af.LedgerKeys); err != nil {
		fatal("anchor: %v", err)
	}
	a.Revocations = make(map[revocation.Pair]bool, len(af.Revocations))
	for _, p := range af.Revocations {
		a.Revocations[p] = true
	}

	var v *lineage.Verdict
	if *requestPath != "" {
		var req models.ActionRequest
		read(*requestPath, &req)
		v = lineage.VerifyDelivered(&b, a, &req)
	} else {
		v = lineage.Verify(&b, a)
	}

	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
	if !v.Accept {
		os.Exit(1)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "linverify: "+format+"\n", args...)
	os.Exit(2)
}
