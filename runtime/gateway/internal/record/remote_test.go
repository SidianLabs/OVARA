// C2-B A2 contract test: remote signing path — the gateway delegates
// envelope signatures to an off-box service holding the approver key.
package record

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeSignerd implements the wire contract: token auth + identity pin.
func fakeSignerd(t *testing.T, priv ed25519.PrivateKey, domain, gw, kid, token string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(msg string) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			fail("bad token")
			return
		}
		var req struct {
			Payload   string `json:"payload"`
			DomainID  string `json:"domain_id"`
			GatewayID string `json:"gateway_id"`
			KeyID     string `json:"key_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			fail("bad request")
			return
		}
		if req.DomainID != domain || req.GatewayID != gw || req.KeyID != kid {
			fail("identity mismatch")
			return
		}
		payload, _ := hex.DecodeString(req.Payload)
		json.NewEncoder(w).Encode(map[string]string{"sig": hex.EncodeToString(ed25519.Sign(priv, payload))})
	}))
}

func TestRemoteSigner_EndToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	srv := fakeSignerd(t, priv, "dom-r", "approver", "apk1", "tok")
	defer srv.Close()

	signer := NewRemoteSigner("dom-r", "approver", "apk1",
		HTTPSigner(srv.URL, "tok", "dom-r", "approver", "apk1"))
	resolve := func(gw, kid string) (ed25519.PublicKey, error) {
		if gw != "approver" || kid != "apk1" {
			return nil, errTestNoKey
		}
		return pub, nil
	}

	dir := t.TempDir()
	path := dir + "/j.jsonl"
	j, err := Open("approval", path, "dom-r", signer, resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	seq, tip, err := j.Append("approval", "rec1", json.RawMessage(`{"a":1}`), nil)
	if err != nil {
		t.Fatalf("remote-signed append: %v", err)
	}
	j.Close()

	// reopen: the remotely-signed record must verify under the pub
	j2, err := Open("approval", path, "dom-r", signer, resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatalf("reopen with remote-signed record: %v", err)
	}
	gotSeq, gotTip := j2.Tip()
	if gotSeq != seq || gotTip != tip {
		t.Fatalf("tip mismatch after remote-signing reopen: %d/%s vs %d/%s", gotSeq, gotTip, seq, tip)
	}
	j2.Close()
}

func TestRemoteSigner_RefusedFailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	// signerd pins a DIFFERENT identity — the gateway's claimed
	// (domain, gw, kid) won't match → every sign call refused
	srv := fakeSignerd(t, priv, "dom-other", "approver", "apk9", "tok")
	defer srv.Close()

	signer := NewRemoteSigner("dom-r", "approver", "apk1",
		HTTPSigner(srv.URL, "tok", "dom-r", "approver", "apk1"))
	resolve := func(gw, kid string) (ed25519.PublicKey, error) { return pub, nil }

	dir := t.TempDir()
	j, err := Open("approval", dir+"/j.jsonl", "dom-r", signer, resolve, Floor{}, func(*Envelope) error { return nil })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer j.Close()
	if _, _, err := j.Append("approval", "rec1", json.RawMessage(`{"a":1}`), nil); err == nil {
		t.Fatal("remote-refused append succeeded — the journal wrote an unsigned record")
	}
}

var errTestNoKey = testErr("no key")

type testErr string

func (e testErr) Error() string { return string(e) }
