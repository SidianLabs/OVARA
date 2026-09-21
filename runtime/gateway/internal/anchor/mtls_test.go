package anchor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

// F-B1: Tier-2 mutual pinning — the oracle must deny any TLS client
// whose leaf pubkey is not in the authorized set, and the client must
// deny any oracle whose pubkey doesn't match the pin.

func tlsClientWith(t *testing.T, cert tls.Certificate, serverName string) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
	}}
}

func startAuthServer(t *testing.T, serverKey ed25519.PrivateKey, authorized map[string]bool) (addr string, cleanup func()) {
	t.Helper()
	sc, err := SelfSignedCert(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}), TLSConfig: &tls.Config{
		Certificates:          []tls.Certificate{sc},
		MinVersion:            tls.VersionTLS12,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: VerifyPeerPubKey(authorized),
	}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(l, "", "")
	return l.Addr().String(), func() { srv.Close(); l.Close() }
}

func selfSignedWith(t *testing.T, priv ed25519.PrivateKey, notAfter time.Time) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "c"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func TestMutualPinAuth(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	clientKey := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	clientPub := hex.EncodeToString(clientKey.Public().(ed25519.PublicKey))
	authorized := map[string]bool{clientPub: true}
	addr, done := startAuthServer(t, serverKey, authorized)
	defer done()
	url := "https://" + addr

	dial := func(hc *http.Client) error {
		r, err := hc.Get(url + "/v1/anchor/d")
		if err != nil {
			return err
		}
		r.Body.Close()
		return nil
	}

	// no client certificate → handshake denied
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if err := dial(hc); err == nil {
		t.Fatal("no-cert client must be denied")
	}
	// unauthorized client key (self-signed, wrong pubkey) → denied
	wrongKey := ed25519.NewKeyFromSeed(append(make([]byte, 31), 9))
	wc := selfSignedWith(t, wrongKey, time.Now().Add(time.Hour))
	if err := dial(tlsClientWith(t, wc, addr)); err == nil {
		t.Fatal("unauthorized client key must be denied")
	}
	// expired client cert → denied
	ec := selfSignedWith(t, clientKey, time.Now().Add(-time.Hour))
	if err := dial(tlsClientWith(t, ec, addr)); err == nil {
		t.Fatal("expired client cert must be denied")
	}
	// authorized client key → allowed
	gc := selfSignedWith(t, clientKey, time.Now().Add(time.Hour))
	if err := dial(tlsClientWith(t, gc, addr)); err != nil {
		t.Fatalf("authorized client denied: %v", err)
	}
}

func TestClientRejectsWrongOracle(t *testing.T) {
	// NewClient requires a client key for https — fail closed when absent.
	if _, err := NewClient("https://127.0.0.1:1", "key:"+hex.EncodeToString(make([]byte, 32)), "", nil); err == nil {
		t.Fatal("https client without client key must fail")
	}
	// pin mismatch: real server key ≠ pinned key
	serverKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	clientKey := ed25519.NewKeyFromSeed(append(make([]byte, 31), 1))
	authorized := map[string]bool{hex.EncodeToString(clientKey.Public().(ed25519.PublicKey)): true}
	addr, done := startAuthServer(t, serverKey, authorized)
	defer done()
	otherPub := hex.EncodeToString(ed25519.NewKeyFromSeed(append(make([]byte, 31), 5)).Public().(ed25519.PublicKey))
	c, err := NewClient("https://"+addr, "key:"+otherPub, "", clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Latest(context.Background(), "dom_x"); err == nil {
		t.Fatal("oracle with wrong pubkey must be rejected by pin")
	}
	// correct pin → reaches the handler (404 unregistered expected)
	goodPub := hex.EncodeToString(serverKey.Public().(ed25519.PublicKey))
	c2, err := NewClient("https://"+addr, "key:"+goodPub, "", clientKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c2.Latest(context.Background(), "dom_x")
	if err == nil {
		t.Fatal("expected error response")
	}
}
