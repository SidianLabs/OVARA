package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func newCA(t *testing.T) (*CA, string, string) {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	keyFile := filepath.Join(dir, "ca.key")
	c, err := LoadOrCreate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return c, certFile, keyFile
}

func TestLoadOrCreateGeneratesValidCA(t *testing.T) {
	c, certFile, keyFile := newCA(t)
	if c.cert == nil || c.key == nil {
		t.Fatal("expected cert and key")
	}
	if !c.cert.IsCA {
		t.Fatal("cert is not a CA")
	}
	if len(c.CertPEM()) == 0 {
		t.Fatal("CertPEM empty")
	}
	if _, err := x509.ParseCertificate(c.cert.Raw); err != nil {
		t.Fatalf("unparseable CA cert: %v", err)
	}
	for _, f := range []string{certFile, keyFile} {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatalf("persisted file %s missing: %v", f, err)
		}
		if info.Size() == 0 {
			t.Fatalf("persisted file %s empty", f)
		}
	}
}

func TestCertForLeafVerifies(t *testing.T) {
	c, _, _ := newCA(t)
	leaf, err := c.CertFor("api.example.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	found := false
	for _, d := range parsed.DNSNames {
		if d == "api.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf missing SAN for host: %v", parsed.DNSNames)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	if _, err := parsed.Verify(x509.VerifyOptions{
		DNSName: "api.example.com",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
}

func TestCertForStripsPortAndCaches(t *testing.T) {
	c, _, _ := newCA(t)
	a, err := c.CertFor("api.example.com:443")
	if err != nil {
		t.Fatalf("CertFor with port: %v", err)
	}
	b, err := c.CertFor("api.example.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	if a != b {
		t.Fatal("expected cached cert for same host")
	}
}

func TestCertForIPHost(t *testing.T) {
	c, _, _ := newCA(t)
	leaf, err := c.CertFor("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	if len(parsed.IPAddresses) == 0 || parsed.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("expected IP SAN 127.0.0.1, got %v", parsed.IPAddresses)
	}
	roots := x509.NewCertPool()
	roots.AddCert(c.cert)
	if _, err := parsed.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: roots}); err != nil {
		t.Fatalf("IP leaf verify: %v", err)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	c1, certFile, keyFile := newCA(t)
	c2, err := LoadOrCreate(certFile, keyFile)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !c1.cert.Equal(c2.cert) {
		t.Fatal("reloaded CA cert differs")
	}
	// leaf minted by reloaded CA must still verify against original cert
	leaf, err := c2.CertFor("rt.example.com")
	if err != nil {
		t.Fatalf("CertFor after reload: %v", err)
	}
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(c1.cert)
	if _, err := parsed.Verify(x509.VerifyOptions{DNSName: "rt.example.com", Roots: roots}); err != nil {
		t.Fatalf("post-reload leaf verify: %v", err)
	}
}
