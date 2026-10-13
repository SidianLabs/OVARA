package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestNewCAIsConstrainedAndShortLived(t *testing.T) {
	c, _, keyFile := newCA(t)
	cert := c.cert
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Fatalf("CA must have path length 0: valid=%v isCA=%v maxPathLen=%d zero=%v",
			cert.BasicConstraintsValid, cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("CA key usage = %v", cert.KeyUsage)
	}
	if life := time.Until(cert.NotAfter); life > 31*24*time.Hour || life < 29*24*time.Hour {
		t.Fatalf("CA lifetime %v, want about 30 days", life)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("CA key mode = %v (%v)", fi.Mode().Perm(), err)
		}
	}

	leafTLS, err := c.CertFor("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafTLS.Certificate[0])
	if span := leaf.NotAfter.Sub(leaf.NotBefore); span > 24*time.Hour {
		t.Fatalf("leaf valid for %v, want at most 24h", span)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.IsCA {
		t.Fatalf("leaf EKU %v isCA %v", leaf.ExtKeyUsage, leaf.IsCA)
	}
	// A sub-CA signed by this CA must not verify.
	subKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sub"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, c.cert, &subKey.PublicKey, c.key)
	sub, _ := x509.ParseCertificate(subDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), DNSNames: []string{"x.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, sub, &subKey.PublicKey, subKey)
	l2, _ := x509.ParseCertificate(leafDER)
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(c.cert)
	inter.AddCert(sub)
	if _, err := l2.Verify(x509.VerifyOptions{DNSName: "x.example", Roots: roots, Intermediates: inter}); err == nil {
		t.Fatal("a chain through an intermediate minted by the CA verified")
	}
}

// writeCA persists a CA built from tmpl, as an older version would have.
func writeCA(t *testing.T, tmpl *x509.Certificate) (string, string, *x509.Certificate) {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o644)
	cert, _ := x509.ParseCertificate(der)
	return certFile, keyFile, cert
}

func TestLoadOrCreateRotatesWeakOrExpiringCA(t *testing.T) {
	now := time.Now()
	base := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ovara Proxy CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
	}
	old := base() // what earlier versions wrote: ten years, no path limit
	old.NotAfter = now.Add(10 * 365 * 24 * time.Hour)
	old.MaxPathLenZero = false
	old.MaxPathLen = -1
	old.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	expired := base()
	expired.NotBefore, expired.NotAfter = now.Add(-40*24*time.Hour), now.Add(-time.Hour)
	expiring := base()
	expiring.NotAfter = now.Add(2 * 24 * time.Hour)

	for name, tmpl := range map[string]*x509.Certificate{"legacy": old, "expired": expired, "expiring": expiring} {
		certFile, keyFile, prev := writeCA(t, tmpl)
		c, err := LoadOrCreate(certFile, keyFile)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.cert.Equal(prev) {
			t.Errorf("%s: CA was not replaced", name)
			continue
		}
		if !c.cert.MaxPathLenZero || time.Until(c.cert.NotAfter) < 29*24*time.Hour {
			t.Errorf("%s: replacement is not a fresh constrained CA", name)
		}
		// The files hold the new pair.
		again, err := LoadOrCreate(certFile, keyFile)
		if err != nil || !again.cert.Equal(c.cert) {
			t.Errorf("%s: reload after rotation: %v", name, err)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(keyFile); fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: rotated key mode %v", name, fi.Mode().Perm())
			}
		}
	}

	// A current, constrained CA is kept.
	certFile, keyFile, prev := writeCA(t, base())
	c, err := LoadOrCreate(certFile, keyFile)
	if err != nil || !c.cert.Equal(prev) {
		t.Fatalf("a valid CA was replaced (err %v)", err)
	}
}

// A leaf never outlives the CA that signed it.
func TestLeafCappedAtCAExpiry(t *testing.T) {
	c, _, _ := newCA(t)
	c.cert.NotAfter = time.Now().Add(2 * time.Hour)
	leafTLS, err := c.CertFor("cap.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if leafTLS.Leaf.NotAfter.After(c.cert.NotAfter) {
		t.Fatalf("leaf %v outlives CA %v", leafTLS.Leaf.NotAfter, c.cert.NotAfter)
	}
}
