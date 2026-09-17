// Package ca maintains a per-installation root CA and mints leaf
// certificates per hostname for MITM interception. The CA certificate is
// distributed to the agent environment's trust store; the key never leaves
// the proxy host.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate loads a persisted CA or generates a new ECDSA P-256 root.
func LoadOrCreate(certFile, keyFile string) (*CA, error) {
	if cert, key, err := load(certFile, keyFile); err == nil {
		return &CA{cert: cert, key: key, cache: map[string]*tls.Certificate{}}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Ovara Proxy CA", Organization: []string{"Sidian Labs"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca := &CA{cert: cert, key: key, cache: map[string]*tls.Certificate{}}
	if err := ca.persist(certFile, keyFile); err != nil {
		return nil, err
	}
	return ca, nil
}

func load(certFile, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, nil, fmt.Errorf("bad CA cert PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kblk, _ := pem.Decode(keyPEM)
	if kblk == nil {
		return nil, nil, fmt.Errorf("bad CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (c *CA) persist(certFile, keyFile string) error {
	for _, f := range []string{certFile, keyFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return err
		}
	}
	der, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
	c.certPEM = certOut
	if err := os.WriteFile(certFile, certOut, 0o644); err != nil {
		return err
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(keyFile, keyOut, 0o600)
}

// CertPEM returns the CA certificate PEM for distribution to trust stores.
func (c *CA) CertPEM() []byte { return c.certPEM }

// CertFor returns a cached or freshly minted leaf certificate for host.
func (c *CA) CertFor(host string) (*tls.Certificate, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, ok := c.cache[host]; ok {
		return cert, nil
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &c.key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  c.key,
	}
	c.cache[host] = cert
	return cert, nil
}
