// Gateway-side oracle client (P2.3.3 AM-3).
//
// The oracle identity PIN authenticates WHICH oracle the gateway is
// talking to — independent of, and never substituted by, the checkpoint
// signature (WHO wrote the checkpoint) or the store's monotonicity
// (WHETHER it may advance). One protocol, two transports:
//
//	unix:///path — Tier 1: same kernel, separate UID. The pin is
//	    "uid:<n>"; verified against SO_PEERCRED on the socket —
//	    filesystem ownership is the trust boundary. Does NOT protect
//	    against root.
//	https://addr — Tier 2: remote oracle over mTLS. The pin is
//	    "key:<hex-ed25519-pub>"; the server certificate's public key
//	    must equal the pinned key — TLS terminates the identity check.
//
// Strict mode semantics live in the caller (server.go reconcile); the
// client just reports typed errors.
package anchor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

var (
	ErrPinMismatch   = errors.New("anchor: oracle identity mismatch (pin)")
	ErrUnavailable   = errors.New("anchor: oracle unavailable")
	ErrBadResponse   = errors.New("anchor: malformed oracle response")
	ErrUnauthorized  = errors.New("anchor: oracle rejected authentication")
	ErrOperatorToken = errors.New("anchor: operator token rejected")
)

// Querier is the read side — Latest for reconcile/status.
type Querier interface {
	Latest(ctx context.Context, domainID string) (*Checkpoint, error)
}

// Pusher is the write side — Commit for mutation-time anchoring.
type Pusher interface {
	Commit(ctx context.Context, domainID string, cp *Checkpoint) error
}

// Client is the gateway's oracle endpoint. Constructed via NewClient —
// the pin check happens on every connection, so a swapped oracle is
// detected even after a reconnect.
type Client struct {
	hc     *http.Client
	base   string // schemeless request base for http.NewRequest
	scheme string // "unix" or "https"
	pin    string // raw pin value for error context
	opTok  string // operator token for reset (optional)
}

// SelfSignedCert derives a TLS identity from an Ed25519 key — the
// certificate exists only to carry the public key; identity is the key,
// not the certificate's metadata (shared by oracle server and client).
func SelfSignedCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ovara-anchor"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("anchor cert: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// VerifyPeerPubKey returns a tls.Config.VerifyPeerCertificate callback
// that admits only peers whose leaf certificate carries an Ed25519
// public key in the authorized set — pin-based peer auth, no CA.
// Certificate validity dates are checked; the CA chain is deliberately
// not (the pin IS the trust decision for a dedicated oracle).
func VerifyPeerPubKey(authorized map[string]bool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("anchor: peer presented no certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("anchor: malformed peer certificate: %w", err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return errors.New("anchor: peer certificate expired or not yet valid")
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || !authorized[hex.EncodeToString(pub)] {
			return errors.New("anchor: peer public key not authorized")
		}
		return nil
	}
}

// NewClient builds a pin-checked client. url must be unix:///path or
// https://host:port. pin: "uid:<n>" for unix, "key:<hex>" for https.
// operatorToken may be "" (reset endpoint then unusable by this client).
// clientKey is the gateway's TLS identity for https (mutual pinning —
// the oracle authorizes the key); it is unused for unix.
func NewClient(url, pin, operatorToken string, clientKey ed25519.PrivateKey) (*Client, error) {
	c := &Client{pin: pin, opTok: operatorToken}
	switch {
	case strings.HasPrefix(url, "unix://"):
		sock := strings.TrimPrefix(url, "unix://")
		uid, err := parseUIDPin(pin)
		if err != nil {
			return nil, err
		}
		c.scheme = "unix"
		c.base = "http://anchor" // Host is irrelevant; path is the socket.
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "unix", sock)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
				}
				if err := verifyPeerUID(conn, uid); err != nil {
					conn.Close()
					return nil, err
				}
				return conn, nil
			},
		}
		c.hc = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	case strings.HasPrefix(url, "https://"):
		keyHex := strings.TrimPrefix(pin, "key:")
		pub, err := hex.DecodeString(keyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("anchor: https pin must be key:<32-byte-hex-ed25519-pub>")
		}
		if clientKey == nil {
			return nil, fmt.Errorf("anchor: https oracle requires a client key (gateway_anchor_key_file) — mutual pin auth")
		}
		ccert, err := SelfSignedCert(clientKey)
		if err != nil {
			return nil, err
		}
		c.scheme = "https"
		c.base = url
		tr := &http.Transport{
			// mTLS self-signed both directions: the pin IS the trust
			// decision — InsecureSkipVerify is intentional and bounded
			// by the explicit public-key comparison below; the oracle
			// symmetrically authorizes this client's leaf pubkey.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
				}
				tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
					Certificates: []tls.Certificate{ccert}})
				if err := tconn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, fmt.Errorf("%w: TLS: %v", ErrUnavailable, err)
				}
				peer := tconn.ConnectionState().PeerCertificates
				if len(peer) == 0 {
					raw.Close()
					return nil, fmt.Errorf("%w: oracle presented no certificate", ErrPinMismatch)
				}
				opk, ok := peer[0].PublicKey.(ed25519.PublicKey)
				if !ok || !bytes.Equal(opk, pub) {
					raw.Close()
					return nil, fmt.Errorf("%w: oracle key does not match pin", ErrPinMismatch)
				}
				return tconn, nil
			},
		}
		c.hc = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	default:
		return nil, fmt.Errorf("anchor: unsupported oracle url %q (want unix:// or https://)", url)
	}
	return c, nil
}

func parseUIDPin(pin string) (int, error) {
	if !strings.HasPrefix(pin, "uid:") {
		return -1, fmt.Errorf("anchor: unix pin must be uid:<n>")
	}
	var n int
	if _, err := fmt.Sscanf(pin, "uid:%d", &n); err != nil || n < 0 {
		return -1, fmt.Errorf("anchor: bad uid pin %q", pin)
	}
	return n, nil
}

func verifyPeerUID(conn net.Conn, want int) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: not a unix connection", ErrPinMismatch)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", err)
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", err)
	}
	if serr != nil {
		return fmt.Errorf("anchor: SO_PEERCRED: %w", serr)
	}
	if int(cred.Uid) != want {
		return fmt.Errorf("%w: peer uid %d, pinned %d", ErrPinMismatch, cred.Uid, want)
	}
	return nil
}

// errorResp is the oracle's uniform failure body.
type errorResp struct {
	Error string `json:"error"`
}

func statusError(code int, body []byte) error {
	var er errorResp
	msg := ""
	if json.Unmarshal(body, &er) == nil {
		msg = er.Error
	}
	switch code {
	case 401, 403:
		return fmt.Errorf("%w: %s", ErrUnauthorized, msg)
	case 404:
		return fmt.Errorf("%w (%s)", ErrDomainUnregistered, msg)
	case 409:
		return fmt.Errorf("%w (%s)", ErrEquivocation, msg)
	case 410:
		return fmt.Errorf("%w (%s)", ErrRegression, msg)
	case 412:
		return fmt.Errorf("%w (%s)", ErrBadKey, msg)
	case 423:
		return fmt.Errorf("%w (%s)", ErrDomainRegistered, msg)
	case 498:
		return fmt.Errorf("%w (%s)", ErrOperatorToken, msg)
	default:
		return fmt.Errorf("%w: status %d %s", ErrBadResponse, code, msg)
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if c.opTok != "" {
		req.Header.Set("X-Operator-Token", c.opTok)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrUnavailable) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != 200 {
		return statusError(resp.StatusCode, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%w: %v", ErrBadResponse, err)
		}
	}
	return nil
}

// registerReq is the domain-initialization request — genesis checkpoint
// + the pubkey that must have signed it.
type registerReq struct {
	Checkpoint *Checkpoint `json:"checkpoint"`
	PubKey     string      `json:"pubkey"`
	KeyID      string      `json:"key_id"`
}

// Register performs the one-time domain initialization (migration path).
// ErrDomainRegistered means someone got there first — fail closed, do
// not silently adopt existing state.
func (c *Client) Register(ctx context.Context, domain string, cp *Checkpoint, pub ed25519.PublicKey, keyID string) error {
	return c.do(ctx, "POST", "/v1/anchor/"+domain+"/register",
		&registerReq{Checkpoint: cp, PubKey: hex.EncodeToString(pub), KeyID: keyID}, nil)
}

// addKeyReq introduces a new lineage key under an existing key's
// authority (rotation grace).
type addKeyReq struct {
	PubKey        string `json:"pubkey"`
	KeyID         string `json:"key_id"`
	IntroducerSig string `json:"introducer_sig"`
}

func (c *Client) AddKey(ctx context.Context, domain string, newPub ed25519.PublicKey, newKeyID string, introducerPriv ed25519.PrivateKey) error {
	sig := ed25519.Sign(introducerPriv, KeyIntroMessage(domain, newKeyID, newPub))
	return c.do(ctx, "POST", "/v1/anchor/"+domain+"/keys",
		&addKeyReq{PubKey: hex.EncodeToString(newPub), KeyID: newKeyID,
			IntroducerSig: hex.EncodeToString(sig)}, nil)
}

func (c *Client) Latest(ctx context.Context, domain string) (*Checkpoint, error) {
	var cp Checkpoint
	if err := c.do(ctx, "GET", "/v1/anchor/"+domain, nil, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

func (c *Client) Commit(ctx context.Context, domain string, cp *Checkpoint) error {
	return c.do(ctx, "PUT", "/v1/anchor/"+domain, cp, nil)
}

// Reset deletes the domain's authoritative record — recovery operation.
// Requires the operator token presented at client construction.
func (c *Client) Reset(ctx context.Context, domain string) error {
	return c.do(ctx, "POST", "/v1/anchor/"+domain+"/reset", nil, nil)
}
