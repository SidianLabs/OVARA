// ovara-anchor — the P2.3.3 monotonic checkpoint oracle.
//
// A standalone authority service: signed checkpoints in, compare-and-
// store out. Generic — it knows domains, sequences, tip hashes, and
// signature lineage; it knows NOTHING about gateways, grants, or keys
// beyond "pubkey in lineage".
//
// Two deployment tiers, one protocol and one security model:
//
//	--listen unix:///run/ovara-anchor/sock   Tier 1: same kernel,
//	    separate UID; the socket file's ownership is the channel-
//	    authentication boundary. Does NOT protect against root.
//	--listen https://:9443 --key FILE        Tier 2: remote oracle,
//	    self-signed Ed25519 cert pinned client-side.
//
// Authority-recovery operations (reset) require the operator token, read
// from --operator-token-file (owner-only) or OVARA_ANCHOR_OPERATOR_TOKEN.
// It is never taken on the command line: every local user can read a
// process's argv.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ovara.runtime.gateway/internal/anchor"
	"ovara.runtime.gateway/internal/gwidentity"
)

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ovara-anchor: "+format+"\n", a...)
	os.Exit(1)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// mapErr translates store errors to wire status codes — the client
// maps them back to the same typed errors.
func mapErr(err error) int {
	switch {
	case errors.Is(err, anchor.ErrDomainUnregistered):
		return 404
	case errors.Is(err, anchor.ErrDomainRegistered):
		return 423
	case errors.Is(err, anchor.ErrRegression):
		return 410
	case errors.Is(err, anchor.ErrEquivocation):
		return 409
	case errors.Is(err, anchor.ErrBadKey), errors.Is(err, anchor.ErrBadSignature):
		return 412
	case errors.Is(err, anchor.ErrMalformed):
		return 400
	default:
		return 500
	}
}

// loadClientKeys reads the authorized client-key file: one hex-encoded
// ed25519 public key per line (# comments and blank lines ignored).
// An empty file is a startup failure — the oracle would serve nobody,
// which is almost always operator error, and fail-closed is safer.
func loadClientKeys(path string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client-keys: %w", err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, err := hex.DecodeString(line)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("client-keys line %d: want 32-byte hex ed25519 pubkey", i+1)
		}
		out[line] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("client-keys %s: no authorized keys", path)
	}
	return out, nil
}

// operatorTokenEnv is where the reset token may come from instead of a file.
const operatorTokenEnv = "OVARA_ANCHOR_OPERATOR_TOKEN"

// loadOperatorToken returns the reset token from file (which must not be
// readable by group or other) or, failing that, from the environment. ""
// means reset is disabled.
func loadOperatorToken(file string) (string, error) {
	if file != "" {
		fi, err := os.Stat(file)
		if err != nil {
			return "", fmt.Errorf("operator token file: %w", err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("operator token file %s is readable by other users (%#o): chmod 600 it", file, fi.Mode().Perm())
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("operator token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("operator token file %s is empty", file)
		}
		return tok, nil
	}
	return strings.TrimSpace(os.Getenv(operatorTokenEnv)), nil
}

// operatorTokenOK compares in constant time: timing must not reveal how
// much of a guessed token was right.
func operatorTokenOK(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func main() {
	store := flag.String("store", "", "oracle store file (required)")
	listen := flag.String("listen", "", "unix:///path or https://addr:port (required)")
	keyFile := flag.String("key", "", "ed25519 key file (required for https)")
	clientKeys := flag.String("client-keys", "", "file of authorized client pubkeys, one hex per line (required for https)")
	opTokFile := flag.String("operator-token-file", "", "owner-only file holding the token required for reset (or set "+operatorTokenEnv+")")
	legacyTok := flag.String("operator-token", "", "no longer accepted: use --operator-token-file or "+operatorTokenEnv)
	flag.Parse()
	if *store == "" || *listen == "" {
		fatal("--store and --listen are required")
	}
	if *legacyTok != "" {
		fatal("--operator-token is no longer accepted (any local user can read a command line): put the token in an owner-only file and pass --operator-token-file, or set %s", operatorTokenEnv)
	}
	opTok, err := loadOperatorToken(*opTokFile)
	if err != nil {
		fatal("%v", err)
	}
	os.Unsetenv(operatorTokenEnv)

	st, err := anchor.OpenStore(*store)
	if err != nil {
		fatal("%v", err)
	}
	defer st.Close()

	srv := &http.Server{Handler: newHandler(st, opTok), ReadHeaderTimeout: 10 * time.Second}
	serve(srv, *listen, *store, *keyFile, *clientKeys)
}

// newHandler serves the oracle protocol over st. opTok authorizes reset;
// "" disables it.
func newHandler(st *anchor.Store, opTok string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/anchor/", func(w http.ResponseWriter, r *http.Request) {
		// /v1/anchor/{domain}[/register|/keys|/reset]
		rest := strings.TrimPrefix(r.URL.Path, "/v1/anchor/")
		parts := strings.SplitN(rest, "/", 2)
		domain := parts[0]
		op := ""
		if len(parts) == 2 {
			op = parts[1]
		}
		switch {
		case r.Method == "GET" && op == "":
			cp, err := st.Latest(domain)
			if err != nil {
				writeErr(w, mapErr(err), err)
				return
			}
			json.NewEncoder(w).Encode(cp)
		case r.Method == "PUT" && op == "":
			var cp anchor.Checkpoint
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cp); err != nil {
				writeErr(w, 400, fmt.Errorf("malformed checkpoint body"))
				return
			}
			if err := st.Commit(domain, &cp); err != nil {
				writeErr(w, mapErr(err), err)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case r.Method == "POST" && op == "register":
			var req struct {
				Checkpoint *anchor.Checkpoint `json:"checkpoint"`
				PubKey     string             `json:"pubkey"`
				KeyID      string             `json:"key_id"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Checkpoint == nil {
				writeErr(w, 400, fmt.Errorf("malformed register body"))
				return
			}
			pub, err := hex.DecodeString(req.PubKey)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				writeErr(w, 400, fmt.Errorf("bad pubkey"))
				return
			}
			if err := st.Register(domain, req.Checkpoint, ed25519.PublicKey(pub), req.KeyID); err != nil {
				writeErr(w, mapErr(err), err)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
		case r.Method == "POST" && op == "keys":
			var req struct {
				PubKey        string `json:"pubkey"`
				KeyID         string `json:"key_id"`
				IntroducerSig string `json:"introducer_sig"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
				writeErr(w, 400, fmt.Errorf("malformed key body"))
				return
			}
			pub, perr := hex.DecodeString(req.PubKey)
			sig, serr := hex.DecodeString(req.IntroducerSig)
			if perr != nil || len(pub) != ed25519.PublicKeySize || serr != nil {
				writeErr(w, 400, fmt.Errorf("bad key introduction"))
				return
			}
			if err := st.AddKey(domain, ed25519.PublicKey(pub), req.KeyID, sig); err != nil {
				writeErr(w, mapErr(err), err)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "key-added"})
		case r.Method == "POST" && op == "reset":
			if !operatorTokenOK(opTok, r.Header.Get("X-Operator-Token")) {
				writeErr(w, 498, fmt.Errorf("operator token rejected"))
				return
			}
			if err := st.Reset(domain); err != nil {
				writeErr(w, mapErr(err), err)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
		default:
			writeErr(w, 405, fmt.Errorf("unsupported operation"))
		}
	})
	return mux
}

func serve(srv *http.Server, listen, store, keyFile, clientKeys string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	switch {
	case strings.HasPrefix(listen, "unix://"):
		sock := strings.TrimPrefix(listen, "unix://")
		os.Remove(sock)
		l, err := net.Listen("unix", sock)
		if err != nil {
			fatal("listen %s: %v", sock, err)
		}
		// 0660 — the socket's owner/group IS the tier-1 channel
		// authentication boundary; the client verifies peer UID.
		if err := os.Chmod(sock, 0660); err != nil {
			fatal("chmod %s: %v", sock, err)
		}
		fmt.Fprintf(os.Stderr, "ovara-anchor: unix://%s store=%s\n", sock, store)
		if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
			fatal("serve: %v", err)
		}
	case strings.HasPrefix(listen, "https://"):
		if keyFile == "" {
			fatal("--key is required for https listen")
		}
		if clientKeys == "" {
			fatal("--client-keys is required for https listen (file of authorized client ed25519 pubkeys, one hex per line) — an oracle must never serve unauthenticated network clients")
		}
		priv, err := gwidentity.LoadOrCreateKey(keyFile)
		if err != nil {
			fatal("%v", err)
		}
		cert, err := anchor.SelfSignedCert(priv)
		if err != nil {
			fatal("%v", err)
		}
		authorized, err := loadClientKeys(clientKeys)
		if err != nil {
			fatal("%v", err)
		}
		addr := strings.TrimPrefix(listen, "https://")
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fatal("listen %s: %v", addr, err)
		}
		// Mutual pinning: the client pins the oracle's pubkey; the oracle
		// requires a client certificate and authorizes its leaf pubkey
		// against --client-keys. RequireAnyClientCert + explicit pubkey
		// check — no CA involved, "any cert" is never trusted.
		srv.TLSConfig = &tls.Config{
			Certificates:          []tls.Certificate{cert},
			MinVersion:            tls.VersionTLS12,
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: anchor.VerifyPeerPubKey(authorized),
		}
		fmt.Fprintf(os.Stderr, "ovara-anchor: https://%s store=%s pub=%s clients=%d\n",
			addr, store, hex.EncodeToString(priv.Public().(ed25519.PublicKey)), len(authorized))
		if err := srv.ServeTLS(l, "", ""); err != nil && err != http.ErrServerClosed {
			fatal("serve: %v", err)
		}
	default:
		fatal("--listen must be unix:///path or https://addr:port")
	}
}
