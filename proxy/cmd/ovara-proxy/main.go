package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ovara.proxy/internal/ca"
	"ovara.proxy/internal/config"
	"ovara.proxy/internal/creds"
	"ovara.proxy/internal/gateway"
	"ovara.proxy/internal/proxy"
	"ovara.proxy/internal/receipts"
)

func main() {
	configPath := flag.String("config", "etc/proxy.json", "path to proxy config")
	verifyFile := flag.String("verify", "", "verify a receipt chain file and exit")
	pubKeyHex := flag.String("pubkey", "", "hex ed25519 public key for -verify")
	flag.Parse()

	if *verifyFile != "" {
		runVerify(*verifyFile, *pubKeyHex)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	rootCA, err := ca.LoadOrCreate(cfg.CACertFile, cfg.CAKeyFile)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	chain, err := receipts.LoadOrCreate(cfg.ReceiptsFile, cfg.ReceiptKeyFile, cfg.PubKeyFile)
	if err != nil {
		log.Fatalf("receipts: %v", err)
	}
	// External anchoring, env-configured: OVARA_ANCHOR_FILE (default
	// var/anchors.jsonl), OVARA_ANCHOR_URL (optional POST sink),
	// OVARA_ANCHOR_EVERY (default 1 = anchor every receipt).
	anchorFile := os.Getenv("OVARA_ANCHOR_FILE")
	if anchorFile == "" {
		anchorFile = "var/anchors.jsonl"
	}
	anchorEvery, _ := strconv.Atoi(os.Getenv("OVARA_ANCHOR_EVERY"))
	chain.SetAnchoring(anchorFile, os.Getenv("OVARA_ANCHOR_URL"), anchorEvery)
	log.Printf("anchoring chain head to %s (every=%d url=%q)", anchorFile, max(anchorEvery, 1), os.Getenv("OVARA_ANCHOR_URL"))
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	bindings := creds.Load(cfg.Credentials)

	srv := proxy.New(rootCA, gw, bindings, chain, cfg.FailOpen)
	srv.SetEscalateWindow(time.Duration(cfg.EscalateTimeoutSec)*time.Second, time.Duration(cfg.EscalatePollSec)*time.Second)
	if cfg.GitGate != nil {
		srv.SetGitGate(*cfg.GitGate)
	}
	srv.SetSensitiveHosts(cfg.SensitiveHosts)
	srv.SetClientAuth(cfg.AgentToken)
	log.Printf("ovara executor proxy on %s (gateway=%s env=%s bindings=%d fail_open=%v client_auth=%v)",
		cfg.ListenAddr, cfg.GatewayURL, cfg.Environment, len(bindings), cfg.FailOpen, cfg.AgentToken != "")
	log.Printf("CA cert: %s — install into agent trust store", cfg.CACertFile)
	log.Printf("receipt chain: %s (pubkey: %s)", cfg.ReceiptsFile, cfg.PubKeyFile)
	if err := http.ListenAndServe(cfg.ListenAddr, srv); err != nil {
		log.Fatal(err)
	}
}

func runVerify(path, pubHex string) {
	keyBytes, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		// Sibling pubkey conventions: <chain>.pub, or the init layout
		// (receipt_pubkey.hex beside the chain file).
		for _, f := range []string{path + ".pub", filepath.Join(filepath.Dir(path), "receipt_pubkey.hex")} {
			if data, err2 := os.ReadFile(f); err2 == nil {
				keyBytes, _ = hex.DecodeString(strings.TrimSpace(string(data)))
				if len(keyBytes) == ed25519.PublicKeySize {
					break
				}
			}
		}
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		log.Fatalf("verify: provide -pubkey or a pubkey file beside %s", path)
	}
	res := receipts.VerifyFile(path, ed25519.PublicKey(keyBytes))
	// If anchors exist (OVARA_ANCHOR_FILE, or the default sink beside the
	// chain file), verify each anchor's head against the recomputed chain
	// head at that sequence.
	anchorPath := os.Getenv("OVARA_ANCHOR_FILE")
	if anchorPath == "" {
		anchorPath = filepath.Join(filepath.Dir(path), "anchors.jsonl")
	}
	if _, err := os.Stat(anchorPath); err == nil {
		res = receipts.VerifyAnchorFile(anchorPath, path, ed25519.PublicKey(keyBytes))
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if !res.Valid {
		os.Exit(1)
	}
}
