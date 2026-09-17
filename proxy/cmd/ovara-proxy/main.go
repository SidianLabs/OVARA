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
	gw := gateway.New(cfg.GatewayURL, cfg.GatewayToken, cfg.Environment)
	bindings := creds.Load(cfg.Credentials)

	srv := proxy.New(rootCA, gw, bindings, chain, cfg.FailOpen)
	log.Printf("ovara executor proxy on %s (gateway=%s env=%s bindings=%d fail_open=%v)",
		cfg.ListenAddr, cfg.GatewayURL, cfg.Environment, len(bindings), cfg.FailOpen)
	log.Printf("CA cert: %s — install into agent trust store", cfg.CACertFile)
	log.Printf("receipt chain: %s (pubkey: %s)", cfg.ReceiptsFile, cfg.PubKeyFile)
	if err := http.ListenAndServe(cfg.ListenAddr, srv); err != nil {
		log.Fatal(err)
	}
}

func runVerify(path, pubHex string) {
	keyBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		if pubHex == "" {
			// Try sibling pubkey file convention
			data, err2 := os.ReadFile(path + ".pub")
			if err2 != nil {
				log.Fatalf("verify: provide -pubkey or a %s.pub file", path)
			}
			keyBytes, _ = hex.DecodeString(string(data))
		}
	}
	res := receipts.VerifyFile(path, ed25519.PublicKey(keyBytes))
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if !res.Valid {
		os.Exit(1)
	}
}
