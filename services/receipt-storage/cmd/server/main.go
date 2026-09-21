package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ovara.services.receipt/internal/server"
	"ovara.services.receipt/internal/store"
)

func main() {
	addr := flag.String("addr", ":8082", "listen address")
	keyFlag := flag.String("key", "", "HMAC key for receipt signature verification (or OVARA_RECEIPT_HMAC_KEY)")
	tokensFlag := flag.String("tokens", "", "comma-separated bearer tokens for API auth (or OVARA_RECEIPT_TOKENS)")
	flag.Parse()

	key := *keyFlag
	if key == "" {
		key = os.Getenv("OVARA_RECEIPT_HMAC_KEY")
	}
	if key == "" {
		log.Println("WARNING: no HMAC key configured (-key flag or OVARA_RECEIPT_HMAC_KEY) — receipt signature verification is disabled")
	}

	tokens := *tokensFlag
	if tokens == "" {
		tokens = os.Getenv("OVARA_RECEIPT_TOKENS")
	}
	var tokenList []string
	for _, t := range strings.Split(tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokenList = append(tokenList, t)
		}
	}
	if len(tokenList) == 0 {
		log.Println("WARNING: no auth tokens configured (-tokens flag or OVARA_RECEIPT_TOKENS) — receipt-storage API is running in OPEN mode and accepts unauthenticated requests")
	}

	s := store.NewMemoryStore(0, []byte(key))
	srv := server.NewServer(*addr, s, tokenList...)

	go func() {
		log.Printf("receipt-storage server listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down")
	srv.Close()
}
