package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ovara.services.approval/internal/server"
	"ovara.services.approval/internal/store"
)

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	tokensFlag := flag.String("tokens", "", "comma-separated bearer tokens for API auth (or OVARA_APPROVAL_TOKENS)")
	flag.Parse()

	tokens := *tokensFlag
	if tokens == "" {
		tokens = os.Getenv("OVARA_APPROVAL_TOKENS")
	}
	var tokenList []string
	for _, t := range strings.Split(tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokenList = append(tokenList, t)
		}
	}
	if len(tokenList) == 0 {
		log.Println("WARNING: no auth tokens configured (-tokens flag or OVARA_APPROVAL_TOKENS) — approval API is running in OPEN mode and accepts unauthenticated requests")
	}

	s := store.NewMemoryStore(0)
	srv := server.NewServer(*addr, s, tokenList...)

	go func() {
		log.Printf("approval server listening on %s", *addr)
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
