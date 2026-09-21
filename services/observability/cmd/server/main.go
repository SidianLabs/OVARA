package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ovara.services.observability/internal/server"
	"ovara.services.observability/internal/store"
)

func main() {
	addr := flag.String("addr", ":8084", "listen address")
	dataFile := flag.String("data", "", "path to JSONL data file for persistence")
	tokensFlag := flag.String("tokens", "", "comma-separated bearer tokens for API auth (or OVARA_OBSERVABILITY_TOKENS)")
	flag.Parse()

	tokens := *tokensFlag
	if tokens == "" {
		tokens = os.Getenv("OVARA_OBSERVABILITY_TOKENS")
	}
	var tokenList []string
	for _, t := range strings.Split(tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokenList = append(tokenList, t)
		}
	}
	if len(tokenList) == 0 {
		log.Println("WARNING: no auth tokens configured (-tokens flag or OVARA_OBSERVABILITY_TOKENS) — observability API is running in OPEN mode and accepts unauthenticated requests")
	}

	var s store.Store
	if *dataFile != "" {
		var err error
		s, err = store.NewFileStore(*dataFile, 0)
		if err != nil {
			log.Fatalf("failed to create file store: %v", err)
		}
	} else {
		s = store.NewMemoryStore(0)
	}
	srv := server.NewServer(*addr, s, tokenList...)

	go func() {
		log.Printf("observability server listening on %s", *addr)
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
