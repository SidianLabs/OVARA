package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ovara.services.alerting/internal/engine"
	"ovara.services.alerting/internal/server"
	"ovara.services.alerting/internal/store"
)

func main() {
	addr := flag.String("addr", ":8083", "listen address")
	dataFile := flag.String("data", "", "path to JSONL data file for persistence")
	tokensFlag := flag.String("tokens", "", "comma-separated bearer tokens for API auth (or OVARA_ALERTING_TOKENS)")
	flag.Parse()

	tokens := *tokensFlag
	if tokens == "" {
		tokens = os.Getenv("OVARA_ALERTING_TOKENS")
	}
	var tokenList []string
	for _, t := range strings.Split(tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tokenList = append(tokenList, t)
		}
	}
	if len(tokenList) == 0 {
		log.Println("WARNING: no auth tokens configured (-tokens flag or OVARA_ALERTING_TOKENS) — alerting API is running in OPEN mode and accepts unauthenticated requests")
	}

	var s store.Store
	var err error

	if *dataFile != "" {
		s, err = store.NewFileStore(0, *dataFile)
		if err != nil {
			log.Fatalf("failed to create file store: %v", err)
		}
	} else {
		s = store.NewMemoryStore(0)
	}

	e := engine.New(s)
	srv := server.NewServer(*addr, e, tokenList...)

	go func() {
		log.Printf("alerting server listening on %s", *addr)
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
