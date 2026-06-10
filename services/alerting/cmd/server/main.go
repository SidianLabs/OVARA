package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ovara.services.alerting/internal/engine"
	"ovara.services.alerting/internal/server"
	"ovara.services.alerting/internal/store"
)

func main() {
	addr := flag.String("addr", ":8083", "listen address")
	dataFile := flag.String("data", "", "path to JSONL data file for persistence")
	flag.Parse()

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
	srv := server.NewServer(*addr, e)

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
