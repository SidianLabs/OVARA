package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ovara.services.observability/internal/server"
	"ovara.services.observability/internal/store"
)

func main() {
	addr := flag.String("addr", ":8084", "listen address")
	flag.Parse()

	s := store.NewMemoryStore(0)
	srv := server.NewServer(*addr, s)

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
