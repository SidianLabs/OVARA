package main

import (
	"log"

	"ovara.runtime.gateway/pkg/server"
)

func main() {
	if err := server.Run(""); err != nil {
		log.Fatal(err)
	}
}
