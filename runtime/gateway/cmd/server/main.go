package main

import (
	"log"

	"ovara.runtime.gateway/server"
)

func main() {
	if err := server.Run(""); err != nil {
		log.Fatal(err)
	}
}
