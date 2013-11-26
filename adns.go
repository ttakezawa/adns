package main

import (
	"log"
)

func main() {
	log.Println("started")
	defer log.Println("stopped")
}
