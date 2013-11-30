package main

import (
	"log"
	"os"
)

func authoritativeMain(udpFd int, tcpFd int) (err error) {
	log.Printf("authoritative started pid:%d udpFd:%d tcpFd:%d", os.Getpid(), udpFd, tcpFd)
	return
}
