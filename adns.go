package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var (
		isRecursive     = flag.Bool("recursive", false, "Recursive Server")
		isAuthoritative = flag.Bool("authoritative", false, "Authoritative Server")
		tcpFd           = flag.Int("tcpfd", -1, "TCP File Discriptor")
		udpFd           = flag.Int("udpfd", -1, "UDP File Discriptor")
	)

	flag.Parse()
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(1)
	}

	if (*isRecursive && *isAuthoritative) || (!*isRecursive && !*isAuthoritative) {
		fmt.Fprintln(os.Stderr, "Select either recursive or authoritative")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	if *isRecursive {
		// err = adns.RecursiveMain(udpFd, tcpFd)
	}
	if *isAuthoritative {
		err = authoritativeMain(*udpFd, *tcpFd)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	log.Println("exited")
}
