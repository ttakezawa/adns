package main

import (
	"flag"
	"fmt"
	"os"
        "runtime"
)

func main() {
	var (
		isRecursive     = flag.Bool("recursive", false, "Recursive Server")
		isAuthoritative = flag.Bool("authoritative", false, "Authoritative Server")
		tcpFd           = flag.Int("tcpfd", -1, "TCP File Discriptor")
		udpFd           = flag.Int("udpfd", -1, "UDP File Discriptor")
		tcp             = flag.Int("tcp", -1, "TCP")
		udp             = flag.Int("udp", -1, "UDP")
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
	switch {
	case *isRecursive:
		// err = recursiveMain(*udpFd, *tcpFd, *udp, *tcp)
	case *isAuthoritative:
		err = authoritativeMain(*udpFd, *tcpFd, *udp, *tcp)
	default:
		panic("must not come here")
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("Main Goroutine exit")
}

func init() {
        runtime.GOMAXPROCS(runtime.NumCPU())
}

