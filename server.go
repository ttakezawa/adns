package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
)

func authoritativeMain(udpFd int, tcpFd int, udp int, tcp int) error {
	log.SetFlags(log.Flags() | log.Lshortfile)

	if (udpFd >= 0) == !(udp >= 0) {
		return newError("Select UDP as either udp or udpfd")
	}
	if (tcpFd >= 0) == !(tcp >= 0) {
		return newError("Select TCP as either tcp or tcpfd")
	}

	log.Printf("authoritative started pid:%d udpFd:%d tcpFd:%d", os.Getpid(), udpFd, tcpFd)

	var udpConn *net.UDPConn
	if udpFd >= 0 {
		conn, err := net.FileConn(os.NewFile(uintptr(udpFd), ""))
		if err != nil {
			return wrapError(err)
		}
		udpConn = conn.(*net.UDPConn)
	} else {
		addr := fmt.Sprintf("0.0.0.0:%d", udp)
		addr = "0.0.0.0:10053"
		laddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return wrapError(err)
		}
		udpConn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			return wrapError(err)
		}
	}

	for {
		msg := make([]byte, 512)
		n, remoteAddr, err := udpConn.ReadFrom(msg)
		if err != nil {
			return wrapError(err)
		}
		buf := bytes.NewBuffer(msg[0:n])
		go authoritativeHandleUDP(udpConn, &remoteAddr, buf)
	}

	return newError("must not come here")
}

func authoritativeHandleUDP(conn *net.UDPConn, remoteAddr *net.Addr, requestBuffer *bytes.Buffer) {
	log.Printf("Received: %s bytes\n", requestBuffer.Len())

	n, err := conn.WriteTo(requestBuffer.Bytes(), *remoteAddr)
	if err != nil {
		log.Print(err)
		runtime.Goexit()
	}
	log.Printf("Sent: %s bytes\n", n)
}
