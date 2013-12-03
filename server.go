package main

import (
	// "bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
)

func authoritativeMain(udpFd int, tcpFd int, udp int, tcp int) error {
	log.SetFlags(log.Flags() | log.Lshortfile)

	if udpFd < 0 && udp < 0 {
		return newError("Select UDP as udp or udpfd")
	}
	if tcpFd < 0 && tcp < 0 {
		// TODO
		//return newError("Select TCP as tcp or tcpfd")
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
		reqBytes := make([]byte, 512)
		n, remoteAddr, err := udpConn.ReadFrom(reqBytes)

		// NOTE: ここはエラーが出ても継続する
		// TODO: シグナル対応する
		if err != nil {
			log.Print(err)
			continue
		} else if n == 0 {
			log.Print("Received an empty request.")
			continue
		}
		go authoritativeHandleUDP(udpConn, &remoteAddr, reqBytes)
	}

	return newError("must not come here")
}

type dnsMessage struct {
	dnsHeader
	Question   []dnsQuestion
	Answer     []dnsRR
	Authority  []dnsRR
	Additional []dnsRR
}

type dnsHeader struct {
	Id uint16
	// Bits uint16
	QR     bool // Query or Response
	Opcode int  // OperationCode
	AA     bool // Authoritative Answer
	TC     bool // Truncated
	RD     bool // Recursion Desired
	RA     bool // Recursion Available
	Z      bool // Reserved for future use. Must be zero.
	Rcode  int  // Response code
	// Qdcount, Ancount, Nscount, Arcount uint16
}

type dnsQuestion struct {
	Qname  string
	Qtype  uint16
	Qclass uint16
}

type dnsRR struct {
	Name     string
	Type     uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    string
}

// func (msg *dnsMessage) Unpack(msg []byte) (err error) {
// }

func authoritativeHandleUDP(conn *net.UDPConn, remoteAddr *net.Addr, reqBytes []byte) {
	log.Printf("Received: %d bytes\n", len(reqBytes))

	n, err := conn.WriteTo(reqBytes, *remoteAddr)
	if err != nil {
		log.Print(err)
		runtime.Goexit()
	}
	log.Printf("Sent: %d bytes\n", n)
}
