package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
)

var ()

type any interface{}

type dnsMessage struct {
	Header     dnsHeader
	Question   []dnsQuestion
	Answer     []dnsRR
	Authority  []dnsRR
	Additional []dnsRR
}

type dnsHeader struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
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

func readUint16(buf *bytes.Buffer) (i uint16, err error) {
	uint16bytes := make([]byte, 2)
	n, err := buf.Read(uint16bytes)
	if err != nil || n != 2 {
		return
	}
	i = binary.BigEndian.Uint16(uint16bytes)
	return
}

// construct dnsMessage
func NewDnsMessage(data *bytes.Buffer) (msg *dnsMessage, err error) {
	msg = &dnsMessage{}
	err = msg.Unpack(data)
	return
}
func (msg *dnsMessage) Unpack(data *bytes.Buffer) (err error) {
	// unpack dnsHeader
	err = binary.Read(data, binary.BigEndian, &msg.Header)
	if err != nil {
		return
	}

	// label, err := data.ReadByte()
	// log.Printf("label:%#v err:%#v\n", label, err)

	// unpack Question
	msg.Question = make([]dnsQuestion, msg.Header.Qdcount)

	for i := uint16(0); i < msg.Header.Qdcount; i++ {
		name := ""
		for {
			// read labelsize
			labelsize, err := data.ReadByte()
			if err != nil {
				return err
			}
			if labelsize == 0 {
				break
			}

			// read domain name
			namebytes := make([]byte, labelsize)
			n, err := data.Read(namebytes)
			if err != nil || n != int(labelsize) {
				log.Fatalf("read domain name. n:%#v, err:%#v", n, err)
				return err
			}
			name += string(namebytes) + "."
		}
		msg.Question[i].Qname = name

		msg.Question[i].Qtype, err = readUint16(data)
		if err != nil {
			return
		}

		msg.Question[i].Qclass, err = readUint16(data)
		if err != nil {
			return
		}
	}

	// unpack Answer
	if msg.Header.Ancount > 0 {
		log.Fatal("Parser Answer Section: not implemeted yet")
	}

	// unpack Authoriy
	if msg.Header.Nscount > 0 {
		log.Fatal("Parser Authority Section: not implemeted yet")
	}

	// unpack Additional
	if msg.Header.Arcount > 0 {
		log.Fatal("Parser Additional Section: not implemeted yet")
	}

	return
}

// serialize
func (msg *dnsMessage) Pack() (data *bytes.Buffer, err error) {
	data = bytes.NewBuffer([]byte{})
	err = binary.Write(data, binary.BigEndian, &msg.Header)
	if err != nil {
		return
	}

	return
}

func main() {
	log.Println("booting...")

	addr := "0.0.0.0:10053"

	udpComm := make(chan bool)
	go udpMain(addr, udpComm)

	tcpComm := make(chan bool)
	go tcpMain(addr, tcpComm)

	log.Println("waiting...")
	select {
	case <-udpComm:
		log.Println("UDP stopped")
		os.Exit(0)
	case <-tcpComm:
		log.Println("TCP stopped")
		os.Exit(0)
	}
}

func udpMain(addr string, comm chan bool) {
	defer func() { comm <- true }()
	log.Println("udpMain")

	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatal("net.ResolveUDPAddr: %s", err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal("net.ListenUDP: %s", err)
	}

	for {
		msg := make([]byte, 512)
		n, remoteAddr, err := conn.ReadFrom(msg)
		if err != nil {
			log.Fatal("conn.ReadFrom: %s", err)
		}
		buf := bytes.NewBuffer(msg[0:n])
		go udpHandle(conn, &remoteAddr, buf)
	}

	return
}

func udpHandle(conn *net.UDPConn, remoteAddr *net.Addr, reqBuf *bytes.Buffer) {
	log.Printf("Request: %#v\n", reqBuf.Bytes())
	request, err := NewDnsMessage(reqBuf)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Request Struct: %#v\n", request)

	var response = request

	responseBuffer, err := response.Pack()
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.WriteTo(responseBuffer.Bytes(), *remoteAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response: %#v\n", responseBuffer.Bytes())
}

func tcpMain(addr string, comm chan bool) {
	defer func() { comm <- true }()
	log.Println("tcpMain")

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go tcpHandle(conn)
	}

	return
}

func tcpHandle(conn net.Conn) {
}
