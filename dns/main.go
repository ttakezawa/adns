package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
)

type any interface{}

type dnsMessage struct {
	dnsHeader
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

func writeUint16(buf *bytes.Buffer, i uint16) (err error) {
	uint16bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(uint16bytes, i)
	n, err := buf.Write(uint16bytes)
	if err != nil && n != 2 {
		log.Fatal("write at wrong length")
	}
	return err
}

func writeUint32(buf *bytes.Buffer, i uint32) (err error) {
	uint32bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(uint32bytes, i)
	n, err := buf.Write(uint32bytes)
	if err != nil && n != 2 {
		log.Fatal("write at wrong length")
	}
	return err
}

// construct dnsMessage
func NewDnsMessage(data *bytes.Buffer) (msg *dnsMessage, err error) {
	msg = &dnsMessage{}
	err = msg.Unpack(data)
	return
}
func (msg *dnsMessage) Unpack(data *bytes.Buffer) (err error) {
	// unpack dnsHeader
	err = binary.Read(data, binary.BigEndian, &msg.dnsHeader)
	if err != nil {
		return
	}

	// label, err := data.ReadByte()
	// log.Printf("label:%#v err:%#v\n", label, err)

	// unpack Question
	msg.Question = make([]dnsQuestion, msg.Qdcount)

	for i := uint16(0); i < msg.Qdcount; i++ {
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
			if labelsize&0xC0 == 0xC0 {
				// 上位2bitが1のとき
				log.Fatal("not implemented yet: label as pointer")
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
	if msg.Ancount > 0 {
		log.Fatal("Parser Answer Section: not implemeted yet")
	}

	// unpack Authoriy
	if msg.Nscount > 0 {
		log.Fatal("Parser Authority Section: not implemeted yet")
	}

	// unpack Additional
	if msg.Arcount > 0 {
		log.Fatal("Parser Additional Section: not implemeted yet")
	}

	return
}

// serialize
func (msg *dnsMessage) Pack() (data *bytes.Buffer, err error) {
	data = bytes.NewBuffer([]byte{})

	// Header
	err = binary.Write(data, binary.BigEndian, &msg.dnsHeader)
	if err != nil {
		return
	}

	// Question
	for i := 0; i < len(msg.Question); i++ {
		// Pack QNAME
		labels := strings.Split(msg.Question[i].Qname, ".")
		for _, label := range labels {
			labelsize := len(label)
			err := data.WriteByte(byte(labelsize))
			if err != nil {
				log.Fatal(err)
			}
			n, err := data.WriteString(label)
			if err != nil || n != labelsize {
				log.Fatal(err)
			}
		}
		// Pack QTYPE
		writeUint16(data, msg.Question[i].Qtype)
		// Pack QCLASS
		writeUint16(data, msg.Question[i].Qclass)
	}

	// Answer
	for _, rr := range msg.Answer {
		// Pack RR of Answer
		packRR(data, &rr)
	}
	// Authority
	// Additional

	return
}

func packDomainName(buf *bytes.Buffer, name *string) {
	labels := strings.Split(*name, ".")
	// log.Printf("packDomainName labels: %#v\n", labels)
	for _, label := range labels {
		labelsize := len(label)
		err := buf.WriteByte(byte(labelsize))
		if err != nil {
			log.Fatal(err)
		}
		n, err := buf.WriteString(label)
		if err != nil || n != labelsize {
			log.Fatal(err)
		}
	}
}

func packRR(buf *bytes.Buffer, rr *dnsRR) {
	packDomainName(buf, &rr.Name)
	writeUint16(buf, rr.Type)
	writeUint16(buf, rr.Class)
	writeUint32(buf, rr.Ttl)
	writeUint16(buf, rr.Rdlength)
	buf.WriteString(rr.Rdata)
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

func udpHandle(conn *net.UDPConn, remoteAddr *net.Addr, requestBuffer *bytes.Buffer) {
	// log.Printf("Request: %#v\n", requestBuffer.Bytes())
	request, err := NewDnsMessage(requestBuffer)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("Request Struct: %#v\n", request)

	// create response
	var response = request

	// setup Header Section
	var bitsbytes = []byte{0x81, 0x80}[:]
	response.Bits = binary.BigEndian.Uint16(bitsbytes)
	response.Qdcount = 1
	response.Ancount = 1

	// setup Answer Section
	response.Answer = make([]dnsRR, 1)
	// var namebytes = []byte{0xc0, 0x0c}
	// response.Answer[0].Name = string(namebytes[:])
	// TODO: とりあえずQuestionのホスト名を入れている
	response.Answer[0].Name = response.Question[0].Qname
	response.Answer[0].Type = response.Question[0].Qtype
	response.Answer[0].Class = response.Question[0].Qclass
	var ttlbytes = []byte{0x00, 0x00, 0x00, 0x3c}
	response.Answer[0].Ttl = binary.BigEndian.Uint32(ttlbytes)
	var rdlengthbytes = []byte{0x00, 0x04}
	response.Answer[0].Rdlength = binary.BigEndian.Uint16(rdlengthbytes)
	var rdatabytes = []byte{0x08, 0x08, 0x08, 0x08}
	response.Answer[0].Rdata = string(rdatabytes)

	// output response
	responseBuffer, err := response.Pack()
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.WriteTo(responseBuffer.Bytes(), *remoteAddr)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("Response: %#v\n", responseBuffer.Bytes())
	// log.Printf("Response Struct: %#v\n", response)
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

func init() {
        runtime.GOMAXPROCS(runtime.NumCPU())
}
