package main

import (
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

type Walker interface {
	// Walk iterates over fields of a structure and calls f
	// with a reference to that field, the name of the field
	// and a tag specifying particular encodings.
	Walk(f func(field interface{}, name, tag string) (ok bool)) (ok bool)
}

// deserialize
func unpackWalker(walker Walker, msg []byte, off int) (off1 int, ok bool) {
	ok = walker.Walk(func(field interface{}, name, tag string) bool {
		// Type switch
		switch fv := field.(type) {
		default:
			log.Print("unknown packing type")
			return false
		case *uint16:
			if off+2 > len(msg) {
				return false
			}
			*fv = uint16(msg[off]<<8) | uint16(msg[off+1])
			off += 2
		case *string:
			var s string
			switch tag {
			default:
				log.Print("unknown string tag", tag)
				return false
			case "domain":
				s, off, ok = unpackDomainName(msg, off)
				if !ok {
					log.Print("failed unpack domain name", name)
					return false
				}
			}
			*fv = s
		}
		return true
	})
	if !ok {
		return len(msg), false
	}
	return off, true
}

func unpackDomainName(msg []byte, off int) (s string, off1 int, ok bool) {
	s = ""
	lenmsg := len(msg)
	ptrCount := 0 // pointer follow counter

	// Read all labels
	for {
		// Each label is represented as a one octet length field followed by that
		// number of octets. Since every domain name ends with the null label of
		// the root, a domain name is terminated by a length byte of zero.  The
		// high order two bits of every length octet must be zero, and the
		// remaining six bits of the length field limit the label to 63 octets or
		// less.

		// Read size of label
		if off >= lenmsg {
			return "", lenmsg, false
		}
		labelSize := int(msg[off])
		off++

		if labelSize == 0 {
			break
		}
		if labelSize&0xC0 == 0x00 {
			// Read a label
			if off+labelSize > len(msg) {
				log.Print("invalid label")
				return "", lenmsg, false
			}

			s += string(msg[off:off+labelSize]) + "."
			off += labelSize
		} else if labelSize&0xC0 == 0xC0 {
			// 上位2bitが1のときは、ポインタが指定されている
			log.Fatal("used label is pointer")

			// pointer to somewhere else in msg.
			// remember location after first ptr,
			// since that's how many bytes we consumed.
			// also, don't follow too many pointers --
			// maybe there's a loop.
			if off >= lenmsg {
				return "", lenmsg, false
			}
			leastSignificantByte := msg[off]
			off++
			if ptrCount == 0 {
				off1 = off
			}
			if ptrCount++; ptrCount > 10 {
				log.Print("follow too many pointers of domain name label")
				return "", lenmsg, false
			}
			off = (labelSize^0xC0)<<8 | int(leastSignificantByte)
		}
	}
	if s == "" {
		s = "."
	}
	if ptrCount == 0 {
		return s, off, true
	} else {
		return s, off1, true
	}
}

type dnsMessage struct {
	dnsHeader
	Question   []dnsQuestion
	Answer     []dnsRR
	Authority  []dnsRR
	Additional []dnsRR
}

func (dns *dnsMessage) Unpack(msg []byte) (err error) {
	off := 0
	var ok bool

	// Header
	headerData := new(dnsHeaderData)
	if off, ok = unpackWalker(headerData, msg, off); !ok {
		return newError("insufficient data")
	}
	dns.dnsHeader.initWithData(headerData)

	// Rest
	dns.Question = make([]dnsQuestion, headerData.Qdcount)
	dns.Answer = make([]dnsRR, headerData.Ancount)
	dns.Authority = make([]dnsRR, headerData.Nscount)
	dns.Additional = make([]dnsRR, headerData.Arcount)

	for i := 0; i < len(dns.Question); i++ {
		off, ok = unpackWalker(&dns.Question[i], msg, off)
		if err != nil {
			return
		}
	}
	// TODO NOW implement
	// for i := 0; i < len(dns.Answer); i++ {
	// 	dns.Answer[i], off, ok = unpackRR(msg, off)
	// 	if err != nil {
	// 		return
	// 	}
	// }
	// for i := 0; i < len(dns.Ns); i++ {
	// 	dns.Ns[i], off, ok = unpackRR(msg, off)
	// 	if err != nil {
	// 		return
	// 	}
	// }
	// for i := 0; i < len(dns.Extra); i++ {
	// 	dns.Extra[i], off, ok = unpackRR(msg, off)
	// 	if err != nil {
	// 		return
	// 	}
	// }

	return nil
}

type dnsHeader struct {
	Id     uint16
	QR     bool // Query or Response
	Opcode int  // OperationCode
	AA     bool // Authoritative Answer
	TC     bool // Truncated
	RD     bool // Recursion Desired
	RA     bool // Recursion Available
	Z      bool // Reserved for future use. Must be zero.
	Rcode  int  // Response code
}

const (
	// dnsHeader.Bits
	_QR = 1 << 15 // query/response (response=1)
	_AA = 1 << 10 // authoritative
	_TC = 1 << 9  // truncated
	_RD = 1 << 8  // recursion desired
	_RA = 1 << 7  // recursion available
)

func (header *dnsHeader) initWithData(headerData *dnsHeaderData) {
	header.Id = headerData.Id

	bits := headerData.Bits
	header.QR = (bits & _QR) != 0
	header.Opcode = int(bits>>11) & 0xF
	header.AA = (bits & _AA) != 0
	header.TC = (bits & _TC) != 0
	header.RD = (bits & _RD) != 0
	header.RA = (bits & _RA) != 0
	header.Rcode = int(bits & 0xF)
}

// Use like Plain Old Data
type dnsHeaderData struct {
	Id                                 uint16
	Bits                               uint16
	Qdcount, Ancount, Nscount, Arcount uint16
}

func (h *dnsHeaderData) Walk(f func(field interface{}, name, tag string) bool) bool {
	return f(&h.Id, "Id", "") &&
		f(&h.Bits, "Bits", "") &&
		f(&h.Qdcount, "Qdcount", "") &&
		f(&h.Ancount, "Ancount", "") &&
		f(&h.Nscount, "Nscount", "") &&
		f(&h.Arcount, "Arcount", "")
}

// // Deserialize
// func (h *dnsHeader) Unpack(msg []byte) (qdcount uint16, ancount uint16, nscount uint16, arcount uint16, err error) {
// 	off := 0

// 	// fetch Id (16 bits)
// 	if off+2 > len(msg) {
// 		return newError("insufficient data")
// 	}
// 	h.Id = uint16(msg[off])<<8 | uint16(msg[off+1])
// 	off += 2

// 	// fetch Flags (16 bits)
// 	if off+2 > len(msg) {
// 		return newError("insufficient data")
// 	}
// 	flags := uint16(msg[off])<<8 | uint16(msg[off+1])
// 	off += 2

// 	return nil
// }

type dnsQuestion struct {
	Qname  string
	Qtype  uint16
	Qclass uint16
}

func (q *dnsQuestion) Walk(f func(field interface{}, name, tag string) bool) bool {
	return f(&q.Qname, "Qname", "domain") &&
		f(&q.Qtype, "Qtype", "") &&
		f(&q.Qclass, "Qclass", "")
}

type dnsRR struct {
	Name     string
	Type     uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
	Rdata    string
}

func authoritativeHandleUDP(conn *net.UDPConn, remoteAddr *net.Addr, reqBytes []byte) {
	log.Printf("Received: %d bytes\n", len(reqBytes))

	reqMsg := new(dnsMessage)
	if err := reqMsg.Unpack(reqBytes); err != nil {
		log.Print(err)
		conn.Close()
		return
	}

	log.Printf("reqMsg: %#v", reqMsg)

	n, err := conn.WriteTo(reqBytes, *remoteAddr)
	if err != nil {
		log.Print(err)
		runtime.Goexit()
	}
	log.Printf("Sent: %d bytes\n", n)
}
