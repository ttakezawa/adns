package main

import (
	"fmt"
	"log"
	"net"
	"os"
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

func packWalker(walker Walker, msg []byte, off int) (off1 int, ok bool) {
	ok = walker.Walk(func(field interface{}, name, tag string) bool {
		switch fv := field.(type) {
		default:
			log.Print("unknown packing type")
			return false
		case *uint16:
			i := *fv
			if off+2 > len(msg) {
				return false
			}
			msg[off] = byte(i >> 8)
			msg[off+1] = byte(i)
			off += 2
		case *uint32:
			i := *fv
			if off+4 > len(msg) {
				return false
			}
			msg[off] = byte(i >> 24)
			msg[off+1] = byte(i >> 16)
			msg[off+2] = byte(i >> 8)
			msg[off+3] = byte(i)
			off += 4
		case *string:
			s := *fv
			switch tag {
			default:
				log.Print("unknown string tag", tag)
				return false
			case "domain":
				off, ok = packDomainName(s, msg, off)
				if !ok {
					return false
				}
			case "":
				// Counted string: 1 byte length.
				if len(s) > 255 || off+1+len(s) > len(msg) {
					return false
				}
				msg[off] = byte(len(s))
				off++
				off += copy(msg[off:], s)
			}
		}
		return true
	})
	if !ok {
		return len(msg), false
	}
	return off, true
}

// Pack a domain name s into msg[off:].
// Domain names are a sequence of counted strings
// split at the dots.  They end with a zero-length string.
func packDomainName(s string, msg []byte, off int) (off1 int, ok bool) {
	// Add trailing dot to canonicalize name.
	if n := len(s); n == 0 || s[n-1] != '.' {
		s += "."
	}

	// Each dot ends a segment of the name.
	// We trade each dot byte for a length byte.
	// There is also a trailing zero.
	// Check that we have all the space we need.
	tot := len(s) + 1
	if off+tot > len(msg) {
		return len(msg), false
	}

	// Emit sequence of counted strings, chopping at dots.
	begin := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			if i-begin >= 1<<6 { // top two bits of length must be clear
				return len(msg), false
			}
			msg[off] = byte(i - begin)
			off++
			for j := begin; j < i; j++ {
				msg[off] = s[j]
				off++
			}
			begin = i + 1
		}
	}
	msg[off] = 0
	off++
	return off, true
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
			*fv = uint16(msg[off])<<8 | uint16(msg[off+1])
			off += 2
		case *uint32:
			if off+4 > len(msg) {
				return false
			}
			*fv = uint32(msg[off])<<24 |
				uint32(msg[off+1])<<16 |
				uint32(msg[off+2])<<8 |
				uint32(msg[off+3])
			off += 4
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

	// Records
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

	for i := 0; i < len(dns.Answer); i++ {
		off, ok = dns.Answer[i].Unpack(msg, off)
		if err != nil {
			return
		}
	}
	for i := 0; i < len(dns.Authority); i++ {
		off, ok = dns.Authority[i].Unpack(msg, off)
		if err != nil {
			return
		}
	}
	for i := 0; i < len(dns.Additional); i++ {
		off, ok = dns.Additional[i].Unpack(msg, off)
		if err != nil {
			return
		}
	}

	return nil
}

// packLen returns the message length when in UNcompressed wire format.
func (dns *dnsMessage) packlen() int {
	// Message header is always 12 bytes
	l := 12
	for i := 0; i < len(dns.Question); i++ {
		l += dns.Question[i].len()
	}
	for i := 0; i < len(dns.Answer); i++ {
		l += dns.Answer[i].len()
	}
	for i := 0; i < len(dns.Authority); i++ {
		l += dns.Authority[i].len()
	}
	for i := 0; i < len(dns.Additional); i++ {
		l += dns.Additional[i].len()
	}
	return l
}

func (dns *dnsMessage) Pack() (msg []byte, ok bool) {

	// Prepare DNS Header
	var headerData dnsHeaderData
	headerData.Id = dns.Id
	headerData.Bits = uint16(dns.Opcode)<<11 | uint16(dns.Rcode)
	if dns.RA {
		headerData.Bits |= _RA
	}
	if dns.RD {
		headerData.Bits |= _RD
	}
	if dns.TC {
		headerData.Bits |= _TC
	}
	if dns.AA {
		headerData.Bits |= _AA
	}
	if dns.QR {
		headerData.Bits |= _QR
	}
	headerData.Qdcount = uint16(len(dns.Question))
	headerData.Ancount = uint16(len(dns.Answer))
	headerData.Nscount = uint16(len(dns.Authority))
	headerData.Arcount = uint16(len(dns.Additional))

	msg = make([]byte, dns.packlen()+1)
	off := 0

	off, ok = packWalker(&headerData, msg, off)
	for i := 0; i < len(dns.Question); i++ {
		if off, ok = packWalker(&dns.Question[i], msg, off); !ok {
			return nil, false
		}
	}
	for i := 0; i < len(dns.Answer); i++ {
		if off, ok = packWalker(&dns.Answer[i], msg, off); !ok {
			return nil, false
		}
	}
	for i := 0; i < len(dns.Authority); i++ {
		if off, ok = packWalker(&dns.Authority[i], msg, off); !ok {
			return nil, false
		}
	}
	for i := 0; i < len(dns.Additional); i++ {
		if off, ok = packWalker(&dns.Additional[i], msg, off); !ok {
			return nil, false
		}
	}

	return msg[0:off], true
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

// Use like Plain Old Data (wire-like definition)
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

func (q *dnsQuestion) len() int {
	return len(q.Qname) + 1 + 2 + 2
}

type dnsRR struct {
	dnsRRHeader
	Rdata string
}

func (rr *dnsRR) len() int {
	return rr.dnsRRHeader.len() + int(rr.dnsRRHeader.Rdlength)
}

type dnsRRHeader struct {
	Name     string
	Type     uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
}

func (h *dnsRRHeader) len() int {
	return len(h.Name) + 1 + 2 + 2 + 4 + 2
}

func (rr *dnsRRHeader) Walk(f func(field interface{}, name, tag string) bool) bool {
	return f(&rr.Name, "Name", "domain") &&
		f(&rr.Type, "Type", "") &&
		f(&rr.Class, "Class", "") &&
		f(&rr.Ttl, "Ttl", "") &&
		f(&rr.Rdlength, "Rdlength", "")
}

func (rr *dnsRR) Unpack(msg []byte, off int) (off1 int, ok bool) {
	if off, ok = unpackWalker(&rr.dnsRRHeader, msg, off); !ok {
		log.Print("failed: unpack RR Header")
		return off, false
	}
	length := int(rr.Rdlength)
	if off+length > len(msg) {
		log.Print("insufficient data")
		return off, false
	}
	rr.Rdata = string(msg[off : off+length])
	off += length

	return off, true
}

func authoritativeHandleUDP(conn *net.UDPConn, remoteAddr *net.Addr, reqBytes []byte) {
	log.Printf("Received: %d bytes\n", len(reqBytes))

	reqMsg := new(dnsMessage)
	if err := reqMsg.Unpack(reqBytes); err != nil {
		log.Print(err)
		conn.Close()
		return
	}

	log.Printf("Request Msg: %#v", reqMsg)

	// TODO impl here
	resMsg := serve(reqMsg)

	log.Printf("Response Msg: %#v", resMsg)

	resBytes, ok := resMsg.Pack()
	if !ok {
		log.Print("failed pack response")
		return
	}
	n, err := conn.WriteTo(resBytes, *remoteAddr)
	if err != nil {
		log.Print(err)
		return
	}
	log.Printf("Sent: %d bytes\n", n)
}

func serve(req *dnsMessage) *dnsMessage {
	res := *req
	return &res
}
