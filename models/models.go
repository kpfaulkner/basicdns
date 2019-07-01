package models

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type QType uint16
type QClass uint16
type OpCode uint16
const (

	// QType
	ARecord QType = 1
  NameServer QType = 2
  CName QType = 5
  SOA QType = 6
  WKS QType = 11
  PTR QType = 12
  HInfo QType = 13
  MInfo QType = 14
  MX QType = 15
  TXT QType = 16

  // QClass
  QCIN QClass = 1
	QCCH QClass = 3
	QCHS QClass = 4


	OpCodeStandard OpCode = 0
	OpCodeInverse OpCode = 1 << 12
	ServerStatus OpCode = 1 << 13

	AA           uint16 = 1 << 10
	TC           uint16 = 1 << 9
	RD           uint16 = 1 << 8
	RA           uint16 = 1 << 7

	QRResponseFlag uint16 = 1 << 15

)


// RawDNSRequest is the raw information from the socket.
// This includes the byte array and the client details of the request (so we know where to respond to).
type RawDNSRequest struct {
	RawBytes []byte
	ClientAddr *net.UDPAddr
}


// DNSRequest is DNS Request (duh).
// Within a single request there can actually be multiple domains to lookup.
type DNSRequest struct {
	QuerySlice []DNSQuestion
}

// DNSHeader... first 12 bytes of the UDP packet.
// See https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html for great explanation about this!
type DNSHeader struct {
	ID         uint16
	MiscFlags  uint16
	QDCount    uint16
	ANCount    uint16
	NSCount    uint16
	ADCount    uint16
}

type DNSQuestion struct {
	Domain string
	QT QType
	QC QClass
}

// DNSResourceRecord used for answers, authority records and additional records
type DNSResourceRecord struct {
	DomainName         string
	QType              QType
	QClass             QClass
	TTL                uint32
	DataLength         uint16
	Data               []byte
}



func (h DNSHeader) ToString() string {

	var s []string
	s = append(s, fmt.Sprintf("ID %d", h.ID))


	s = append(s, fmt.Sprintf("flags binary %s", strconv.FormatInt(int64(h.MiscFlags), 2)))
	s = append(s, fmt.Sprintf("flags dec %d", h.MiscFlags))


	if h.MiscFlags & QRResponseFlag != 0 {
		s = append(s, "response")
	} else {
		s = append(s, "query")
	}

	if h.MiscFlags & AA != 0 {
		s = append(s, "AA")
	}

	if h.MiscFlags & TC != 0 {
		s = append(s, "TC")
	}

	if h.MiscFlags & RD != 0 {
		s = append(s, "RD")
	}

	if h.MiscFlags & RA != 0 {
		s = append(s, "RA")
	}

	s = append(s, fmt.Sprintf("QC %d", h.QDCount))
	s = append(s, fmt.Sprintf("AN %d", h.ANCount))
	s = append(s, fmt.Sprintf("NS %d", h.NSCount))
	s = append(s, fmt.Sprintf("AD %d", h.ADCount))

	return strings.Join(s, "\n")
}


func (q DNSQuestion) ToString() string {
	var s []string
	s = append(s, fmt.Sprintf("Domain %s", q.Domain))
	s = append(s, fmt.Sprintf("QT %d", q.QT))
	s = append(s, fmt.Sprintf("QC %d", q.QC))

	return strings.Join(s, "\n")

}

func (r DNSResourceRecord) ToString() string {

	var s []string
	s = append(s, fmt.Sprintf("RESOURCE RECORD"))
	s = append(s, fmt.Sprintf("Domain %s", r.DomainName))
	s = append(s, fmt.Sprintf("QT %d", r.QType))
	s = append(s, fmt.Sprintf("QC %d", r.QClass))
	s = append(s, fmt.Sprintf("TTL %d", r.TTL))
	s = append(s, fmt.Sprintf("Data Length %d", r.DataLength))
	s = append(s, fmt.Sprintf("Data %v", r.Data))

	return strings.Join(s, "\n")

}







