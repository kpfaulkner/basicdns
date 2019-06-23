package models

import "net"

type QType uint16
type QClass uint16

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
  IN QClass = 1
  CH QClass = 3
  HS QClass = 4

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
	QuerySlice []DNSQuery
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

type DNSQuery struct {
	Domain string
	QT QType
	QC QClass
}
