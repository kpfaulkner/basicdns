package models

import "net"

// RawDNSRequest is the raw information from the socket.
// This includes the byte array and the client details of the request (so we know where to respond to).
type RawDNSRequest struct {
	RawBytes []byte
	ClientAddr *net.UDPAddr
}


type DNSRequest struct {

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
