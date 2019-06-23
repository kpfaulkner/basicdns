package models

import "net"

// RawDNSRequest is the raw information from the socket.
// This includes the byte array and the client details of the request (so we know where to respond to).
type RawDNSRequest struct {
	rawBytes []byte
	clientAddr *net.UDPAddr
}
