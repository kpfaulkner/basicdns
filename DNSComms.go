package main

import (
	"bytes"
	log "github.com/golang/glog"
	//"github.com/labstack/gommon/log"
	"net"
)

// SendDNSRecord send the DNSRecord to the client address. Given DNSPacket is used for the request AND the
// response, this function can be used when replying to whoever is called BasicDNS but could also be used for
// when querying upstream DNS servers when we dont know the answer.
func SendDNSRecord(dnsPacket DNSPacket, conn *net.UDPConn, clientAddr *net.UDPAddr ) error {
	var buffer = new(bytes.Buffer)

	err := WriteDNSPacketToBuffer(dnsPacket, buffer)
	if err != nil {
		log.Errorf("Unable to generate packet to send %s\n", err)
		return err
	}

	_, err = conn.WriteTo(buffer.Bytes(), clientAddr)
	if err != nil {
		log.Errorf("Unable to send packet %s\n", err)
		return err
	}
	return nil
}

