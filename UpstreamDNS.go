package main

import (
	"fmt"
	"github.com/labstack/gommon/log"
	"net"
)

type UpstreamDNS struct {
	upstreamDNSFQDN string // IP/FQDN of upstream DNS.
	port int
	conn *net.UDPConn
	udpAddr *net.UDPAddr
}

func NewUpstreamDNS( nameServer string, port int) (*UpstreamDNS, error) {
  u := UpstreamDNS{}
  u.upstreamDNSFQDN = nameServer
  u.port = port

	u.udpAddr,_ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", nameServer, port))
  conn, err := connectUpStream( nameServer, u.udpAddr)
  if err != nil {
  	log.Errorf("Unable to create UpstreamDNS instance %s\n", err)
  	return nil, err
  }

  u.conn = conn

	return &u, nil
}


// connectUpStream will connect to the upstream DNS provider we've specified.
// Returning Conn interface as opposed to UDPConn. Should be ok. :)
func connectUpStream( upstreamDNS string, udpAddr *net.UDPAddr ) (*net.UDPConn, error){
	//Connect udp
	conn, err := net.DialUDP("udp", nil, udpAddr )
	if err != nil {
		return nil, err
	}

  return conn, nil
}

// GetARecord returns
func (u UpstreamDNS) GetARecord(domainName string) (*DNSPacket, error) {

	dnsPacket, err := GenerateARecordRequest( domainName, true)
	if err != nil {
		log.Errorf("unable to get ARecord from upstream provider %s\n", err)
		return nil, err
	}

	SendDNSRecord( dnsPacket, u.conn, u.udpAddr)

	return nil, nil
}




