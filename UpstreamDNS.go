package main

import (
	"fmt"
	"github.com/labstack/gommon/log"
	"net"
)

type UpstreamDNS struct {
	upstreamDNSFQDN string // IP/FQDN of upstream DNS.
	port int
	Conn *net.UDPConn
	udpAddr *net.UDPAddr
}

func NewUpstreamDNS( nameServer string, port int) (*UpstreamDNS, error) {
  u := UpstreamDNS{}
  u.upstreamDNSFQDN = nameServer
  u.port = port
	u.udpAddr,_ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", nameServer, port))

	return &u, nil
}


// connectUpStream will connect to the upstream DNS provider we've specified.
// Returning Conn interface as opposed to UDPConn. Should be ok. :)
func connectUpStream( upstreamDNS string, udpAddr *net.UDPAddr ) (*net.UDPConn, error){
	//Connect udp

	/*
	conn, err := net.DialUDP("udp", nil, udpAddr )
	if err != nil {
		return nil, err
	}*/

	var ip = make(net.IP,4)
	// 203.40.11.170
	ip[0] = 203
	ip[1] = 40
	ip[2] = 11
	ip[3] = 170

	conn, err := net.ListenUDP("udp", &net.UDPAddr{ Port: 10000})
	if err != nil {
		log.Fatal("Listen:", err)
	}

  return conn, nil
}

// GetARecord requests ARecord from upstream DNS server.
// no data returned here...
func (u UpstreamDNS) GetARecordWithID(id uint16, domainName string) error {

	dnsPacket, err := GenerateARecordRequest( id, domainName, true)
	if err != nil {
		log.Errorf("unable to get ARecord from upstream provider %s\n", err)
		return err
	}

	resolver := net.UDPAddr{IP: net.IP{1, 1, 1, 1}, Port: 53}

	SendDNSRecord(dnsPacket, u.Conn, &resolver)

	return nil
}




