package main

import (
	"github.com/kpfaulkner/basicdns/models"
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

	ip, _, err := net.ParseCIDR(nameServer+"/32")
	if err != nil {
		log.Fatalf("unable to get upstream addr %s\n", err)
	}

	u.udpAddr = &net.UDPAddr{IP: ip, Port: port}
	return &u, nil
}


// GetRecordWithID requests a record from upstream DNS server.
// no data returned here...
func (u UpstreamDNS) GetRecordWithID(id uint16, domainName string, qType models.QType) error {

	dnsPacket, err := GenerateRecordRequest( id, domainName, true,qType)
	if err != nil {
		log.Errorf("unable to get ARecord from upstream provider %s\n", err)
		return err
	}

	SendDNSRecord(dnsPacket, u.Conn, u.udpAddr)

	return nil
}



