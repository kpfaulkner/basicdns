package main

import (
	"bytes"
	"github.com/labstack/gommon/log"
	"net"
	"time"
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
	//_, err = conn.Write(buffer.Bytes())
	if err != nil {
		log.Errorf("Unable to send packet %s\n", err)
		return err
	}

	// now listen for response.

	return nil
}

func ReadUDPSResponse( conn *net.UDPConn, clientAddr *net.UDPAddr ) (*DNSPacket, error) {

	byteArray := make([]byte, 512)

	// nasty magic...
	conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(30)))

	nRead, addr, err := conn.ReadFrom(byteArray)
	if err != nil {
		log.Errorf("unable to read UDP response %s\n", err)
		return nil, err
	}

	log.Debugf("nread %d\n", nRead)
	log.Debugf("addr %s\n", addr)


	/*
	_, err := conn.Read(byteArray)
	if err != nil {
		log.Errorf("unable to read UDP response %s\n", err)
		return nil, err
	}
	*/


	var buffer = new(bytes.Buffer)
	buffer.Write(byteArray)

	dnsPacket, err := ReadDNSPacketFromBuffer( buffer)
	if err != nil {
		log.Errorf("unable to convert DNSPacket to struct %s\n", err)
		return nil, err
	}

	return dnsPacket, nil

}

