package main

import (
	"basicdns/models"
	"bytes"
	"encoding/binary"
	"net"
)

// SendDNSRecord send the DNSRecord to the client address. Given DNSRecord is used for the request AND the
// response, this function can be used when replying to whoever is called BasicDNS but could also be used for
// when querying upstream DNS servers when we dont know the answer.
func SendDNSRecord(transactionID uint16, miscFlags uint16,   record models.DNSRecord, conn *net.UDPConn, clientAddr *net.UDPAddr ) error {

	var responseBuffer = new(bytes.Buffer)
	var responseHeader models.DNSHeader

	responseHeader = models.DNSHeader{
		ID : transactionID,
		MiscFlags : miscFlags,
		NumQuestions:   queryHeader.NumQuestions,
		NumAnswers:     uint16(len(answerResourceRecords)),
		NumAuthorities: uint16(len(authorityResourceRecords)),
		NumAdditionals: uint16(len(additionalResourceRecords)),
	}

	err = binary.Write(responseBuffer, binary.BigEndian, &responseHeader)

	return nil
}
