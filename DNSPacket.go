package main

import (
	"basicdns/models"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/labstack/gommon/log"
	"math/rand"
	"strconv"
	"strings"
	"time"
)


// DNSPacket is the entire DNS Packet used for requests and responses.
type DNSPacket struct {
	header     models.DNSHeader
	question   models.DNSQuestion
	answers    []models.DNSResourceRecord
	authority  []models.DNSResourceRecord
	additional []models.DNSResourceRecord
}

// NewDNSPacket returns constructed DNS request/reponse packet.
func NewDNSPacket() DNSPacket {
	p := DNSPacket{}

	return p
}

// ReadDNSPacketFromBuffer takes a Buffer (assumed to be at beginning of buffer) and creates a DNSPacket.
// All sections of a DNS request should be populated.
func ReadDNSPacketFromBuffer(requestBuffer *bytes.Buffer ) (*DNSPacket, error) {

  header,err  := ReadDNSHeaderFromBuffer(requestBuffer)
  if err != nil {
  	log.Errorf("unable to read DNS header %s\n", err)
  	return nil, err
  }

  question, err := ReadDNSQuestionFromBuffer(requestBuffer, header.QDCount)
	if err != nil {
		log.Errorf("unable to read DNS question %s\n", err)
		return nil, err
	}

	answers, err := ReadDNSResourceRecordFromBuffer(requestBuffer, header.ANCount)
	if err != nil {
		log.Errorf("unable to read DNS answers %s\n", err)
		return nil, err
	}

	authority, err := ReadDNSResourceRecordFromBuffer(requestBuffer, header.NSCount)
	if err != nil {
		log.Errorf("unable to read DNS nameserver authority %s\n", err)
		return nil, err
	}

	additional, err := ReadDNSResourceRecordFromBuffer(requestBuffer, header.ADCount)
	if err != nil {
		log.Errorf("unable to read DNS additional %s\n", err)
		return nil, err
	}

	dnsPacket := NewDNSPacket()
  dnsPacket.header = *header
  dnsPacket.question = *question
  dnsPacket.answers = answers
  dnsPacket.authority = authority
  dnsPacket.additional = additional

	return &dnsPacket, nil
}

// ReadDNSHeaderFromBuffer reads the header from the requestBuffer
func ReadDNSHeaderFromBuffer( requestBuffer *bytes.Buffer ) (*models.DNSHeader, error) {

	var header models.DNSHeader
	err := binary.Read(requestBuffer, binary.BigEndian, &header)
	if err != nil {
		log.Errorf("Cannot decode header %s\n", err)
		return nil, err
	}

	return &header, nil
}

func readDomainName( requestBuffer *bytes.Buffer) (string, error) {
	var domainSegments []string
	completed := false
	for completed == false {

		// read first byte. This will be how long the query domain will be.
		domainLength, err := requestBuffer.ReadByte()

		if domainLength == 0 {
			// finito.
			completed = true
			continue
		}

		byteSlice := make([]byte, domainLength)

		_, err = requestBuffer.Read(byteSlice)
		if err != nil {
			log.Errorf("Unable to read part of request domain %s\n", err)
			return "", err
		}
		domainSegments = append(domainSegments, string(byteSlice))
	}
	return strings.Join(domainSegments, "."), nil

}

// ReadDNSQuestionFromBuffer reads the question from the requestBuffer
// ASSUMPTION is that the Buffer has the correct offset. Need to see how I can adjust this assumption?
func ReadDNSQuestionFromBuffer( requestBuffer *bytes.Buffer, noQuestions uint16 ) (*models.DNSQuestion, error) {

	var question models.DNSQuestion

	// early bail out.
	if noQuestions == 0 {
		return &question, nil
	}

	domainName, _ := readDomainName(requestBuffer)

	// reads QType and QClass
	qType := models.QType(binary.BigEndian.Uint16(requestBuffer.Next(2)))
	qClass := models.QClass(binary.BigEndian.Uint16(requestBuffer.Next(2)))

	req := models.DNSQuestion{}
	req.Domain = domainName
	req.QT = qType
	req.QC = qClass

	return &req, nil
}

// ReadDNSResourceRecordFromBuffer reads the DNS resource records from the requestBuffer. This can be used for answers, authority or additional RR
func ReadDNSResourceRecordFromBuffer( requestBuffer *bytes.Buffer, noResourceRecords uint16 ) ([]models.DNSResourceRecord, error) {

	records := make([]models.DNSResourceRecord, noResourceRecords)

	var i uint16
	for i = 0 ; i< noResourceRecords ;i++ {
		name, err  := readDomainName(requestBuffer)

		if err != nil {
			log.Errorf("error reading name from RR %s\n", err)
			return nil, err
		}

		rrType := binary.BigEndian.Uint16(requestBuffer.Next(2))
		rrClass := binary.BigEndian.Uint16(requestBuffer.Next(2))
		rrTTL := binary.BigEndian.Uint32(requestBuffer.Next(4))
		rrRDLLength := binary.BigEndian.Uint16(requestBuffer.Next(2))

		record := models.DNSResourceRecord{}
		record.DomainName = name
		record.QType = rrType
		record.QClass = rrClass
		record.TTL = rrTTL
		record.DataLength = rrRDLLength
		record.Data = requestBuffer.Next( int(rrRDLLength))
		records[i] = record
	}

	return records, nil
}

// WriteDNSPacketToBuffer writes the packet to the supplied buffer.
// passing in buffer to write it, so we can reuse the buffer as opposed to
// always allocating memory for new ones.
func WriteDNSPacketToBuffer( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	responseBuffer.Reset()

	err := writeDNSHeader( dnsPacket, responseBuffer)
	if err != nil {
		log.Errorf("Unable to write header response %s\n", err)
		return err
	}

	err = writeDNSQuestion( dnsPacket, responseBuffer)
	if err != nil {
		log.Errorf("Unable to write question response %s\n", err)
		return err
	}

	err = writeDNSAnswers( dnsPacket, responseBuffer)
	if err != nil {
		log.Errorf("Unable to write answer response %s\n", err)
		return err
	}

	err = writeDNSAuthority( dnsPacket, responseBuffer)
	if err != nil {
		log.Errorf("Unable to write authority response %s\n", err)
		return err
	}

	err = writeDNSAdditional( dnsPacket, responseBuffer)
	if err != nil {
		log.Errorf("Unable to write additional response %s\n", err)
		return err
	}
	return nil
}

func writeDNSHeader( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	header := dnsPacket.header

	// assuming QDCount are correct
	// need to figure out what these do.

	header.MiscFlags = models.QRResponseFlag   // QR == 1, indicating response.
	header.ANCount = uint16( len( dnsPacket.answers))
	header.NSCount = uint16( len( dnsPacket.authority))
	header.ADCount = uint16( len( dnsPacket.additional))

	err := binary.Write(responseBuffer, binary.BigEndian, &header)

	if err != nil {
		log.Errorf("Error writing header %s: ", err.Error())
		return err
	}

	return nil
}

// writeDomainName is used to write out domain names in the format that DNS requests like it.
// length of segment followed by segment (in bytes). This will be used by multiple resource records.
func writeDomainName(domainName string, responseBuffer *bytes.Buffer) error {
	segments := strings.Split(domainName, ".")
	for _, segment := range segments {
		segmentLength := len(segment)
		segmentInBytes := []byte(segment)

		// write length of segment, then the segment (in bytes)
		responseBuffer.WriteByte(byte(segmentLength))
		responseBuffer.Write(segmentInBytes)
	}

	// 0 indicates, end of domain.
	responseBuffer.WriteByte(byte(0))

	return nil
}

// writeDNSQuestion is writing out the same question that arrived originally.
// probably should cache it rather than re-create it?
func writeDNSQuestion( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	question := dnsPacket.question.Domain
	err := writeDomainName( question, responseBuffer)
	if err != nil {
		log.Errorf("unable to write question domainname %s\n", err)
		return err
	}

	binary.Write(responseBuffer, binary.BigEndian, dnsPacket.question.QT)
	binary.Write(responseBuffer, binary.BigEndian, dnsPacket.question.QC)

	return nil
}

// writeDNSResourceRecord is the generic function that writes out RR's which are used for answers, authority and
// additional info.
func writeDNSResourceRecord( domainName string,  records []models.DNSResourceRecord, responseBuffer *bytes.Buffer) error {

	for _, record := range records {
		err := writeDomainName( domainName, responseBuffer)
		if err != nil {
			log.Errorf("Cannot write domain name for RR %s\n", err)
			return err
		}

		binary.Write(responseBuffer, binary.BigEndian, record.QType)
		binary.Write(responseBuffer, binary.BigEndian, record.QClass)
		binary.Write(responseBuffer, binary.BigEndian, record.TTL)
		binary.Write(responseBuffer, binary.BigEndian, record.DataLength)
		binary.Write(responseBuffer, binary.BigEndian, record.Data)
	}

	return nil
}


func writeDNSAnswers( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	err := writeDNSResourceRecord(dnsPacket.question.Domain, dnsPacket.answers, responseBuffer)
	if err != nil {
		log.Errorf("unable to write answers %s\n", err)
		return err
	}
	return nil
}

func writeDNSAuthority( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	err := writeDNSResourceRecord(dnsPacket.question.Domain, dnsPacket.authority, responseBuffer)
	if err != nil {
		log.Errorf("unable to write authority %s\n", err)
		return err
	}
	return nil
}


func writeDNSAdditional( dnsPacket DNSPacket, responseBuffer *bytes.Buffer) error {

	err := writeDNSResourceRecord(dnsPacket.question.Domain, dnsPacket.additional, responseBuffer)
	if err != nil {
		log.Errorf("unable to write additional %s\n", err)
		return err
	}
	return nil
}

// convertIPToBytes....  convert 10.12.123.14  to a byte array.
// major assumption we're talking IPV4 here.
// TODO(kpfaulkner) add error checking.
func convertIPToBytes( ip string ) [4]byte {

	var bytes [4]byte

	sp := strings.Split(ip, ".")
	for  i:=0; i< 4; i++ {
		i,_ = strconv.Atoi(sp[i])
    bytes[i] = byte(i)
	}

	return bytes
}


// convertIPToBytes....  convert 10.12.123.14  to a byte array.
// major assumption we're talking IPV4 here.
// TODO(kpfaulkner) add error checking.
func convertBytesToIP(bytes [4]byte) string {

  var sp = make([]string, 4)
	for  i, b := range bytes {
      sp[i] = fmt.Sprintf("%d", b)
	}

	return strings.Join(sp, ".")
}

func GenerateDNSQuestion( domainName string, qt models.QType, qc models.QClass ) (models.DNSQuestion) {
  qs := models.DNSQuestion{}
  qs.Domain = domainName
  qs.QT = qt
  qs.QC = qc
  return qs
}

func GenerateFlags(  isResponse bool, opCode models.OpCode, isTruncated bool, isRecursive bool ) uint16 {
  flags := uint16(0)

  if isResponse {
  	flags |= models.QRResponseFlag
  }

  flags |= uint16(opCode)

  if isTruncated {
  	flags |= models.TC
  }

  if isRecursive {
  	flags |= models.RD
  }

	return flags
}

func GenerateDNSHeader( domainName string, isResponse bool, opCode models.OpCode, isTruncated bool, isRecursive bool) models.DNSHeader {

	h := models.DNSHeader{}

	rand.Seed(time.Now().Unix())
	n := rand.Intn(32767)
	h.ID = uint16(n)
  h.MiscFlags = GenerateFlags(isResponse, opCode, isTruncated, isRecursive)
  h.QDCount = 1  // assumption we'll only deal with 1 query at a time.
  h.ANCount = 0
  h.NSCount = 0
  h.ADCount = 0

	return h
}

func GenerateARecordRequest( domainName string, recursive bool ) (DNSPacket, error ) {

	dnsPacket := NewDNSPacket()
	dnsPacket.question = GenerateDNSQuestion(domainName, models.ARecord, models.QCIN )
  dnsPacket.header = GenerateDNSHeader( domainName, false, models.OpCodeStandard, false, true)
  



}







