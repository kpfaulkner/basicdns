package main

import (
	"basicdns/models"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/labstack/gommon/log"
	"strconv"
	"strings"
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

// ToString.....  print out entire packet... make it easier for debugging
func (p DNSPacket ) ToString() string {

	// header
	header := p.header.ToString()

	// question
  q := p.question.ToString()

  var aa []string
	// answers
	for _,a := range p.answers {
		aa = append(aa, fmt.Sprintf("%s\n\n\n", a.ToString()))
	}

	var ad []string
	// answers
	for _,a := range p.additional{
		ad = append(ad, fmt.Sprintf("%s\n\n\n", a.ToString()))
	}

	return fmt.Sprintf("%s\n%s\nanswers\n%s\nadditional\n%s\n ", header, q, aa,ad)
}

// ReadDNSPacketFromBuffer takes a Buffer (assumed to be at beginning of buffer) and creates a DNSPacket.
// All sections of a DNS request should be populated.
func ReadDNSPacketFromBuffer(requestBuffer bytes.Buffer ) (*DNSPacket, error) {

	// this is so stupidly lazy but cant figure out a nice way so
	// we can get offset from beginning. Given we're just shuffling 512 bytes around it shouldn't be
	// that impactful, but is definitely a hack. Maybe need to change requestBuffer to simply be a slice of bytes
	// instead?
	originalBytes := requestBuffer.Bytes()

  header,err  := ReadDNSHeaderFromBuffer(&requestBuffer)
  if err != nil {
  	log.Errorf("unable to read DNS header %s\n", err)
  	return nil, err
  }

  question, err := ReadDNSQuestionFromBuffer(&requestBuffer, header.QDCount)
	if err != nil {
		log.Errorf("unable to read DNS question %s\n", err)
		return nil, err
	}

	answers, err := ReadDNSResourceRecordFromBuffer(&requestBuffer, header.ANCount, originalBytes)
	if err != nil {
		log.Errorf("unable to read DNS answers %s\n", err)
		return nil, err
	}

	authority, err := ReadDNSResourceRecordFromBuffer(&requestBuffer, header.NSCount, originalBytes)
	if err != nil {
		log.Errorf("unable to read DNS nameserver authority %s\n", err)
		return nil, err
	}

	additional, err := ReadDNSResourceRecordFromBuffer(&requestBuffer, header.ADCount, originalBytes)
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

// readNonCompressedDomainName just read "regular" domain name from buffer.
// split by segment size, bytes of segment, etc etc... until we hit 0 indicating all done.
func readNonCompressedDomainName( requestBuffer *bytes.Buffer) (string, error) {
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

// readDomainName reads the domain name from the buffer. There are 2 formats that this can take.
// one is the first 2 bits are 11 which means  we read the remaining 14 bits for an address which is an
// offset from the beginning of the packet/buffer.
// If the first 2 bits are NOT 11 then it will just be the first byte is the number of bytes in that segment of the name
// followed by the bytes of the segment, repeat until we just read a 0 byte. Must reword this...
// hack is to have requestBuffer as our main point of reading, but also passing in original message byte slice
// just so we can get references when we get compressed domain name.
func readDomainName( requestBuffer *bytes.Buffer, packetBytes []byte ) (string, error) {

	// checking if compressed or not.
	byteArray := requestBuffer.Bytes()
	if byteArray[0] & 192 == 192 {
		// compressed.
		//firstTwoBytes := binary.BigEndian.Uint16(byteArray[:2])

		// remove first 2 bits
		//nameOffset := firstTwoBytes & uint16(49152)
    nameOffset := byteArray[1]

    // tell main requestBuffer to forward on 2 bytes.
    _ = requestBuffer.Next(2)
		bufferForName := bytes.NewBuffer(packetBytes[nameOffset:])
		return readNonCompressedDomainName( bufferForName)

	} else {
		return readNonCompressedDomainName(requestBuffer)
	}
}

// ReadDNSQuestionFromBuffer reads the question from the requestBuffer
// ASSUMPTION is that the Buffer has the correct offset. Need to see how I can adjust this assumption?
func ReadDNSQuestionFromBuffer( requestBuffer *bytes.Buffer, noQuestions uint16 ) (*models.DNSQuestion, error) {

	var question models.DNSQuestion

	// early bail out.
	if noQuestions == 0 {
		return &question, nil
	}

	domainName, _ := readNonCompressedDomainName(requestBuffer)

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
func ReadDNSResourceRecordFromBuffer( requestBuffer *bytes.Buffer, noResourceRecords uint16, packetBytes []byte ) ([]models.DNSResourceRecord, error) {

	records := make([]models.DNSResourceRecord, noResourceRecords)

	var i uint16
	for i = 0 ; i< noResourceRecords ;i++ {
		name, err  := readDomainName(requestBuffer, packetBytes)

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
		record.QType = models.QType(rrType)
		record.QClass = models.QClass(rrClass)
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

	header.ANCount = uint16( len( dnsPacket.answers))
	header.NSCount = uint16( len( dnsPacket.authority))
	header.ADCount = uint16( len( dnsPacket.additional))
  header.QDCount = 1

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

func GenerateDNSHeader( id uint16, domainName string, isResponse bool, opCode models.OpCode, isTruncated bool, isRecursive bool) models.DNSHeader {

	h := models.DNSHeader{}

	h.ID = id // common id as original.
  h.MiscFlags = GenerateFlags(isResponse, opCode, isTruncated, isRecursive)
  h.QDCount = 1  // assumption we'll only deal with 1 query at a time.
  h.ANCount = 0
  h.NSCount = 0
  h.ADCount = 0

	return h
}

func GenerateARecordRequest( id uint16, domainName string, recursive bool ) (DNSPacket, error ) {

	dnsPacket := NewDNSPacket()
	dnsPacket.header = GenerateDNSHeader( id, domainName, false, models.OpCodeStandard, false, recursive)
	dnsPacket.question = GenerateDNSQuestion(domainName, models.ARecord, models.QCIN )

	return dnsPacket, nil
}









