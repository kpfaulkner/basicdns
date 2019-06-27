package main

/*
Copyright 2019 Ken Faulkner

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


  BasicDNS. This is a simple hobby/toy DNS server which is super heavily inspired by:
    - https://routley.io/tech/2017/12/28/hand-writing-dns-messages.html
    - https://github.com/dlorch/dnsserver   Brilliantly simple example of DNS lookup, but more importantly a good binary
      encoding and UDP example.
    - http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html

*/


import (
	"basicdns/models"
	"bytes"
	"encoding/binary"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"strings"
	"sync"
)



const (
	MaxPacketSizeInBytes int=512
	DNSPort int = 10053
)

// BasicDNS is the core of the simple DNS server.
// This maintains goroutine pool for incoming requests amongst other things.
type BasicDNS struct {
  wg sync.WaitGroup
  requestChannel chan models.RawDNSRequest // requests to go routines will come through the channel.

  numResolverGoRoutines int

  // cache... simplistic one for now.
  cache DNSCacheReaderWriter

  upstreamDNS UpstreamDNS
}

// NewBasicDNS Create new instance, initialise pool of goroutines etc.
func NewBasicDNS(poolSize int ) (*BasicDNS, error) {
	b := BasicDNS{}
  b.numResolverGoRoutines = poolSize

	// channel size of 1000.....  need to figure out what is the best size here.
	requests := make(chan models.RawDNSRequest, 1000)
	b.requestChannel = requests
	cache := DNSCache{}
	b.cache = &cache

	ud,_ :=  NewUpstreamDNS("1.1.1.1", 53)
	b.upstreamDNS = *ud

	return &b, nil
}

// readQueryDetails reads the domain names from the question section.
// also returns QType and QClass
func readQueryDetails(requestBuffer *bytes.Buffer) (*models.DNSQuestion, error) {

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
			return nil, err
		}
		domainSegments = append(domainSegments, string(byteSlice))
	}

	// reads QType and QClass
	qType := models.QType(binary.BigEndian.Uint16(requestBuffer.Next(2)))
	qClass := models.QClass(binary.BigEndian.Uint16(requestBuffer.Next(2)))

	req := models.DNSQuestion{}
	req.Domain = strings.Join(domainSegments, ".")
	req.QT = qType
	req.QC = qClass

	return &req, nil
}

// readRequest converts the bytearray to the DNSRequest format.
func readRequest( requestBuffer *bytes.Buffer) (*models.DNSRequest, error) {

	var header models.DNSHeader
	err := binary.Read(requestBuffer, binary.BigEndian, &header)
	if err != nil {
		log.Errorf("Cannot decode header %s\n", err)
		log.Errorf("Will not process this request\n") // what should we return to the caller?  Any appropriate error code?

		return nil, err
	}

	request := models.DNSRequest{}

	log.Infof("number of queries %d\n", header.QDCount)

	// loop through and read all record requests.
	for i:=uint16(0); i< header.QDCount; i++ {
		req,err  := readQueryDetails(requestBuffer)
		if err != nil {
			log.Errorf("error while reading domain %s\n", err)
		}

		log.Infof("have query for %s\n", req.Domain)
		request.QuerySlice = append( request.QuerySlice, *req)
	}

	return &request, nil
}

// sendNotImplemented will send RCODE 4 (not implemented)
func sendNotImplemented(conn *net.UDPConn, clientAddr *net.UDPAddr ) {

}

// sendDNSPacketesponse sends the DNSPacket to the clientAddr.
func sendDNSPacketResponse( record DNSPacket,conn *net.UDPConn, clientAddr *net.UDPAddr ) error {


	return nil
}

func (b *BasicDNS) processARecordRequest(dnsPacket DNSPacket, conn *net.UDPConn, clientAddr *net.UDPAddr ) {

	var newDNSPacket DNSPacket

	// check cache
	record, recordExists, err := b.cache.Get( models.ARecord, dnsPacket.question.Domain)
	if err != nil {
    // cannot work... return not implemented for moment!
    sendNotImplemented( conn, clientAddr)
    return
	}


	if !recordExists{

		// if allowed to check upstream, do it.
		if dnsPacket.header.MiscFlags & models.RD != 0 {
			// query upstream DNS server, record into cache.
			// perform ARecord lookup.
			// store in cache
			// return to sender....    address unknown.
			//record, err := b.upstreamDNS.GetARecord( dnsPacket)
			newDNSPacket, err := b.upstreamDNS.GetARecord(dnsPacket.question.Domain)

			if err != nil {
				// unable to get ARecord..... kaboom?
				// TODO(kpfaulkner)
			}
			b.cache.Set( models.ARecord, dnsPacket.question.Domain, *newDNSPacket)
		} else {
			// no recursion wanted.
			// return with no answer.

    }
	} else {
		newDNSPacket = record.DNSRec
	}

	sendDNSPacketResponse( newDNSPacket, conn, clientAddr)
}

func (b *BasicDNS) processCNameRequest(dnsPacket DNSPacket, conn *net.UDPConn, clientAddr *net.UDPAddr ) {

}

// processDNSRequest is where the work happens.
// Reads the incoming request channel, decodes the request, processes, then returns reponse.
//
// First version will only handle a SINGLE question in the DNS request.
// Unsure how we should handle multiple. (or how to test it). Baby steps..
func (b *BasicDNS) processDNSRequest(conn *net.UDPConn, requestChannel chan models.RawDNSRequest) {

	for {
		request, ok := <-requestChannel
		if !ok {
			b.wg.Done()

			// closed.....  time to leave!!
			return
		}

		var requestBuffer = bytes.NewBuffer(request.RawBytes)

		dnsPacket,err  := ReadDNSPacketFromBuffer( requestBuffer)
		if err != nil {
			log.Errorf("unable to process request... BOOOOOM  %s\n", err)
			sendNotImplemented( conn, request.ClientAddr)
			continue
		}

		log.Infof("packet is %v\n", dnsPacket)



		// only process first request until I figure out how to handle multiple questions from request packet.
		switch dnsPacket.question.QT {

		  case models.ARecord : {
		  	b.processARecordRequest(  *dnsPacket, conn, request.ClientAddr)
		  }
		  case models.CName : {
			  b.processCNameRequest( *dnsPacket, conn, request.ClientAddr)
		  }

		  default:
			  log.Errorf("Not dealing with anything other than A and CNAME lookups so far!\n")
			  sendNotImplemented( conn, request.ClientAddr)
		}

	}
}

// createHandlerPool will create a pool of go routines that handle the incoming requests.
func (b BasicDNS) createHandlerPool( conn *net.UDPConn ) {
	for i:=0;i< b.numResolverGoRoutines ;i++ {
    go b.processDNSRequest( conn, b.requestChannel )
	}
}

// RunServer is the main loop for the DNS server.
// accept connections and passes off to go routines for processing.
func (b BasicDNS) RunServer() {

	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", DNSPort))
	if err != nil {
		log.Fatalf("Unable to resolve UDP address %s\n", err)
	}

	conn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		log.Fatalf("Unable to listen %s\n", err.Error())
	}

	defer conn.Close()

	// About to add numResolverGoRoutines added.
	b.wg.Add( b.numResolverGoRoutines)
	b.createHandlerPool(conn)

	// request coming in. Allocated bytes up front.
	// reading request from main thread.... will this be a bottleneck?
	requestBuffer := make([]byte, MaxPacketSizeInBytes)

	for {
		_, clientAddr, err := conn.ReadFromUDP(requestBuffer)

		if err != nil {
			log.Errorf("Unable to read request bytes %s\n", err)
			// failed, so need to figure out what to return? For now....  afraid we'll just drop it.
			continue
		}

		request := models.RawDNSRequest{ requestBuffer, clientAddr}
		b.requestChannel <- request
	}

	// although shouldn't leave the for loop above, make sure wg is handled properly.
	b.wg.Wait()

}
