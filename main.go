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
	"fmt"
	log "github.com/golang/glog"
	"net"
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
}

// NewBasicDNS Create new instance, initialise pool of goroutines etc.
func NewBasicDNS(poolSize int ) (*BasicDNS, error) {
	b := BasicDNS{}
  b.numResolverGoRoutines = poolSize

	// channel size of 1000.....  need to figure out what is the best size here.
	b.requestChannel :=  make(chan models.RawDNSRequest, 1000)

	return &b, nil
}

func processDNSRequest(request []byte, conn *net.UDPConn, client *net.UDPAddr) {

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
		// go handleDNSClient(requestBytes, serverConn, clientAddr) // array is value type (call-by-value), i.e. copied
	}

}

func main() {

	// parse args.

	// run main.


}
