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
	"encoding/json"
	log "github.com/golang/glog"
	"io"
	"net/http"
)

// AdminServer provides controls for BasicDNS.
type AdminServer struct {

	// reference to DNS server running
  dnsServer *BasicDNS

}


// RunAdminWebServer runs the admin webserver.... and does adminy stuff.
func RunAdminWebServer(dnsServer *BasicDNS) {

	as := AdminServer{}
  as.dnsServer = dnsServer

	err := as.Run()
	if err != nil {
		log.Fatalf("Admin server died.....  shutting down:  %s\n", err)
	}

}

// clearCache returns a HandlerFunc that does the cache clearing for us.
func (as *AdminServer) clearCache() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		as.dnsServer.ClearCache()
		io.WriteString(w, "cleared cache")
	}
}

// CacheStatistics returns a HandlerFunc that gets stats for cache.
func (as *AdminServer) cacheStatistics() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		stats := as.dnsServer.CacheStats()

		w.Header().Set("Content-Type", "application/json")
		// get a payload p := Payload{d}
		json.NewEncoder(w).Encode(stats)

	}
}


func (as *AdminServer) setupRoutes() error {

	http.HandleFunc("/clearcache", as.clearCache())
	http.HandleFunc("/cachestats", as.cacheStatistics())
	return nil
}


// Run starts the webserver.... and starts answering API calls :)
func (as *AdminServer) Run() error {

	as.setupRoutes()
  http.ListenAndServe(":8080", nil)

	return nil
}
