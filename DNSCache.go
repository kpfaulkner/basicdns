package main

/*
  Cache for DNSRecords.
  HAVE NOT ATTEMPTED TO MAKE THIS THREAD/GOROUTINE SAFE YET!!!!

 */


import (
	"basicdns/models"
	"errors"
	log "github.com/golang/glog"
)

// DNSCacheReaderWriter is the interface for any caches that will store DNSRecords
type DNSCacheReaderWriter interface {
  Set( qType models.QType, domainName string, record models.DNSRecord ) error

  Get( qType models.QType, domainName string) (*models.DNSRecord, error)
}

// DNSCache is the internal cache used to store the various DNS records.
// Probably just a very simplistic map for now, but will extend if/when needed.
type DNSCache struct {

	// keep different record caches in different maps....  until I figure out a better way.

	// A Records.
	ARecordMap map[string]models.DNSRecord

	// CNAMEs
	CNameRecordMap map[string]models.DNSRecord
}

func NewDNSCache() (DNSCache, error ) {

	c := DNSCache{}
	c.ARecordMap = make(map[string]models.DNSRecord)
	c.CNameRecordMap = make(map[string]models.DNSRecord)

  return c, nil
}

func (d *DNSCache) getRecordMap( qType models.QType ) (map[string]models.DNSRecord, error) {

	if qType == models.ARecord {
		return d.ARecordMap, nil
	}

  if qType == models.CName {
  	return d.CNameRecordMap, nil
  }

  return nil, errors.New("Unable to find appropriate cache")
}

// NOT THREAD SAFE YET
func (d *DNSCache) Set( qType models.QType, domainName string, record models.DNSRecord ) error {
  m, err := d.getRecordMap( qType)
  if err != nil {
  	log.Errorf("Cache set unable to get appropriate cache map %s\n", err)
  	return err
  }

	m[domainName ] = record

	return nil
}

// NOT THREAD SAFE YET
func (d *DNSCache) Get( qType models.QType, domainName string) (*models.DNSRecord, error) {
	m, err := d.getRecordMap( qType)
	if err != nil {
		log.Errorf("Cache get unable to get appropriate cache map %s\n", err)
		return nil, err
	}


	entry, ok := m[domainName]
	if !ok  {
		// map entry doesn't exist.
		// Is this really an error?
		return nil, errors.New("domain does not exist")
	}

	return &entry, nil

}
