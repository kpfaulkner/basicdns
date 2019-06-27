package main

/*
  Cache for DNSRecords.
  HAVE NOT ATTEMPTED TO MAKE THIS THREAD/GOROUTINE SAFE YET!!!!

 */

import (
	"basicdns/models"
	"errors"
	log "github.com/golang/glog"
	"time"
)

type CacheEntry struct {
	DNSRec models.DNSRecord
	ExpiryTimeStamp time.Time   // used to validate/expire TTL.
}


// DNSCacheReaderWriter is the interface for any caches that will store DNSRecords
type DNSCacheReaderWriter interface {
  Set( qType models.QType, domainName string, record models.DNSRecord ) error

  Get( qType models.QType, domainName string) (*CacheEntry, bool, error)
}

// DNSCache is the internal cache used to store the various DNS records.
// Probably just a very simplistic map for now, but will extend if/when needed.
// Cache is TTL aware. If on return the TTL has determined to have expired, will return nothing
// as if the cache entry didn't exist. This will force repopulation anyway.
type DNSCache struct {

	// keep different record caches in different maps....  until I figure out a better way.

	// A Records.
	ARecordMap map[string]CacheEntry

	// CNAMEs
	CNameRecordMap map[string]CacheEntry
}

func NewDNSCache() (DNSCache, error ) {

	c := DNSCache{}
	c.ARecordMap = make(map[string]CacheEntry)
	c.CNameRecordMap = make(map[string]CacheEntry)

  return c, nil
}

func (d *DNSCache) getRecordMap( qType models.QType ) (map[string]CacheEntry, error) {

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

  expireTime := time.Now().UTC().Add( time.Duration(record.TTL) * time.Second)
  cacheEntry := CacheEntry{ DNSRec: record, ExpiryTimeStamp: expireTime}
	m[domainName ] = cacheEntry

	return nil
}


// Get returns the entry from the cache.
// Instead of creating custom error types indicating that the entry doesn't exist in the cache (which is NOT an error)
// Will use a bool to indicate if the cache entry existed or not.
// NOT THREAD SAFE YET
func (d *DNSCache) Get( qType models.QType, domainName string) (*CacheEntry, bool, error) {
	m, err := d.getRecordMap( qType)
	if err != nil {
		log.Errorf("Cache get unable to get appropriate cache map %s\n", err)
		return nil, false, err
	}

	entry, ok := m[domainName]
	if !ok  {
		// map entry doesn't exist.
		return nil, false, nil
	}

	// check if expired. If expired, clear cache and return as if it never existed.....
	if entry.ExpiryTimeStamp.After(time.Now().UTC()) {
    // clear out cache for this entry.
		delete(m, domainName)
		return nil, false, nil
	}

	return &entry, true, nil

}
