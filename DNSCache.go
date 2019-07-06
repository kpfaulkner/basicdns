package main

/*
  Cache for DNSRecords.
  HAVE NOT ATTEMPTED TO MAKE THIS THREAD/GOROUTINE SAFE YET!!!!

 */

import (
	"github.com/kpfaulkner/basicdns/models"
	"errors"
	"sync"
	"time"
	log "github.com/golang/glog"
)

type CacheEntry struct {
	DNSRec DNSPacket
	ExpiryTimeStamp time.Time   // used to validate/expire TTL.

}


// DNSCacheReaderWriter is the interface for any caches that will store DNSRecords
type DNSCacheReaderWriter interface {
  Set( qType models.QType, domainName string, record DNSPacket ) error

  Get( qType models.QType, domainName string) (CacheEntry, bool, error)
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

	// lock for get/set. Allow multi reader at once.
	lock sync.RWMutex

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

// getMinTTLFromRecordResources get minimum TTL from all record resources supplied
func getMinTTLFromRecordResources( rrArray []models.DNSResourceRecord) uint32 {

	minTTL := uint32(0)
	for _,rr := range rrArray {
		if minTTL == 0 {
			minTTL = rr.TTL
		}

		if rr.TTL < minTTL {
			minTTL = rr.TTL
		}
	}

	return minTTL
}

// Set.... does setty stuff.
// TTL needs to come from either the answer section or the authority....
// need to figure out which one....
func (d *DNSCache) Set( qType models.QType, domainName string, record DNSPacket ) error {

  m, err := d.getRecordMap( qType)
  if err != nil {
  	log.Errorf("Cache set unable to get appropriate cache map %s\n", err)
  	return err
  }

  allRRs := append( record.answers, record.authority...)
	allRRs = append(allRRs, record.additional...)

  minTTL := getMinTTLFromRecordResources( allRRs)
  expireTime := time.Now().UTC().Add( time.Duration(minTTL) * time.Second)
  cacheEntry := CacheEntry{ DNSRec: record, ExpiryTimeStamp: expireTime}
	d.lock.Lock()
	m[domainName] = cacheEntry
	d.lock.Unlock()

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

	d.lock.RLock()
	defer d.lock.RUnlock()

	entry, ok := m[domainName]
	if !ok  {
		// map entry doesn't exist.
		return nil, false, nil
	}

	// check if expired. If expired, clear cache and return as if it never existed.....
	if entry.ExpiryTimeStamp.Before(time.Now().UTC()) {
    // clear out cache for this entry.
		delete(m, domainName)
		return nil, false, nil
	}

	return &entry, true, nil
}
