package main

/*
  Cache for DNSRecords.
  HAVE NOT ATTEMPTED TO MAKE THIS THREAD/GOROUTINE SAFE YET!!!!

 */

import (
	"github.com/kpfaulkner/basicdns/models"
	"sync"
	"time"
)

type CacheEntry struct {
	DNSRec DNSPacket
	ExpiryTimeStamp time.Time   // used to validate/expire TTL.
}

type QTypeCache map[string]CacheEntry

// DNSCacheReaderWriter is the interface for any caches that will store DNSRecords
type DNSCacheReaderWriter interface {
	Set( qType models.QType, domainName string, record DNSPacket ) error
	Get( qType models.QType, domainName string) (*CacheEntry, bool, error)
	Clear() error
	Stats() CacheStats
}


type CacheStats struct {
  NoARecords int
  NoCNames int

}

// DNSCache is the internal cache used to store the various DNS records.
// Probably just a very simplistic map for now, but will extend if/when needed.
// Cache is TTL aware. If on return the TTL has determined to have expired, will return nothing
// as if the cache entry didn't exist. This will force repopulation anyway.
type DNSCache struct {

	// keep different record caches in different maps....  until I figure out a better way.

	// First lookup is based on QType... then its domain -> CacheEntry
	cache map[models.QType]QTypeCache

	// lock for get/set. Allow multi reader at once.
	lock sync.RWMutex

}

func NewDNSCache() (DNSCache, error ) {

	c := DNSCache{}
	c.cache = make(map[models.QType]QTypeCache)

  return c, nil
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


  allRRs := append( record.answers, record.authority...)
	allRRs = append(allRRs, record.additional...)

  minTTL := getMinTTLFromRecordResources( allRRs)
  expireTime := time.Now().UTC().Add( time.Duration(minTTL) * time.Second)
  cacheEntry := CacheEntry{ DNSRec: record, ExpiryTimeStamp: expireTime}

  // WWWWWAAAAAAAAYYYYYYYYYY too much happening inside the lock.
  // until its a problem will leave it
	d.lock.Lock()

	// ugly... need something more atomic.
	// cache to write against.
  var qCache QTypeCache
  var ok bool

	if qCache, ok = d.cache[qType]; !ok {
		d.cache[qType] = QTypeCache{}
		qCache = d.cache[qType]
	}
	qCache[domainName] = cacheEntry
	d.lock.Unlock()

	return nil
}


// Get returns the entry from the cache.
// Instead of creating custom error types indicating that the entry doesn't exist in the cache (which is NOT an error)
// Will use a bool to indicate if the cache entry existed or not.
// NOT THREAD SAFE YET
func (d *DNSCache) Get( qType models.QType, domainName string) (*CacheEntry, bool, error) {

	// cache to write against.
	cache := d.cache[ qType]

	d.lock.RLock()
	defer d.lock.RUnlock()

	entry, ok := cache[domainName]
	if !ok  {
		// map entry doesn't exist.
		return nil, false, nil
	}

	// check if expired. If expired, clear cache and return as if it never existed.....
	if entry.ExpiryTimeStamp.Before(time.Now().UTC()) {
    // clear out cache for this entry.
		delete(cache, domainName)
		return nil, false, nil
	}

	return &entry, true, nil
}

func (d *DNSCache) Clear() error {

	d.lock.Lock()

	//d.cache = make(map[models.QType]QTypeCache)
	for k := range d.cache {
		delete(d.cache, k)
	}

	d.lock.Unlock()
	return nil
}

func (d *DNSCache) Stats() CacheStats {

	stats := CacheStats{}
	stats.NoARecords = len(d.cache[ models.ARecord])
	stats.NoCNames = len(d.cache[ models.CName])

	return stats
}




