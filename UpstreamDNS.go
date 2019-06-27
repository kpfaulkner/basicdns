package main

import (
	"context"
	"errors"
	"net"
)

type UpstreamDNS struct {
	resolver *net.Resolver
}

func NewUpstreamDNS( nameserver string) UpstreamDNS {
  u := UpstreamDNS{}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", net.JoinHostPort(nameserver, "53"))
		},
	}

	u.resolver = resolver
	return u
}

// GetARecord returns
func (u UpstreamDNS) GetARecord(domainName string) (string, error) {
	ipRecords, _ := u.resolver.LookupIPAddr( context.Background(), domainName)

	for _, ip := range ipRecords {
		ipv4 := ip.IP.To4()
		if ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", errors.New("unable to find IPV4 address")
}

func (u UpstreamDNS) GetCNAME( domainName string) (string, error) {
  cname, err := u.resolver.LookupCNAME(context.Background(), domainName)

  if err != nil {
  	return "", err
	}

  return cname, nil
}

func (u UpstreamDNS) GetPtr( ip string) ([]string, error) {
	ptr, err := u.resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return nil, err
	}

	return ptr, nil
}

func (u UpstreamDNS) GetNameServer( domainName string) ([]string, error) {
	ns, err := u.resolver.LookupNS(context.Background(), domainName)
	if err != nil {
		return nil, err
	}

	nameServers := []string{}
  for _,i := range ns {
  	nameServers = append(nameServers, i.Host)
  }

	return nameServers, nil
}




