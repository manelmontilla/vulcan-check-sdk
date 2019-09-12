package helpers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/miekg/dns"
)

const (
	dnsConfFilePath      = "/etc/resolv.conf"
	noSuchHostErrorToken = "no such host"
)

var (
	dnsConf *dns.ClientConfig
	// ErrFailedToGetDNSAnswer represents error returned when unable to get a valid answer from the current configured dns
	// servers.
	ErrFailedToGetDNSAnswer = errors.New("failed to get a valid answer")
	reservedIPV4s           = []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	reservedIPV6s = []string{
		"::1/128",
		"64:ff9b::/96",
		"100::/64",
		"2001::/32",
		"2001:20::/28",
		"2001:db8::/32",
		"2002::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	NotScannableNetsIPV4 []*net.IPNet
	NotScannableNetsIPV6 []*net.IPNet
)

func init() {
	// Add the reserved ip v4 nets as not scannable.
	for _, ip := range reservedIPV4s {
		_, reserved, _ := net.ParseCIDR(ip) // nolint
		NotScannableNetsIPV4 = append(NotScannableNetsIPV4, reserved)
	}

	// Add the reserved ip v6 nets as not scannable.
	for _, ip := range reservedIPV6s {
		_, reserved, _ := net.ParseCIDR(ip) // nolint
		NotScannableNetsIPV6 = append(NotScannableNetsIPV6, reserved)
	}
}

// Target represents a target received by a check. d
type Target struct {
	Value      string
	hostname   *bool
	domainName *bool
}

// IsHostname returns true if a target is not an IP but can be resolved to an IP.
func (t Target) IsHostname() (bool, error) {
	if t.hostname != nil {
		return *t.hostname, nil
	}
	// If the target is an IP can not be a hostname
	if t.IsIP() {
		is := false
		t.hostname = &is
		return *t.hostname, nil
	}

	r, err := net.LookupIP(t.Value)
	if err != nil {
		// We want to differentiate the error: errNoSuchHost = errors.New("no such host")
		// defined in the package net but, as is not exported, we need to fallback to
		// compare the string description of the error. This not a good practice but it's the
		// only thing we can do by now.
		if strings.Contains(err.Error(), noSuchHostErrorToken) {
			return false, nil
		}
		return false, err
	}
	is := len(r) > 0
	t.hostname = &is
	return *t.hostname, nil
}

// IsIP returns true if current value of the target is an IP.
func (t Target) IsIP() bool {
	return net.ParseIP(t.Value) != nil
}

// IsCIDR returns true if current value of the target is an CIDR.
func (t Target) IsCIDR() bool {
	_, _, err := net.ParseCIDR(t.Value)
	return err == nil
}

// IsURL returns true if current value of the target is an URL.
func (t Target) IsURL() bool {
	_, err := url.ParseRequestURI(t.Value)
	return err == nil
}

// IsAWSAccount returns true if current value of the target is an AWS account.
func (t Target) IsAWSAccount() bool {
	_, err := arn.Parse(t.Value)
	return err == nil
}

// IsDockerImage returns true if current value of the target is a Docker image.
// Approach:
// * split identifier on first "/"
// * verify that first element contains a "." (registry domain)
// * split second element by ":"
// * verify that it has two elements (image and tag)
func (t Target) IsDockerImage() bool {
	slashSplit := strings.SplitAfterN(t.Value, "/", 2)
	if len(slashSplit) > 1 {
		if strings.Contains(slashSplit[0], ".") {
			targetSplit := strings.Split(slashSplit[1], ":")
			if len(targetSplit) == 2 {
				return true
			}
		}
	}
	return false
}

// IsDomainName returns true if a query to a domain server returns a SOA record for the target.
func (t Target) IsDomainName() (bool, error) {
	if t.domainName != nil {
		return *t.domainName, nil
	}

	// If the target is an IP can not be a DomainName.
	if t.IsIP() {
		return false, nil
	}

	is, err := IsDomainName(t.Value)
	if err != nil {
		return false, err
	}
	t.domainName = &is
	return *t.domainName, nil
}

// IsDomainName returns true if a query to a domain server returns a SOA record for the
// asset value.
func IsDomainName(asset string) (bool, error) {
	return hasSOARecord(asset)
}

func hasSOARecord(address string) (bool, error) {
	var err error
	// Read the local dns server config only the first time.
	if dnsConf == nil {
		dnsConf, err = dns.ClientConfigFromFile(dnsConfFilePath)
		if err != nil {
			return false, err
		}
	}
	m := &dns.Msg{}
	address = address + "."
	m.SetQuestion(address, dns.TypeSOA)
	c := dns.Client{}
	var r *dns.Msg
	// Try to get an answer using local configured dns servers.
	for _, srv := range dnsConf.Servers {
		r = nil
		r, _, err = c.Exchange(m, fmt.Sprintf("%s:%s", srv, dnsConf.Port))
		if err != nil {
			return false, err
		}

		if r.Rcode == dns.RcodeSuccess && r != nil {
			break
		}
	}
	if r == nil {
		return false, ErrFailedToGetDNSAnswer
	}
	return soaHeaderForName(r, address), nil
}

func soaHeaderForName(r *dns.Msg, name string) bool {
	for _, a := range r.Answer {
		h := a.Header()
		if h.Name == name && h.Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// IsScannable tells you whether an asset can be scanned or not,
// based in its type and value.
// The goal it's to prevent scanning hosts that are not public.
// Limitation: as the asset type is not available the function
// tries to guess the asset type, and that can lead to the scenario
// where we want to scan a domain that also is a hostname which
// resolves to a private IP. In that case the domain won't be scanned
// while it should.
func IsScannable(asset string) bool {
	t := Target{Value: asset}

	if t.IsIP() || t.IsCIDR() {
		log.Printf("%s is IP or CIDR", t.Value)
		ok, _ := isAllowed(t.Value) // nolint
		return ok
	}

	if t.IsURL() {
		u, _ := url.ParseRequestURI(t.Value) // nolint
		asset = u.Hostname()
	}

	addrs, _ := net.LookupHost(asset) // nolint

	return verifyIPs(addrs)
}

func verifyIPs(addrs []string) bool {
	for _, addr := range addrs {
		if ok, err := isAllowed(addr); err != nil || !ok {
			return false
		}
	}
	return true
}

func isAllowed(addr string) (bool, error) {
	addrCIDR := addr
	var nets []*net.IPNet
	if strings.Contains(addr, ".") {
		if !strings.Contains(addr, "/") {
			addrCIDR = fmt.Sprintf("%s/32", addr)
		}
		nets = NotScannableNetsIPV4
	} else {
		if !strings.Contains(addr, "/") {
			addrCIDR = fmt.Sprintf("%s/128", addr)
		}
		nets = NotScannableNetsIPV6
	}
	_, addrNet, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		return false, fmt.Errorf("error parsing the ip address %s", addr)
	}
	for _, n := range nets {
		if n.Contains(addrNet.IP) {
			return false, nil
		}
	}
	return true, nil
}
