package main

import (
	"fmt"
	"net"
)

// ExpandCIDR returns all IP addresses within a CIDR block.
// For example, "192.168.1.0/30" returns [192.168.1.0, 192.168.1.1, 192.168.1.2, 192.168.1.3]
func ExpandCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		// Make a copy since incIP modifies in place
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	return ips, nil
}

// ParseCIDRs validates and expands multiple CIDR blocks into a flat list of IPs.
func ParseCIDRs(cidrs []string) ([]net.IP, error) {
	var allIPs []net.IP

	for _, cidr := range cidrs {
		ips, err := ExpandCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allIPs = append(allIPs, ips...)
	}

	return allIPs, nil
}

// incIP increments an IP address in place.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
