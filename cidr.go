package main

import (
	"fmt"
	"math"
	"net"
)

// SentinelSize is returned by CIDRSize for ranges too large to count (≥64 host bits).
// It signals "uncountably large" without failing, allowing truncation downstream.
const SentinelSize = math.MaxUint64

// CIDRSize returns the number of addresses in a CIDR block without expanding it.
// Returns SentinelSize for ranges with ≥64 host bits (too large to count).
// Returns an error only if the CIDR is invalid.
func CIDRSize(cidr string) (uint64, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones

	// For very large ranges (e.g., IPv6 /64), return sentinel instead of error
	if hostBits >= 64 {
		return SentinelSize, nil
	}

	return 1 << uint(hostBits), nil
}

// ExpandCIDR returns IP addresses within a CIDR block, up to maxIPs.
// If maxIPs > 0 and the CIDR contains more addresses, truncates to maxIPs.
// For example, "192.168.1.0/30" returns [192.168.1.0, 192.168.1.1, 192.168.1.2, 192.168.1.3]
func ExpandCIDR(cidr string, maxIPs uint64) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	size, err := CIDRSize(cidr)
	if err != nil {
		return nil, err
	}

	// Determine allocation size (can't allocate SentinelSize)
	allocSize := size
	if maxIPs > 0 && (size == SentinelSize || size > maxIPs) {
		allocSize = maxIPs
	}

	// Pre-allocate slice for efficiency
	ips := make([]net.IP, 0, allocSize)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		// Make a copy since incIP modifies in place
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)

		// Truncate if we've hit the limit
		if maxIPs > 0 && uint64(len(ips)) >= maxIPs {
			break
		}
	}

	return ips, nil
}

// ParseCIDRs validates and expands multiple CIDR blocks into a flat list of IPs.
// If maxIPs > 0 and total exceeds the limit, truncates to maxIPs addresses.
func ParseCIDRs(cidrs []string, maxIPs uint64) ([]net.IP, error) {
	// First pass: calculate total size and validate syntax
	var totalSize uint64
	hasHugeRange := false
	for _, cidr := range cidrs {
		size, err := CIDRSize(cidr)
		if err != nil {
			return nil, err
		}
		if size == SentinelSize {
			hasHugeRange = true
		} else if !hasHugeRange {
			// Only accumulate if we haven't hit a sentinel yet
			// (once we have a sentinel, total is effectively infinite)
			newTotal := totalSize + size
			if newTotal < totalSize { // overflow check
				hasHugeRange = true
			} else {
				totalSize = newTotal
			}
		}
	}

	// Determine allocation capacity
	allocCap := totalSize
	if hasHugeRange || (maxIPs > 0 && totalSize > maxIPs) {
		if maxIPs > 0 {
			allocCap = maxIPs
		} else {
			allocCap = 65536 // reasonable default if no limit and huge range
		}
	}

	// Second pass: expand with budget tracking
	allIPs := make([]net.IP, 0, allocCap)
	remaining := maxIPs
	for _, cidr := range cidrs {
		var limit uint64
		if maxIPs > 0 {
			limit = remaining
			if limit == 0 {
				break // budget exhausted
			}
		}
		ips, err := ExpandCIDR(cidr, limit)
		if err != nil {
			return nil, err
		}
		allIPs = append(allIPs, ips...)
		if maxIPs > 0 {
			remaining -= uint64(len(ips))
		}
	}

	return allIPs, nil
}

// copyIP returns a copy of an IP address.
func copyIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

// trailingZeroBits counts trailing zero bits in an IP address.
// This determines the maximum CIDR alignment for a block starting at this IP.
func trailingZeroBits(ip net.IP) int {
	count := 0
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == 0 {
			count += 8
			continue
		}
		b := ip[i]
		for b&1 == 0 {
			count++
			b >>= 1
		}
		break
	}
	return count
}

// findContiguousRuns splits a sorted IP slice into runs of consecutive IPs
// (each pair differs by exactly 1).
func findContiguousRuns(sortedIPs []net.IP) [][]net.IP {
	if len(sortedIPs) == 0 {
		return nil
	}

	var runs [][]net.IP
	start := 0

	for i := 1; i < len(sortedIPs); i++ {
		prev := copyIP(sortedIPs[i-1])
		incIP(prev)
		if !prev.Equal(sortedIPs[i]) {
			runs = append(runs, sortedIPs[start:i])
			start = i
		}
	}
	runs = append(runs, sortedIPs[start:])
	return runs
}

// ContiguousIPsToNetworks converts a sorted, contiguous IP slice into the
// minimal set of CIDR blocks covering them exactly. Uses a greedy algorithm:
// at each position, find the largest power-of-2 aligned block that fits.
func ContiguousIPsToNetworks(ips []net.IP) []*net.IPNet {
	if len(ips) == 0 {
		return nil
	}

	totalBits := len(ips[0]) * 8 // 32 for IPv4, 128 for IPv6
	var networks []*net.IPNet
	pos := 0

	for pos < len(ips) {
		remaining := len(ips) - pos
		alignment := trailingZeroBits(ips[pos])

		// Find the largest power-of-2 block that fits
		blockBits := 0
		for blockBits < alignment && (1<<(blockBits+1)) <= remaining {
			blockBits++
		}

		ones := totalBits - blockBits
		mask := net.CIDRMask(ones, totalBits)
		networks = append(networks, &net.IPNet{
			IP:   copyIP(ips[pos]),
			Mask: mask,
		})

		pos += 1 << blockBits
	}

	return networks
}

// IPsToNetworks converts a sorted IP slice (possibly non-contiguous) into
// CIDR blocks. Splits into contiguous runs first.
func IPsToNetworks(sortedIPs []net.IP) []*net.IPNet {
	var networks []*net.IPNet
	for _, run := range findContiguousRuns(sortedIPs) {
		networks = append(networks, ContiguousIPsToNetworks(run)...)
	}
	return networks
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
