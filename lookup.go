package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// LookupResult holds the result of a PTR lookup.
type LookupResult struct {
	IP    net.IP
	PTR   string // Empty if no PTR record found
	Error error  // Non-nil if lookup failed (not NXDOMAIN)
}

// Resolver abstracts DNS lookups for testing.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// NetResolver wraps net.Resolver to implement our Resolver interface.
type NetResolver struct {
	*net.Resolver
}

func (r *NetResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return r.Resolver.LookupAddr(ctx, addr)
}

// DefaultResolver returns a resolver using the system DNS.
func DefaultResolver() Resolver {
	return &NetResolver{&net.Resolver{}}
}

// CustomResolver returns a resolver that queries the given DNS server.
// The server can be an IP, hostname, or host:port. If no port is given, :53 is used.
// normalizeServer ensures a server address has a port, defaulting to :53.
func normalizeServer(server string) (string, error) {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// Assume bare host/IP without port
		host = server
		port = "53"
	}
	if port == "" {
		port = "53"
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("invalid DNS server address %q: empty hostname", server)
	}
	addr := net.JoinHostPort(host, port)
	// Validate the result is well-formed
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("invalid DNS server address %q: %w", server, err)
	}
	return addr, nil
}

func CustomResolver(server string) (Resolver, error) {
	server, err := normalizeServer(server)
	if err != nil {
		return nil, err
	}
	return &NetResolver{&net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", server)
		},
	}}, nil
}

// LookupWorkers performs concurrent PTR lookups using a worker pool.
// Results are sent to the returned channel as they complete.
func LookupWorkers(ctx context.Context, ips []net.IP, concurrency int, resolver Resolver) <-chan LookupResult {
	results := make(chan LookupResult, len(ips))
	jobs := make(chan net.IP, len(ips))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				result := lookupIP(ctx, ip, resolver)
				results <- result
			}
		}()
	}

	// Send jobs
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()

	// Close results when all workers done
	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// lookupIP performs a single PTR lookup.
func lookupIP(ctx context.Context, ip net.IP, resolver Resolver) LookupResult {
	names, err := resolver.LookupAddr(ctx, ip.String())

	result := LookupResult{IP: ip}

	if err != nil {
		// Check if it's a "not found" error (NXDOMAIN)
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			// NXDOMAIN is not an error, just no PTR record
			return result
		}
		result.Error = err
		return result
	}

	if len(names) > 0 {
		// Return first PTR record, strip trailing dot
		ptr := names[0]
		if len(ptr) > 0 && ptr[len(ptr)-1] == '.' {
			ptr = ptr[:len(ptr)-1]
		}
		result.PTR = ptr
	}

	return result
}
