package main

import (
	"context"
	"errors"
	"net"
	"testing"
)

// MockResolver implements Resolver for testing.
type MockResolver struct {
	results map[string][]string
	errors  map[string]error
}

func NewMockResolver() *MockResolver {
	return &MockResolver{
		results: make(map[string][]string),
		errors:  make(map[string]error),
	}
}

func (m *MockResolver) AddResult(ip string, ptrs ...string) {
	m.results[ip] = ptrs
}

func (m *MockResolver) AddError(ip string, err error) {
	m.errors[ip] = err
}

func (m *MockResolver) AddNXDomain(ip string) {
	m.errors[ip] = &net.DNSError{
		Err:        "no such host",
		Name:       ip,
		IsNotFound: true,
	}
}

func (m *MockResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if err, ok := m.errors[addr]; ok {
		return nil, err
	}
	if ptrs, ok := m.results[addr]; ok {
		return ptrs, nil
	}
	// Default: NXDOMAIN
	return nil, &net.DNSError{
		Err:        "no such host",
		Name:       addr,
		IsNotFound: true,
	}
}

func TestLookupWorkers(t *testing.T) {
	resolver := NewMockResolver()
	resolver.AddResult("192.168.1.1", "host1.example.com.")
	resolver.AddResult("192.168.1.2", "host2.example.com.")
	resolver.AddNXDomain("192.168.1.3")
	resolver.AddError("192.168.1.4", errors.New("timeout"))

	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("192.168.1.2"),
		net.ParseIP("192.168.1.3"),
		net.ParseIP("192.168.1.4"),
	}

	ctx := context.Background()
	resultChan := LookupWorkers(ctx, ips, 2, resolver)

	results := make(map[string]LookupResult)
	for r := range resultChan {
		results[r.IP.String()] = r
	}

	// Check we got all results
	if len(results) != 4 {
		t.Errorf("got %d results, want 4", len(results))
	}

	// Check resolved IP
	if r := results["192.168.1.1"]; r.PTR != "host1.example.com" {
		t.Errorf("192.168.1.1 PTR = %q, want %q", r.PTR, "host1.example.com")
	}

	// Check NXDOMAIN
	if r := results["192.168.1.3"]; r.PTR != "" || r.Error != nil {
		t.Errorf("192.168.1.3 expected NXDOMAIN, got PTR=%q, Error=%v", r.PTR, r.Error)
	}

	// Check error
	if r := results["192.168.1.4"]; r.Error == nil {
		t.Error("192.168.1.4 expected error, got nil")
	}
}

func TestLookupIPStripsDot(t *testing.T) {
	resolver := NewMockResolver()
	resolver.AddResult("192.168.1.1", "host.example.com.")

	ip := net.ParseIP("192.168.1.1")
	result := lookupIP(context.Background(), ip, resolver)

	if result.PTR != "host.example.com" {
		t.Errorf("PTR = %q, want %q (trailing dot should be stripped)", result.PTR, "host.example.com")
	}
}

func TestLookupIPReturnsFirstPTR(t *testing.T) {
	resolver := NewMockResolver()
	resolver.AddResult("192.168.1.1", "first.example.com.", "second.example.com.")

	ip := net.ParseIP("192.168.1.1")
	result := lookupIP(context.Background(), ip, resolver)

	if result.PTR != "first.example.com" {
		t.Errorf("PTR = %q, want %q (should return first record)", result.PTR, "first.example.com")
	}
}

func TestLookupWorkersConcurrency(t *testing.T) {
	// Test that we can handle more IPs than workers
	resolver := NewMockResolver()
	for i := 0; i < 100; i++ {
		ip := net.IPv4(192, 168, 1, byte(i)).String()
		resolver.AddNXDomain(ip)
	}

	ips := make([]net.IP, 100)
	for i := 0; i < 100; i++ {
		ips[i] = net.IPv4(192, 168, 1, byte(i))
	}

	ctx := context.Background()
	resultChan := LookupWorkers(ctx, ips, 10, resolver)

	count := 0
	for range resultChan {
		count++
	}

	if count != 100 {
		t.Errorf("got %d results, want 100", count)
	}
}
