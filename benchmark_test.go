package main

import (
	"bytes"
	"context"
	"net"
	"testing"
)

func BenchmarkExpandCIDR_32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ExpandCIDR("192.168.1.1/32", 0)
	}
}

func BenchmarkExpandCIDR_30(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ExpandCIDR("192.168.1.0/30", 0)
	}
}

func BenchmarkExpandCIDR_24(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ExpandCIDR("192.168.1.0/24", 0)
	}
}

func BenchmarkExpandCIDR_16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ExpandCIDR("192.168.0.0/16", 0)
	}
}

func BenchmarkLookupWorkers(b *testing.B) {
	// Create mock resolver that returns immediately
	resolver := NewMockResolver()
	for i := 0; i < 256; i++ {
		ip := net.IPv4(192, 168, 1, byte(i)).String()
		resolver.AddNXDomain(ip)
	}

	ips, _ := ExpandCIDR("192.168.1.0/24", 0)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resultChan := LookupWorkers(ctx, ips, 50, resolver)
		for range resultChan {
			// drain results
		}
	}
}

func BenchmarkLookupWorkers_Concurrency(b *testing.B) {
	resolver := NewMockResolver()
	for i := 0; i < 256; i++ {
		ip := net.IPv4(192, 168, 1, byte(i)).String()
		resolver.AddNXDomain(ip)
	}

	ips, _ := ExpandCIDR("192.168.1.0/24", 0)
	ctx := context.Background()

	concurrencies := []int{1, 10, 50, 100, 200}
	for _, c := range concurrencies {
		b.Run(string(rune('0'+c/100))+string(rune('0'+c/10%10))+string(rune('0'+c%10)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				resultChan := LookupWorkers(ctx, ips, c, resolver)
				for range resultChan {
				}
			}
		})
	}
}

func BenchmarkFormatText(b *testing.B) {
	results := make([]LookupResult, 256)
	for i := 0; i < 256; i++ {
		results[i] = LookupResult{
			IP:  net.IPv4(192, 168, 1, byte(i)),
			PTR: "host.example.com",
		}
	}

	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = FormatText(&buf, results)
	}
}

func BenchmarkFormatJSON(b *testing.B) {
	results := make([]LookupResult, 256)
	for i := 0; i < 256; i++ {
		results[i] = LookupResult{
			IP:  net.IPv4(192, 168, 1, byte(i)),
			PTR: "host.example.com",
		}
	}

	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = FormatJSON(&buf, results)
	}
}

func BenchmarkSortResults(b *testing.B) {
	// Pre-generate unsorted results
	makeResults := func() []LookupResult {
		results := make([]LookupResult, 256)
		for i := 0; i < 256; i++ {
			// Reverse order to ensure sorting work
			results[i] = LookupResult{
				IP: net.IPv4(192, 168, 1, byte(255-i)),
			}
		}
		return results
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results := makeResults()
		SortResults(results)
	}
}
