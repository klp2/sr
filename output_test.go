package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestFilterResults(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("192.168.1.1"), PTR: "host1.example.com"},
		{IP: net.ParseIP("192.168.1.2"), PTR: ""}, // NXDOMAIN
		{IP: net.ParseIP("192.168.1.3"), PTR: "host3.example.com"},
		{IP: net.ParseIP("192.168.1.4"), PTR: "", Error: errors.New("error")}, // Error, not NXDOMAIN
	}

	tests := []struct {
		name    string
		opts    OutputOptions
		wantLen int
	}{
		{
			name:    "no filter",
			opts:    OutputOptions{},
			wantLen: 4,
		},
		{
			name:    "resolved only",
			opts:    OutputOptions{ResolvedOnly: true},
			wantLen: 2, // host1 and host3
		},
		{
			name:    "nxdomain only",
			opts:    OutputOptions{NXDomainOnly: true},
			wantLen: 1, // only 192.168.1.2 (error doesn't count)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterResults(results, tt.opts)
			if len(filtered) != tt.wantLen {
				t.Errorf("FilterResults got %d results, want %d", len(filtered), tt.wantLen)
			}
		})
	}
}

func TestSortResults(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("192.168.1.10")},
		{IP: net.ParseIP("192.168.1.2")},
		{IP: net.ParseIP("192.168.1.1")},
		{IP: net.ParseIP("10.0.0.1")},
	}

	SortResults(results)

	expected := []string{"10.0.0.1", "192.168.1.1", "192.168.1.2", "192.168.1.10"}
	for i, want := range expected {
		if results[i].IP.String() != want {
			t.Errorf("results[%d] = %s, want %s", i, results[i].IP, want)
		}
	}
}

func TestFormatText(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("192.168.1.1"), PTR: "host1.example.com"},
		{IP: net.ParseIP("192.168.1.2"), PTR: ""},
		{IP: net.ParseIP("192.168.1.3"), Error: errors.New("timeout")},
	}

	var buf bytes.Buffer
	err := FormatText(&buf, results)
	if err != nil {
		t.Fatalf("FormatText error: %v", err)
	}

	output := buf.String()

	// Check PTR record line
	if !strings.Contains(output, "192.168.1.1") || !strings.Contains(output, "host1.example.com") {
		t.Errorf("output missing PTR record line")
	}

	// Check NXDOMAIN line
	if !strings.Contains(output, "192.168.1.2") || !strings.Contains(output, "NXDOMAIN") {
		t.Errorf("output missing NXDOMAIN line")
	}

	// Check error line
	if !strings.Contains(output, "192.168.1.3") || !strings.Contains(output, "ERROR") {
		t.Errorf("output missing error line")
	}
}

func TestFormatTextIPv6(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("2001:4860:4860::8888"), PTR: "dns.google"},
		{IP: net.ParseIP("2001:db8::1"), PTR: ""},
	}

	var buf bytes.Buffer
	err := FormatText(&buf, results)
	if err != nil {
		t.Fatalf("FormatText error: %v", err)
	}

	output := buf.String()

	// Check IPv6 addresses are present
	if !strings.Contains(output, "2001:4860:4860::8888") {
		t.Errorf("output missing IPv6 address")
	}
	if !strings.Contains(output, "dns.google") {
		t.Errorf("output missing PTR for IPv6")
	}
	if !strings.Contains(output, "2001:db8::1") {
		t.Errorf("output missing second IPv6 address")
	}
}

func TestFormatTextMixedAlignment(t *testing.T) {
	// Test that mixed IPv4/IPv6 results align properly
	results := []LookupResult{
		{IP: net.ParseIP("8.8.8.8"), PTR: "dns.google"},
		{IP: net.ParseIP("2001:4860:4860::8888"), PTR: "dns.google"},
	}

	var buf bytes.Buffer
	err := FormatText(&buf, results)
	if err != nil {
		t.Fatalf("FormatText error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}

	// The IPv6 address is longer, so both lines should have the same alignment
	// Find where "dns.google" starts in each line
	pos1 := strings.Index(lines[0], "dns.google")
	pos2 := strings.Index(lines[1], "dns.google")

	if pos1 != pos2 {
		t.Errorf("misaligned columns: IPv4 PTR at %d, IPv6 PTR at %d\nlines:\n%s", pos1, pos2, buf.String())
	}
}

func TestFormatJSON(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("192.168.1.1"), PTR: "host1.example.com"},
		{IP: net.ParseIP("192.168.1.2"), PTR: ""},
		{IP: net.ParseIP("192.168.1.3"), Error: errors.New("timeout")},
	}

	var buf bytes.Buffer
	err := FormatJSON(&buf, results)
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}

	var jsonResults []JSONResult
	if err := json.Unmarshal(buf.Bytes(), &jsonResults); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(jsonResults) != 3 {
		t.Errorf("got %d JSON results, want 3", len(jsonResults))
	}

	// Check PTR record
	if jsonResults[0].PTR == nil || *jsonResults[0].PTR != "host1.example.com" {
		t.Errorf("jsonResults[0].PTR = %v, want host1.example.com", jsonResults[0].PTR)
	}

	// Check NXDOMAIN (null ptr)
	if jsonResults[1].PTR != nil {
		t.Errorf("jsonResults[1].PTR = %v, want nil", jsonResults[1].PTR)
	}

	// Check error
	if jsonResults[2].Error == nil {
		t.Error("jsonResults[2].Error = nil, want error message")
	}
}

func TestWriteOutput(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("192.168.1.10")},
		{IP: net.ParseIP("192.168.1.2")},
		{IP: net.ParseIP("192.168.1.1"), PTR: "host.example.com"},
	}

	t.Run("sorted text", func(t *testing.T) {
		var buf bytes.Buffer
		opts := OutputOptions{Format: "text", Sort: true, Expand: true}
		if err := WriteOutput(&buf, results, opts); err != nil {
			t.Fatalf("WriteOutput error: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 3 {
			t.Errorf("got %d lines, want 3", len(lines))
		}

		// First should be 192.168.1.1 (sorted)
		if !strings.HasPrefix(lines[0], "192.168.1.1") {
			t.Errorf("first line = %q, want to start with 192.168.1.1", lines[0])
		}
	})

	t.Run("filtered resolved only", func(t *testing.T) {
		var buf bytes.Buffer
		opts := OutputOptions{Format: "text", ResolvedOnly: true, Expand: true}
		if err := WriteOutput(&buf, results, opts); err != nil {
			t.Fatalf("WriteOutput error: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Errorf("got %d lines, want 1 (resolved only)", len(lines))
		}
	})
}

func TestConsolidateResults(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("10.0.0.0").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.1").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.2").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.3").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.4").To4(), PTR: ""},                             // NXDOMAIN
		{IP: net.ParseIP("10.0.0.5").To4(), PTR: "other.example.com"},            // different PTR
		{IP: net.ParseIP("10.0.0.6").To4(), PTR: "", Error: errors.New("error")}, // error
	}

	consolidated := ConsolidateResults(results)

	// Should produce: 10.0.0.0/30 host.example.com, 10.0.0.4/32 NXDOMAIN, 10.0.0.5/32 other, 10.0.0.6/32 error
	if len(consolidated) != 4 {
		var lines []string
		for _, c := range consolidated {
			lines = append(lines, c.Network.String()+" "+c.PTR)
		}
		t.Fatalf("got %d consolidated results %v, want 4", len(consolidated), lines)
	}

	// Sorted by IP, so 10.0.0.0/30 first
	if consolidated[0].Network.String() != "10.0.0.0/30" {
		t.Errorf("consolidated[0] = %s, want 10.0.0.0/30", consolidated[0].Network)
	}
	if consolidated[0].PTR != "host.example.com" {
		t.Errorf("consolidated[0].PTR = %q, want host.example.com", consolidated[0].PTR)
	}

	// 10.0.0.4/32 NXDOMAIN
	if consolidated[1].Network.String() != "10.0.0.4/32" {
		t.Errorf("consolidated[1] = %s, want 10.0.0.4/32", consolidated[1].Network)
	}
	if consolidated[1].PTR != "" {
		t.Errorf("consolidated[1].PTR = %q, want empty", consolidated[1].PTR)
	}

	// Error entry
	if consolidated[3].Error == nil {
		t.Error("consolidated[3].Error = nil, want error")
	}
}

func TestFormatTextConsolidated(t *testing.T) {
	consolidated := []ConsolidatedResult{
		{
			Network: mustParseCIDR("10.0.0.0/30"),
			PTR:     "host.example.com",
		},
		{
			Network: mustParseCIDR("10.0.0.4/32"),
		},
		{
			Network: mustParseCIDR("10.0.0.5/32"),
			PTR:     "other.example.com",
		},
	}

	var buf bytes.Buffer
	err := FormatTextConsolidated(&buf, consolidated)
	if err != nil {
		t.Fatalf("FormatTextConsolidated error: %v", err)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3:\n%s", len(lines), output)
	}

	// Single IP should not have /32 suffix
	if strings.Contains(lines[1], "/32") {
		t.Errorf("single IP should not show /32: %s", lines[1])
	}

	// CIDR should show /30
	if !strings.Contains(lines[0], "10.0.0.0/30") {
		t.Errorf("CIDR missing /30: %s", lines[0])
	}

	// Check alignment: PTR values should start at the same column
	pos1 := strings.Index(lines[0], "host.example.com")
	pos2 := strings.Index(lines[1], "NXDOMAIN")
	if pos1 != pos2 {
		t.Errorf("misaligned columns: %d vs %d", pos1, pos2)
	}
}

func TestFormatJSONConsolidated(t *testing.T) {
	consolidated := []ConsolidatedResult{
		{
			Network: mustParseCIDR("10.0.0.0/30"),
			PTR:     "host.example.com",
		},
		{
			Network: mustParseCIDR("10.0.0.4/32"),
		},
		{
			Network: mustParseCIDR("10.0.0.5/32"),
			Error:   errors.New("timeout"),
		},
	}

	var buf bytes.Buffer
	err := FormatJSONConsolidated(&buf, consolidated)
	if err != nil {
		t.Fatalf("FormatJSONConsolidated error: %v", err)
	}

	var jsonResults []ConsolidatedJSONResult
	if err := json.Unmarshal(buf.Bytes(), &jsonResults); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, buf.String())
	}

	if len(jsonResults) != 3 {
		t.Fatalf("got %d results, want 3", len(jsonResults))
	}

	// CIDR entry
	if jsonResults[0].Network != "10.0.0.0/30" {
		t.Errorf("network = %s, want 10.0.0.0/30", jsonResults[0].Network)
	}
	if jsonResults[0].PTR == nil || *jsonResults[0].PTR != "host.example.com" {
		t.Errorf("PTR = %v, want host.example.com", jsonResults[0].PTR)
	}

	// Single IP (NXDOMAIN) — should show plain IP, not /32
	if jsonResults[1].Network != "10.0.0.4" {
		t.Errorf("network = %s, want 10.0.0.4", jsonResults[1].Network)
	}
	if jsonResults[1].PTR != nil {
		t.Errorf("PTR = %v, want nil", jsonResults[1].PTR)
	}

	// Error entry
	if jsonResults[2].Error == nil {
		t.Error("error = nil, want error")
	}
}

func TestWriteOutputConsolidated(t *testing.T) {
	results := []LookupResult{
		{IP: net.ParseIP("10.0.0.0").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.1").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.2").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.3").To4(), PTR: "host.example.com"},
	}

	var buf bytes.Buffer
	opts := OutputOptions{Format: "text"} // Expand: false (default)
	if err := WriteOutput(&buf, results, opts); err != nil {
		t.Fatalf("WriteOutput error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1 (consolidated): %s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "10.0.0.0/30") {
		t.Errorf("expected consolidated CIDR, got: %s", lines[0])
	}
}

func TestExtractPTRPattern(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		ptr  string
		want string
	}{
		// Forward dots: a.b.c.d.suffix
		{
			name: "forward dots",
			ip:   "64.147.100.1",
			ptr:  "64.147.100.1.static.nyinternet.net",
			want: "*.static.nyinternet.net",
		},
		// Reversed dots: d.c.b.a.suffix
		{
			name: "reversed dots",
			ip:   "64.147.100.1",
			ptr:  "1.100.147.64.static.nyinternet.net",
			want: "*.static.nyinternet.net",
		},
		// Forward dashes in first label: a-b-c-d.suffix
		{
			name: "forward dashes",
			ip:   "192.168.1.10",
			ptr:  "192-168-1-10.example.com",
			want: "*.example.com",
		},
		// Reversed dashes in first label: d-c-b-a.suffix
		{
			name: "reversed dashes",
			ip:   "192.168.1.10",
			ptr:  "10-1-168-192.example.com",
			want: "*.example.com",
		},
		// Embedded with prefix: host-a-b-c-d.suffix
		{
			name: "embedded with prefix",
			ip:   "10.0.0.5",
			ptr:  "host-10-0-0-5.isp.example.com",
			want: "*.isp.example.com",
		},
		// Embedded reversed with prefix: prefix-d-c-b-a.suffix
		{
			name: "embedded reversed with prefix",
			ip:   "10.0.0.5",
			ptr:  "cpe-5-0-0-10.isp.example.com",
			want: "*.isp.example.com",
		},
		// No match: completely different hostname
		{
			name: "no match",
			ip:   "10.0.0.1",
			ptr:  "mail.google.com",
			want: "",
		},
		// Coincidental: only some octets appear
		{
			name: "partial octet match",
			ip:   "10.0.0.1",
			ptr:  "host10.example.com",
			want: "",
		},
		// IPv6: should be skipped
		{
			name: "ipv6 skipped",
			ip:   "2001:db8::1",
			ptr:  "host.example.com",
			want: "",
		},
		// Empty PTR
		{
			name: "empty ptr",
			ip:   "10.0.0.1",
			ptr:  "",
			want: "",
		},
		// Suffix too short (only 1 label)
		{
			name: "suffix too short for dashes",
			ip:   "10.0.0.1",
			ptr:  "10-0-0-1.com",
			want: "",
		},
		{
			name: "suffix too short for dots",
			ip:   "10.0.0.1",
			ptr:  "10.0.0.1.com",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := extractPTRPattern(ip, tt.ptr)
			if got != tt.want {
				t.Errorf("extractPTRPattern(%s, %q) = %q, want %q", tt.ip, tt.ptr, got, tt.want)
			}
		})
	}
}

func TestConsolidateResultsWithPatterns(t *testing.T) {
	// Simulate ISP-style PTR records that embed the IP in reversed dot notation
	results := []LookupResult{
		{IP: net.ParseIP("64.147.100.0").To4(), PTR: "0.100.147.64.static.nyinternet.net"},
		{IP: net.ParseIP("64.147.100.1").To4(), PTR: "1.100.147.64.static.nyinternet.net"},
		{IP: net.ParseIP("64.147.100.2").To4(), PTR: "2.100.147.64.static.nyinternet.net"},
		{IP: net.ParseIP("64.147.100.3").To4(), PTR: "3.100.147.64.static.nyinternet.net"},
	}

	consolidated := ConsolidateResults(results)

	// All 4 IPs should consolidate into a single /30 with the pattern
	if len(consolidated) != 1 {
		var lines []string
		for _, c := range consolidated {
			lines = append(lines, c.Network.String()+" "+c.PTR)
		}
		t.Fatalf("got %d results %v, want 1", len(consolidated), lines)
	}

	if consolidated[0].Network.String() != "64.147.100.0/30" {
		t.Errorf("network = %s, want 64.147.100.0/30", consolidated[0].Network)
	}
	if consolidated[0].PTR != "*.static.nyinternet.net" {
		t.Errorf("PTR = %q, want *.static.nyinternet.net", consolidated[0].PTR)
	}
}

func TestConsolidateResultsPatternThreshold(t *testing.T) {
	// A single IP with a pattern-matching PTR should keep its exact PTR
	results := []LookupResult{
		{IP: net.ParseIP("64.147.100.1").To4(), PTR: "1.100.147.64.static.nyinternet.net"},
	}

	consolidated := ConsolidateResults(results)

	if len(consolidated) != 1 {
		t.Fatalf("got %d results, want 1", len(consolidated))
	}
	if consolidated[0].PTR != "1.100.147.64.static.nyinternet.net" {
		t.Errorf("PTR = %q, want exact PTR preserved", consolidated[0].PTR)
	}
}

func TestConsolidateResultsMixedPatternAndExact(t *testing.T) {
	// Mix of exact-match consolidation and pattern-based consolidation
	results := []LookupResult{
		// These 2 share exact PTR → consolidate normally
		{IP: net.ParseIP("10.0.0.0").To4(), PTR: "host.example.com"},
		{IP: net.ParseIP("10.0.0.1").To4(), PTR: "host.example.com"},
		// These 4 have IP-templated PTRs → pattern consolidation
		{IP: net.ParseIP("10.0.1.0").To4(), PTR: "10-0-1-0.isp.example.com"},
		{IP: net.ParseIP("10.0.1.1").To4(), PTR: "10-0-1-1.isp.example.com"},
		{IP: net.ParseIP("10.0.1.2").To4(), PTR: "10-0-1-2.isp.example.com"},
		{IP: net.ParseIP("10.0.1.3").To4(), PTR: "10-0-1-3.isp.example.com"},
		// NXDOMAIN
		{IP: net.ParseIP("10.0.2.0").To4(), PTR: ""},
	}

	consolidated := ConsolidateResults(results)

	// Expect: 10.0.0.0/31 host.example.com, 10.0.1.0/30 *.isp.example.com, 10.0.2.0 NXDOMAIN
	if len(consolidated) != 3 {
		var lines []string
		for _, c := range consolidated {
			lines = append(lines, networkString(c.Network)+" "+c.PTR)
		}
		t.Fatalf("got %d results %v, want 3", len(consolidated), lines)
	}

	// Results are sorted by IP
	if consolidated[0].Network.String() != "10.0.0.0/31" {
		t.Errorf("[0] network = %s, want 10.0.0.0/31", consolidated[0].Network)
	}
	if consolidated[0].PTR != "host.example.com" {
		t.Errorf("[0] PTR = %q, want host.example.com", consolidated[0].PTR)
	}

	if consolidated[1].Network.String() != "10.0.1.0/30" {
		t.Errorf("[1] network = %s, want 10.0.1.0/30", consolidated[1].Network)
	}
	if consolidated[1].PTR != "*.isp.example.com" {
		t.Errorf("[1] PTR = %q, want *.isp.example.com", consolidated[1].PTR)
	}

	if consolidated[2].PTR != "" {
		t.Errorf("[2] PTR = %q, want empty (NXDOMAIN)", consolidated[2].PTR)
	}
}

func TestExtractIPv6PTRPattern(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		ptr  string
		want string
	}{
		// Full expanded dashes: 2001-0db8-0000-0000-0000-0000-0000-0001
		{
			name: "full expanded dashes",
			ip:   "2001:db8::1",
			ptr:  "2001-0db8-0000-0000-0000-0000-0000-0001.static.isp.net",
			want: "*.static.isp.net",
		},
		// Compressed dashes: 2001-db8--1
		{
			name: "compressed dashes",
			ip:   "2001:db8::1",
			ptr:  "2001-db8--1.static.isp.net",
			want: "*.static.isp.net",
		},
		// Reversed nibble dashes
		{
			name: "reversed nibble dashes",
			ip:   "2001:db8::1",
			ptr:  "1-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-8-b-d-0-1-0-0-2.isp.net",
			want: "*.isp.net",
		},
		// Embedded with prefix
		{
			name: "embedded full expanded with prefix",
			ip:   "2001:db8::1",
			ptr:  "host-2001-0db8-0000-0000-0000-0000-0000-0001.example.com",
			want: "*.example.com",
		},
		{
			name: "embedded compressed with prefix",
			ip:   "2001:db8::1",
			ptr:  "host-2001-db8--1.example.com",
			want: "*.example.com",
		},
		{
			name: "embedded reversed nibble with prefix",
			ip:   "2001:db8::1",
			ptr:  "host-1-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-8-b-d-0-1-0-0-2.isp.net",
			want: "*.isp.net",
		},
		// No match
		{
			name: "no match",
			ip:   "2001:db8::1",
			ptr:  "mail.google.com",
			want: "",
		},
		// IPv4 should be skipped
		{
			name: "ipv4 skipped",
			ip:   "10.0.0.1",
			ptr:  "host.example.com",
			want: "",
		},
		// No dot in PTR (single label)
		{
			name: "no dot in ptr",
			ip:   "2001:db8::1",
			ptr:  "just-a-hostname",
			want: "",
		},
		// Empty PTR
		{
			name: "empty ptr",
			ip:   "2001:db8::1",
			ptr:  "",
			want: "",
		},
		// Suffix too short
		{
			name: "suffix too short",
			ip:   "2001:db8::1",
			ptr:  "2001-0db8-0000-0000-0000-0000-0000-0001.com",
			want: "",
		},
		// Case insensitive matching
		{
			name: "case insensitive",
			ip:   "2001:db8::ab",
			ptr:  "2001-0DB8-0000-0000-0000-0000-0000-00AB.static.isp.net",
			want: "*.static.isp.net",
		},
		// Different IPv6 address with more hex variety
		{
			name: "full address expanded",
			ip:   "2001:db8:85a3::8a2e:370:7334",
			ptr:  "2001-0db8-85a3-0000-0000-8a2e-0370-7334.example.com",
			want: "*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := extractIPv6PTRPattern(ip, tt.ptr)
			if got != tt.want {
				t.Errorf("extractIPv6PTRPattern(%s, %q) = %q, want %q", tt.ip, tt.ptr, got, tt.want)
			}
		})
	}
}

func TestConsolidateResultsIPv6Patterns(t *testing.T) {
	// Simulate ISP-style IPv6 PTR records with embedded addresses
	results := []LookupResult{
		{IP: net.ParseIP("2001:db8::1"), PTR: "2001-0db8-0000-0000-0000-0000-0000-0001.static.isp.net"},
		{IP: net.ParseIP("2001:db8::2"), PTR: "2001-0db8-0000-0000-0000-0000-0000-0002.static.isp.net"},
		{IP: net.ParseIP("2001:db8::3"), PTR: "2001-0db8-0000-0000-0000-0000-0000-0003.static.isp.net"},
	}

	got := ConsolidateResults(results)

	// 3 IPs → 2 CIDRs (2001:db8::1/128 + 2001:db8::2/127), both under the same pattern
	if len(got) != 2 {
		t.Fatalf("expected 2 consolidated results, got %d", len(got))
	}
	for _, r := range got {
		if r.PTR != "*.static.isp.net" {
			t.Errorf("PTR = %q, want %q", r.PTR, "*.static.isp.net")
		}
	}
}

func TestConsolidateResultsMixedIPVersions(t *testing.T) {
	results := []LookupResult{
		// IPv4 pattern group
		{IP: net.ParseIP("192.168.1.1").To4(), PTR: "192-168-1-1.example.com"},
		{IP: net.ParseIP("192.168.1.2").To4(), PTR: "192-168-1-2.example.com"},
		// IPv6 pattern group
		{IP: net.ParseIP("2001:db8::1"), PTR: "2001-0db8-0000-0000-0000-0000-0000-0001.static.isp.net"},
		{IP: net.ParseIP("2001:db8::2"), PTR: "2001-0db8-0000-0000-0000-0000-0000-0002.static.isp.net"},
		// Non-matching entry
		{IP: net.ParseIP("10.0.0.1").To4(), PTR: "mail.google.com"},
	}

	got := ConsolidateResults(results)

	// Verify all expected patterns appear in results
	patterns := make(map[string]bool)
	for _, r := range got {
		patterns[r.PTR] = true
	}

	if !patterns["*.example.com"] {
		t.Error("missing IPv4 pattern *.example.com")
	}
	if !patterns["*.static.isp.net"] {
		t.Error("missing IPv6 pattern *.static.isp.net")
	}
	if !patterns["mail.google.com"] {
		t.Error("missing non-matching entry mail.google.com")
	}
	// 2 IPv4 CIDRs + 2 IPv6 CIDRs + 1 unmatched = 5
	if len(got) != 5 {
		t.Errorf("expected 5 consolidated results, got %d", len(got))
	}
}

// mustParseCIDR parses a CIDR string or panics.
func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}
