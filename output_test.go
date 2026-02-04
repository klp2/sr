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
		opts := OutputOptions{Format: "text", Sort: true}
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
		opts := OutputOptions{Format: "text", ResolvedOnly: true}
		if err := WriteOutput(&buf, results, opts); err != nil {
			t.Fatalf("WriteOutput error: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		if len(lines) != 1 {
			t.Errorf("got %d lines, want 1 (resolved only)", len(lines))
		}
	})
}
