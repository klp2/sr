package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestE2E_BasicLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	outStr := string(output)
	if !strings.Contains(outStr, "8.8.8.8") {
		t.Errorf("output missing 8.8.8.8: %s", outStr)
	}
	if !strings.Contains(outStr, "dns.google") {
		t.Errorf("output missing dns.google: %s", outStr)
	}
}

func TestE2E_JSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Expanded JSON uses the per-IP format
	cmd := exec.Command("go", "run", ".", "-e", "-o", "json", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	var results []JSONResult
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, output)
	}

	if len(results) != 1 {
		t.Errorf("got %d results, want 1", len(results))
	}

	if results[0].IP != "8.8.8.8" {
		t.Errorf("IP = %s, want 8.8.8.8", results[0].IP)
	}

	if results[0].PTR == nil || *results[0].PTR != "dns.google" {
		t.Errorf("PTR = %v, want dns.google", results[0].PTR)
	}
}

func TestE2E_MultipleCIDRs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "--expand", "--sort", "8.8.8.8/32", "8.8.4.4/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Errorf("got %d lines, want 2", len(lines))
	}

	// Should be sorted: 8.8.4.4 before 8.8.8.8
	if !strings.HasPrefix(lines[0], "8.8.4.4") {
		t.Errorf("first line = %q, want to start with 8.8.4.4", lines[0])
	}
}

func TestE2E_ResolvedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// 8.8.8.8/30 gives 8.8.8.8-8.8.8.11, only 8.8.8.8 has PTR
	cmd := exec.Command("go", "run", ".", "--resolved-only", "8.8.8.8/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1 (only resolved): %s", len(lines), output)
	}

	if !strings.Contains(lines[0], "8.8.8.8") {
		t.Errorf("line = %q, want 8.8.8.8", lines[0])
	}
}

func TestE2E_InvalidCIDR(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "not-a-cidr")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for invalid CIDR, got success")
	}

	if !strings.Contains(string(output), "invalid CIDR") {
		t.Errorf("output = %s, want to contain 'invalid CIDR'", output)
	}
}

func TestE2E_MutuallyExclusiveFlags(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--resolved-only", "--nxdomain-only", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Error("expected error for mutually exclusive flags")
	}

	if !strings.Contains(string(output), "mutually exclusive") {
		t.Errorf("output = %s, want to contain 'mutually exclusive'", output)
	}
}

func TestE2E_Help(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	outStr := string(output)
	requiredStrings := []string{
		"PTR lookups",
		"--concurrency",
		"--output",
		"--resolved-only",
		"--nxdomain-only",
		"--sort",
		"--max-ips",
		"IPv6",
		"-c,", "-o,", "-r,", "-n,", "-s,", "-m,", "-S,",
		"--server",
	}

	for _, s := range requiredStrings {
		if !strings.Contains(outStr, s) {
			t.Errorf("help output missing %q", s)
		}
	}
}

func TestE2E_ShortFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string // substring expected in output
		fail bool   // expect nonzero exit
	}{
		{
			name: "short mutually exclusive",
			args: []string{"-r", "-n", "8.8.8.8/32"},
			want: "mutually exclusive",
			fail: true,
		},
		{
			name: "short invalid output format",
			args: []string{"-o", "csv", "8.8.8.8/32"},
			want: "invalid output format",
			fail: true,
		},
		{
			name: "short max-ips truncates",
			args: []string{"-m", "10", "192.168.1.0/24"},
			want: "", // just check it succeeds with 10 lines
		},
		{
			name: "combined short flags",
			args: []string{"-rn", "8.8.8.8/32"},
			want: "mutually exclusive",
			fail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"run", "."}, tt.args...)
			cmd := exec.Command("go", args...)
			output, err := cmd.CombinedOutput()

			if tt.fail && err == nil {
				t.Errorf("expected error, got success: %s", output)
			}
			if !tt.fail && err != nil {
				t.Fatalf("command failed: %v\noutput: %s", err, output)
			}
			if tt.want != "" && !strings.Contains(string(output), tt.want) {
				t.Errorf("output missing %q: %s", tt.want, output)
			}
		})
	}
}

func TestE2E_ShortMaxIPs(t *testing.T) {
	// -m should work the same as --max-ips
	cmd := exec.Command("go", "run", ".", "-e", "-m", "10", "192.168.1.0/24")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 10 {
		t.Errorf("got %d lines, want 10 (truncated with -m): %s", len(lines), output)
	}
}

func TestE2E_ShortSort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "-e", "-s", "8.8.8.8/32", "8.8.4.4/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Errorf("got %d lines, want 2", len(lines))
	}

	// Should be sorted: 8.8.4.4 before 8.8.8.8
	if !strings.HasPrefix(lines[0], "8.8.4.4") {
		t.Errorf("first line = %q, want to start with 8.8.4.4", lines[0])
	}
}

func TestE2E_ShortResolvedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "-r", "8.8.8.8/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1 (only resolved): %s", len(lines), output)
	}

	if !strings.Contains(lines[0], "8.8.8.8") {
		t.Errorf("line = %q, want 8.8.8.8", lines[0])
	}
}

func TestE2E_ShortJSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "-e", "-o", "json", "-r", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	var results []JSONResult
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, output)
	}

	if len(results) != 1 {
		t.Errorf("got %d results, want 1", len(results))
	}
}

func TestE2E_IPv6Lookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Google's public DNS IPv6 address
	cmd := exec.Command("go", "run", ".", "2001:4860:4860::8888/128")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	outStr := string(output)
	if !strings.Contains(outStr, "2001:4860:4860::8888") {
		t.Errorf("output missing IPv6 address: %s", outStr)
	}
	// Google's IPv6 DNS usually resolves to dns.google
	if !strings.Contains(outStr, "dns.google") {
		t.Errorf("output missing expected PTR dns.google: %s", outStr)
	}
}

func TestE2E_IPv6Range(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Small range - /126 gives 4 addresses, expanded
	cmd := exec.Command("go", "run", ".", "--expand", "2001:4860:4860::8888/126")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 {
		t.Errorf("got %d lines, want 4 for /126: %s", len(lines), output)
	}
}

func TestE2E_MaxIPsTruncates(t *testing.T) {
	// A /24 (256 addresses) with limit of 10 should truncate
	cmd := exec.Command("go", "run", ".", "--expand", "--max-ips", "10", "192.168.1.0/24")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 10 {
		t.Errorf("got %d lines, want 10 (truncated): %s", len(lines), output)
	}
}

func TestE2E_MaxIPsAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// /30 gives 4 IPs, well under limit of 10
	cmd := exec.Command("go", "run", ".", "--expand", "--max-ips", "10", "8.8.8.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 {
		t.Errorf("got %d lines, want 4: %s", len(lines), output)
	}
}

func TestE2E_HugeIPv6Truncated(t *testing.T) {
	// A /64 has 2^64 addresses - should be truncated to --max-ips
	cmd := exec.Command("go", "run", ".", "--expand", "--max-ips", "10", "2001:db8::/64")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 10 {
		t.Errorf("got %d lines, want 10 (truncated): %s", len(lines), output)
	}

	// Verify first few addresses are sequential
	if !strings.HasPrefix(lines[0], "2001:db8::") {
		t.Errorf("first line = %q, want to start with 2001:db8::", lines[0])
	}
}

func TestE2E_ConsolidatedDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Default (consolidated) output: 8.8.8.0/30 has 4 IPs, most without PTR
	// Consolidated should produce fewer lines than 4
	cmd := exec.Command("go", "run", ".", "8.8.8.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	// Should have fewer lines than 4 (consolidated)
	if len(lines) >= 4 {
		t.Errorf("consolidated output should have fewer than 4 lines, got %d: %s", len(lines), output)
	}
	// Should still contain dns.google
	if !strings.Contains(string(output), "dns.google") {
		t.Errorf("output missing dns.google: %s", output)
	}
}

func TestE2E_ExpandFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// --expand should produce per-IP output (4 lines for /30)
	cmd := exec.Command("go", "run", ".", "--expand", "8.8.8.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 {
		t.Errorf("got %d lines, want 4 (expanded): %s", len(lines), output)
	}
}

func TestE2E_ExpandShortFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// -e should work the same as --expand
	cmd := exec.Command("go", "run", ".", "-e", "8.8.8.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 {
		t.Errorf("got %d lines, want 4 (expanded with -e): %s", len(lines), output)
	}
}

func TestE2E_ConsolidatedResolvedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Consolidated + resolved-only: should only show entries with PTR
	cmd := exec.Command("go", "run", ".", "-r", "8.8.8.0/30")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1 (consolidated resolved only): %s", len(lines), output)
	}
	if !strings.Contains(string(output), "dns.google") {
		t.Errorf("output missing dns.google: %s", output)
	}
}

func TestE2E_ConsolidatedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "-o", "json", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	var results []ConsolidatedJSONResult
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, output)
	}

	if len(results) != 1 {
		t.Errorf("got %d results, want 1", len(results))
	}

	// Single IP should show plain IP, not /32
	if results[0].Network != "8.8.8.8" {
		t.Errorf("network = %s, want 8.8.8.8", results[0].Network)
	}
	if results[0].PTR == nil || *results[0].PTR != "dns.google" {
		t.Errorf("PTR = %v, want dns.google", results[0].PTR)
	}
}

func TestE2E_HelpExpandFlag(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	outStr := string(output)
	for _, s := range []string{"--expand", "-e,"} {
		if !strings.Contains(outStr, s) {
			t.Errorf("help output missing %q", s)
		}
	}
}

func TestE2E_CustomServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	for _, flag := range []string{"--server", "-S"} {
		t.Run(flag, func(t *testing.T) {
			cmd := exec.Command("go", "run", ".", flag, "8.8.8.8", "8.8.8.8/32")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command failed: %v\noutput: %s", err, output)
			}

			if !strings.Contains(string(output), "dns.google") {
				t.Errorf("output missing dns.google: %s", output)
			}
		})
	}
}

func TestE2E_CustomServerWithPort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	cmd := exec.Command("go", "run", ".", "--server", "8.8.8.8:53", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\noutput: %s", err, output)
	}

	if !strings.Contains(string(output), "dns.google") {
		t.Errorf("output missing dns.google: %s", output)
	}
}

func TestE2E_InvalidServer(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--server", "   ", "8.8.8.8/32")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for whitespace-only server")
	}
	if !strings.Contains(string(output), "invalid DNS server address") {
		t.Errorf("expected clear error message, got: %s", output)
	}
}
