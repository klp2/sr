package main

import (
	"fmt"
	"math"
	"net"
	"testing"
)

func TestCIDRSize(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		wantSize uint64
		wantErr  bool
	}{
		{"IPv4 /32", "192.168.1.1/32", 1, false},
		{"IPv4 /30", "192.168.1.0/30", 4, false},
		{"IPv4 /24", "10.0.0.0/24", 256, false},
		{"IPv4 /16", "172.16.0.0/16", 65536, false},
		{"IPv6 /128", "2001:db8::1/128", 1, false},
		{"IPv6 /126", "2001:db8::/126", 4, false},
		{"IPv6 /120", "2001:db8::/120", 256, false},
		{"IPv6 /64 returns sentinel", "2001:db8::/64", math.MaxUint64, false},
		{"IPv6 /0 returns sentinel", "::/0", math.MaxUint64, false},
		{"invalid CIDR", "not-a-cidr", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := CIDRSize(tt.cidr)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CIDRSize(%q) expected error, got nil", tt.cidr)
				}
				return
			}

			if err != nil {
				t.Errorf("CIDRSize(%q) unexpected error: %v", tt.cidr, err)
				return
			}

			if size != tt.wantSize {
				t.Errorf("CIDRSize(%q) = %d, want %d", tt.cidr, size, tt.wantSize)
			}
		})
	}
}

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		maxIPs  uint64
		wantLen int
		wantErr bool
		wantIPs []string // optional: specific IPs to check
	}{
		{
			name:    "single IP /32",
			cidr:    "192.168.1.1/32",
			wantLen: 1,
			wantIPs: []string{"192.168.1.1"},
		},
		{
			name:    "/30 gives 4 IPs",
			cidr:    "192.168.1.0/30",
			wantLen: 4,
			wantIPs: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"},
		},
		{
			name:    "/24 gives 256 IPs",
			cidr:    "10.0.0.0/24",
			wantLen: 256,
		},
		{
			name:    "/16 gives 65536 IPs",
			cidr:    "172.16.0.0/16",
			wantLen: 65536,
		},
		{
			name:    "invalid CIDR",
			cidr:    "not-a-cidr",
			wantErr: true,
		},
		{
			name:    "invalid IP in CIDR",
			cidr:    "999.999.999.999/24",
			wantErr: true,
		},
		// IPv6 tests
		{
			name:    "IPv6 single /128",
			cidr:    "2001:db8::1/128",
			wantLen: 1,
			wantIPs: []string{"2001:db8::1"},
		},
		{
			name:    "IPv6 /126 gives 4 IPs",
			cidr:    "2001:db8::/126",
			wantLen: 4,
			wantIPs: []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"},
		},
		{
			name:    "IPv6 /120 gives 256 IPs",
			cidr:    "2001:db8::/120",
			wantLen: 256,
		},
		// maxIPs limit tests
		{
			name:    "truncates to maxIPs limit",
			cidr:    "10.0.0.0/24",
			maxIPs:  100,
			wantLen: 100,
			wantIPs: []string{"10.0.0.0", "10.0.0.1"}, // verify first IPs
		},
		{
			name:    "within maxIPs limit",
			cidr:    "10.0.0.0/30",
			maxIPs:  100,
			wantLen: 4,
		},
		{
			name:    "maxIPs zero means no limit",
			cidr:    "10.0.0.0/24",
			maxIPs:  0,
			wantLen: 256,
		},
		// Huge range truncation tests
		{
			name:    "huge IPv6 range truncated",
			cidr:    "2001:db8::/64",
			maxIPs:  10,
			wantLen: 10,
			wantIPs: []string{"2001:db8::", "2001:db8::1", "2001:db8::2"},
		},
		{
			name:    "huge IPv6 range with larger limit",
			cidr:    "2001:db8::/64",
			maxIPs:  1000,
			wantLen: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ExpandCIDR(tt.cidr, tt.maxIPs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExpandCIDR(%q) expected error, got nil", tt.cidr)
				}
				return
			}

			if err != nil {
				t.Errorf("ExpandCIDR(%q) unexpected error: %v", tt.cidr, err)
				return
			}

			if len(ips) != tt.wantLen {
				t.Errorf("ExpandCIDR(%q) got %d IPs, want %d", tt.cidr, len(ips), tt.wantLen)
			}

			if len(tt.wantIPs) > 0 {
				for i, wantIP := range tt.wantIPs {
					if i >= len(ips) {
						t.Errorf("ExpandCIDR(%q) missing IP at index %d", tt.cidr, i)
						continue
					}
					if ips[i].String() != wantIP {
						t.Errorf("ExpandCIDR(%q) IP[%d] = %s, want %s", tt.cidr, i, ips[i], wantIP)
					}
				}
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		maxIPs  uint64
		wantLen int
		wantErr bool
	}{
		{
			name:    "single CIDR",
			cidrs:   []string{"192.168.1.0/30"},
			wantLen: 4,
		},
		{
			name:    "multiple CIDRs",
			cidrs:   []string{"192.168.1.0/30", "10.0.0.0/30"},
			wantLen: 8,
		},
		{
			name:    "empty list",
			cidrs:   []string{},
			wantLen: 0,
		},
		{
			name:    "one invalid CIDR",
			cidrs:   []string{"192.168.1.0/30", "invalid"},
			wantErr: true,
		},
		// IPv6 tests
		{
			name:    "IPv6 single CIDR",
			cidrs:   []string{"2001:db8::/126"},
			wantLen: 4,
		},
		{
			name:    "mixed IPv4 and IPv6",
			cidrs:   []string{"192.168.1.0/30", "2001:db8::/126"},
			wantLen: 8,
		},
		// maxIPs limit tests
		{
			name:    "total truncated to maxIPs",
			cidrs:   []string{"192.168.1.0/30", "10.0.0.0/30"}, // 8 total
			maxIPs:  5,
			wantLen: 5, // truncated: 4 from first, 1 from second
		},
		{
			name:    "total within maxIPs",
			cidrs:   []string{"192.168.1.0/30", "10.0.0.0/30"}, // 8 total
			maxIPs:  10,
			wantLen: 8,
		},
		// Huge range tests
		{
			name:    "huge range truncated",
			cidrs:   []string{"2001:db8::/64"},
			maxIPs:  50,
			wantLen: 50,
		},
		{
			name:    "mixed normal and huge range",
			cidrs:   []string{"192.168.1.0/30", "2001:db8::/64"},
			maxIPs:  10,
			wantLen: 10, // 4 from first, 6 from second
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ParseCIDRs(tt.cidrs, tt.maxIPs)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseCIDRs expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCIDRs unexpected error: %v", err)
				return
			}

			if len(ips) != tt.wantLen {
				t.Errorf("ParseCIDRs got %d IPs, want %d", len(ips), tt.wantLen)
			}
		})
	}
}

func TestTrailingZeroBits(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		isV6 bool
		want int
	}{
		{"x.x.x.0", "192.168.1.0", false, 8},
		{"x.x.x.1", "192.168.1.1", false, 0},
		{"x.x.x.4", "10.0.0.4", false, 2},
		{"x.x.x.128", "10.0.0.128", false, 7},
		{"all zeros IPv4", "0.0.0.0", false, 32},
		{"x.x.x.2", "10.0.0.2", false, 1},
		{"x.x.x.16", "10.0.0.16", false, 4},
		{"IPv6 ::1", "::1", true, 0},
		{"IPv6 ::0", "::", true, 128},
		{"IPv6 ::100", "::100", true, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.isV6 {
				ip = net.ParseIP(tt.ip)
			} else {
				ip = net.ParseIP(tt.ip).To4()
			}
			got := trailingZeroBits(ip)
			if got != tt.want {
				t.Errorf("trailingZeroBits(%s) = %d, want %d", tt.ip, got, tt.want)
			}
		})
	}
}

func TestFindContiguousRuns(t *testing.T) {
	parseIPs := func(strs []string) []net.IP {
		ips := make([]net.IP, len(strs))
		for i, s := range strs {
			ips[i] = net.ParseIP(s).To4()
		}
		return ips
	}

	tests := []struct {
		name     string
		ips      []string
		wantRuns int
		wantLens []int
	}{
		{
			name:     "contiguous",
			ips:      []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			wantRuns: 1,
			wantLens: []int{3},
		},
		{
			name:     "gap",
			ips:      []string{"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6"},
			wantRuns: 2,
			wantLens: []int{2, 2},
		},
		{
			name:     "single IP",
			ips:      []string{"10.0.0.1"},
			wantRuns: 1,
			wantLens: []int{1},
		},
		{
			name:     "empty",
			ips:      []string{},
			wantRuns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := parseIPs(tt.ips)
			runs := findContiguousRuns(ips)
			if len(runs) != tt.wantRuns {
				t.Errorf("got %d runs, want %d", len(runs), tt.wantRuns)
				return
			}
			for i, wantLen := range tt.wantLens {
				if len(runs[i]) != wantLen {
					t.Errorf("run[%d] len = %d, want %d", i, len(runs[i]), wantLen)
				}
			}
		})
	}
}

func TestContiguousIPsToNetworks(t *testing.T) {
	parseIPs := func(strs []string) []net.IP {
		ips := make([]net.IP, len(strs))
		for i, s := range strs {
			ips[i] = net.ParseIP(s).To4()
		}
		return ips
	}

	tests := []struct {
		name         string
		ips          []string
		wantNetworks []string
	}{
		{
			name:         "aligned /30",
			ips:          []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
			wantNetworks: []string{"10.0.0.0/30"},
		},
		{
			name:         "unaligned 3 IPs",
			ips:          []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			wantNetworks: []string{"10.0.0.1/32", "10.0.0.2/31"},
		},
		{
			name: "full /24",
			ips: func() []string {
				var s []string
				for i := 0; i < 256; i++ {
					s = append(s, fmt.Sprintf("10.0.0.%d", i))
				}
				return s
			}(),
			wantNetworks: []string{"10.0.0.0/24"},
		},
		{
			name:         "single IP",
			ips:          []string{"10.0.0.5"},
			wantNetworks: []string{"10.0.0.5/32"},
		},
		{
			name:         "empty",
			ips:          []string{},
			wantNetworks: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := parseIPs(tt.ips)
			networks := ContiguousIPsToNetworks(ips)
			if tt.wantNetworks == nil {
				if networks != nil {
					t.Errorf("got %v, want nil", networks)
				}
				return
			}
			if len(networks) != len(tt.wantNetworks) {
				var got []string
				for _, n := range networks {
					got = append(got, n.String())
				}
				t.Errorf("got %v, want %v", got, tt.wantNetworks)
				return
			}
			for i, want := range tt.wantNetworks {
				if networks[i].String() != want {
					t.Errorf("networks[%d] = %s, want %s", i, networks[i], want)
				}
			}
		})
	}
}

func TestContiguousIPsToNetworksIPv6(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2001:db8::"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
		net.ParseIP("2001:db8::3"),
	}
	networks := ContiguousIPsToNetworks(ips)
	if len(networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(networks))
	}
	want := "2001:db8::/126"
	if networks[0].String() != want {
		t.Errorf("got %s, want %s", networks[0], want)
	}
}

func TestIPsToNetworks(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("10.0.0.0").To4(),
		net.ParseIP("10.0.0.1").To4(),
		net.ParseIP("10.0.0.2").To4(),
		net.ParseIP("10.0.0.3").To4(),
		// gap
		net.ParseIP("10.0.0.8").To4(),
		net.ParseIP("10.0.0.9").To4(),
	}
	networks := IPsToNetworks(ips)
	want := []string{"10.0.0.0/30", "10.0.0.8/31"}
	if len(networks) != len(want) {
		var got []string
		for _, n := range networks {
			got = append(got, n.String())
		}
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, w := range want {
		if networks[i].String() != w {
			t.Errorf("networks[%d] = %s, want %s", i, networks[i], w)
		}
	}
}

func TestIncIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
		isV6 bool
	}{
		{"simple increment", "192.168.1.1", "192.168.1.2", false},
		{"byte overflow", "192.168.1.255", "192.168.2.0", false},
		{"multiple overflow", "192.168.255.255", "192.169.0.0", false},
		{"max IP", "255.255.255.255", "0.0.0.0", false},
		// IPv6 tests
		{"IPv6 simple increment", "2001:db8::1", "2001:db8::2", true},
		{"IPv6 byte overflow", "2001:db8::ff", "2001:db8::100", true},
		{"IPv6 segment overflow", "2001:db8::ffff", "2001:db8::1:0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.isV6 {
				ip = net.ParseIP(tt.ip)
			} else {
				ip = net.ParseIP(tt.ip).To4()
			}
			incIP(ip)
			if ip.String() != tt.want {
				t.Errorf("incIP(%s) = %s, want %s", tt.ip, ip, tt.want)
			}
		})
	}
}
