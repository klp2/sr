package main

import (
	"net"
	"testing"
)

func TestExpandCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ExpandCIDR(tt.cidr)

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := ParseCIDRs(tt.cidrs)

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

func TestIncIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"simple increment", "192.168.1.1", "192.168.1.2"},
		{"byte overflow", "192.168.1.255", "192.168.2.0"},
		{"multiple overflow", "192.168.255.255", "192.169.0.0"},
		{"max IP", "255.255.255.255", "0.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			incIP(ip)
			if ip.String() != tt.want {
				t.Errorf("incIP(%s) = %s, want %s", tt.ip, ip, tt.want)
			}
		})
	}
}
