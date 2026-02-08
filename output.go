package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

// OutputOptions controls how results are formatted and filtered.
type OutputOptions struct {
	Format       string // "text" or "json"
	ResolvedOnly bool   // Only show IPs with PTR records
	NXDomainOnly bool   // Only show IPs without PTR records
	Sort         bool   // Sort output by IP address
	Expand       bool   // Show per-IP output instead of consolidated CIDRs
}

// ConsolidatedResult groups IPs with the same PTR into CIDR networks.
type ConsolidatedResult struct {
	Network *net.IPNet // Always set (single IPs get /32 or /128 mask)
	PTR     string     // Empty for NXDOMAIN
	Error   error      // Non-nil only for error entries
}

// FilterResults applies filtering options to results.
func FilterResults(results []LookupResult, opts OutputOptions) []LookupResult {
	if !opts.ResolvedOnly && !opts.NXDomainOnly {
		return results
	}

	filtered := make([]LookupResult, 0, len(results))
	for _, r := range results {
		if opts.ResolvedOnly && r.PTR != "" {
			filtered = append(filtered, r)
		} else if opts.NXDomainOnly && r.PTR == "" && r.Error == nil {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// SortResults sorts results by IP address.
func SortResults(results []LookupResult) {
	sort.Slice(results, func(i, j int) bool {
		return bytes.Compare(results[i].IP, results[j].IP) < 0
	})
}

// FormatText writes results in plain text format.
func FormatText(w io.Writer, results []LookupResult) error {
	// Calculate the maximum IP width for alignment
	// IPv4 max is 15 chars, IPv6 max is 39 chars
	width := 15
	for _, r := range results {
		if len(r.IP.String()) > width {
			width = len(r.IP.String())
		}
	}

	format := fmt.Sprintf("%%-%ds %%s\n", width)
	for _, r := range results {
		var err error
		if r.Error != nil {
			_, err = fmt.Fprintf(w, format, r.IP, "ERROR: "+r.Error.Error())
		} else if r.PTR != "" {
			_, err = fmt.Fprintf(w, format, r.IP, r.PTR)
		} else {
			_, err = fmt.Fprintf(w, format, r.IP, "NXDOMAIN")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// JSONResult is the JSON representation of a lookup result.
type JSONResult struct {
	IP    string  `json:"ip"`
	PTR   *string `json:"ptr"`
	Error *string `json:"error,omitempty"`
}

// FormatJSON writes results in JSON format.
func FormatJSON(w io.Writer, results []LookupResult) error {
	jsonResults := make([]JSONResult, len(results))

	for i, r := range results {
		jr := JSONResult{IP: r.IP.String()}

		if r.Error != nil {
			errStr := r.Error.Error()
			jr.Error = &errStr
		} else if r.PTR != "" {
			jr.PTR = &r.PTR
		}
		// If no PTR and no error, PTR stays nil (NXDOMAIN)

		jsonResults[i] = jr
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonResults)
}

// extractPTRPattern checks if a PTR record contains an IP-derived hostname
// (e.g., ISP-style records like "1.100.147.64.static.nyinternet.net") and
// returns a pattern like "*.static.nyinternet.net". Returns "" if no pattern found.
// Only works for IPv4; IPv6 addresses are skipped.
func extractPTRPattern(ip net.IP, ptr string) string {
	ip4 := ip.To4()
	if ip4 == nil || ptr == "" {
		return ""
	}

	a := fmt.Sprintf("%d", ip4[0])
	b := fmt.Sprintf("%d", ip4[1])
	c := fmt.Sprintf("%d", ip4[2])
	d := fmt.Sprintf("%d", ip4[3])

	// Forward octets joined by dots: a.b.c.d.suffix
	fwdDots := a + "." + b + "." + c + "." + d + "."
	if strings.HasPrefix(ptr, fwdDots) {
		suffix := ptr[len(fwdDots):]
		if strings.Contains(suffix, ".") {
			return "*." + suffix
		}
		return ""
	}

	// Reversed octets joined by dots: d.c.b.a.suffix
	revDots := d + "." + c + "." + b + "." + a + "."
	if strings.HasPrefix(ptr, revDots) {
		suffix := ptr[len(revDots):]
		if strings.Contains(suffix, ".") {
			return "*." + suffix
		}
		return ""
	}

	// Dash-based patterns are in the first label
	dot := strings.IndexByte(ptr, '.')
	if dot == -1 {
		return ""
	}
	firstLabel := ptr[:dot]
	suffix := ptr[dot+1:] // everything after the first dot

	// Suffix must have at least 2 labels (e.g., "example.com" not just "com")
	if !strings.Contains(suffix, ".") {
		return ""
	}

	fwdDashes := a + "-" + b + "-" + c + "-" + d
	revDashes := d + "-" + c + "-" + b + "-" + a

	// Forward dashes as full first label: a-b-c-d.suffix
	if firstLabel == fwdDashes {
		return "*." + suffix
	}

	// Reversed dashes as full first label: d-c-b-a.suffix
	if firstLabel == revDashes {
		return "*." + suffix
	}

	// Embedded with prefix: host-a-b-c-d.suffix or prefix-d-c-b-a.suffix
	if strings.HasSuffix(firstLabel, "-"+fwdDashes) {
		return "*." + suffix
	}
	if strings.HasSuffix(firstLabel, "-"+revDashes) {
		return "*." + suffix
	}

	return ""
}

// ConsolidateResults groups IPs with the same PTR record into CIDR networks.
// It performs two consolidation passes:
//  1. Exact PTR match: IPs with identical PTR records are grouped together.
//  2. Pattern match: Single-IP groups with IP-templated PTR records (e.g.,
//     "1.100.147.64.static.nyinternet.net") are re-grouped by their common
//     suffix pattern (e.g., "*.static.nyinternet.net").
func ConsolidateResults(results []LookupResult) []ConsolidatedResult {
	// Separate errors from non-errors
	var errors []LookupResult
	groups := make(map[string][]net.IP) // PTR (or "") -> IPs

	for _, r := range results {
		if r.Error != nil {
			errors = append(errors, r)
			continue
		}
		groups[r.PTR] = append(groups[r.PTR], r.IP)
	}

	var consolidated []ConsolidatedResult

	// Track single-IP groups with PTR records for pattern consolidation
	type singleEntry struct {
		ip  net.IP
		ptr string
	}
	var singles []singleEntry

	// Pass 1: Process each exact-PTR group
	for ptr, ips := range groups {
		// Sort IPs within the group
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) < 0
		})

		// Deduplicate consecutive duplicates
		deduped := []net.IP{ips[0]}
		for i := 1; i < len(ips); i++ {
			if !ips[i].Equal(ips[i-1]) {
				deduped = append(deduped, ips[i])
			}
		}

		// Single-IP groups with a PTR are candidates for pattern consolidation
		if len(deduped) == 1 && ptr != "" {
			singles = append(singles, singleEntry{ip: deduped[0], ptr: ptr})
			continue
		}

		networks := IPsToNetworks(deduped)
		for _, n := range networks {
			consolidated = append(consolidated, ConsolidatedResult{
				Network: n,
				PTR:     ptr,
			})
		}
	}

	// Pass 2: Pattern-based consolidation of single-IP entries
	patternGroups := make(map[string][]net.IP) // pattern -> IPs
	var unmatched []singleEntry

	for _, s := range singles {
		pattern := extractPTRPattern(s.ip, s.ptr)
		if pattern != "" {
			patternGroups[pattern] = append(patternGroups[pattern], s.ip)
		} else {
			unmatched = append(unmatched, s)
		}
	}

	for pattern, ips := range patternGroups {
		if len(ips) < 2 {
			// Single-IP pattern group: find the original PTR and keep it
			for _, s := range singles {
				if s.ip.Equal(ips[0]) {
					consolidated = append(consolidated, ConsolidatedResult{
						Network: singleIPNet(s.ip),
						PTR:     s.ptr,
					})
					break
				}
			}
			continue
		}

		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i], ips[j]) < 0
		})

		networks := IPsToNetworks(ips)
		for _, n := range networks {
			consolidated = append(consolidated, ConsolidatedResult{
				Network: n,
				PTR:     pattern,
			})
		}
	}

	// Add unmatched singles with their exact PTR
	for _, s := range unmatched {
		consolidated = append(consolidated, ConsolidatedResult{
			Network: singleIPNet(s.ip),
			PTR:     s.ptr,
		})
	}

	// Add errors as individual /32 or /128 entries
	for _, r := range errors {
		consolidated = append(consolidated, ConsolidatedResult{
			Network: singleIPNet(r.IP),
			Error:   r.Error,
		})
	}

	// Sort all results by network IP
	sort.Slice(consolidated, func(i, j int) bool {
		return bytes.Compare(consolidated[i].Network.IP, consolidated[j].Network.IP) < 0
	})

	return consolidated
}

// singleIPNet returns a /32 (IPv4) or /128 (IPv6) network for a single IP.
func singleIPNet(ip net.IP) *net.IPNet {
	bits := 32
	normalized := ip.To4()
	if normalized == nil {
		bits = 128
		normalized = ip
	}
	return &net.IPNet{
		IP:   normalized,
		Mask: net.CIDRMask(bits, bits),
	}
}

// isSingleHost returns true if the network represents a single IP (/32 or /128).
func isSingleHost(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	return ones == bits
}

// networkString returns a CIDR string, or a plain IP for single hosts.
func networkString(n *net.IPNet) string {
	if isSingleHost(n) {
		return n.IP.String()
	}
	return n.String()
}

// FormatTextConsolidated writes consolidated results in plain text format.
func FormatTextConsolidated(w io.Writer, results []ConsolidatedResult) error {
	// Calculate the maximum network string width for alignment
	width := 15
	for _, r := range results {
		s := networkString(r.Network)
		if len(s) > width {
			width = len(s)
		}
	}

	format := fmt.Sprintf("%%-%ds %%s\n", width)
	for _, r := range results {
		var err error
		s := networkString(r.Network)
		if r.Error != nil {
			_, err = fmt.Fprintf(w, format, s, "ERROR: "+r.Error.Error())
		} else if r.PTR != "" {
			_, err = fmt.Fprintf(w, format, s, r.PTR)
		} else {
			_, err = fmt.Fprintf(w, format, s, "NXDOMAIN")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ConsolidatedJSONResult is the JSON representation of a consolidated result.
type ConsolidatedJSONResult struct {
	Network string  `json:"network"`
	PTR     *string `json:"ptr"`
	Error   *string `json:"error,omitempty"`
}

// FormatJSONConsolidated writes consolidated results in JSON format.
func FormatJSONConsolidated(w io.Writer, results []ConsolidatedResult) error {
	jsonResults := make([]ConsolidatedJSONResult, len(results))

	for i, r := range results {
		jr := ConsolidatedJSONResult{Network: networkString(r.Network)}

		if r.Error != nil {
			errStr := r.Error.Error()
			jr.Error = &errStr
		} else if r.PTR != "" {
			jr.PTR = &r.PTR
		}

		jsonResults[i] = jr
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonResults)
}

// WriteOutput writes results in the specified format.
func WriteOutput(w io.Writer, results []LookupResult, opts OutputOptions) error {
	// Apply filtering
	results = FilterResults(results, opts)

	if opts.Expand {
		// Per-IP output (original behavior)
		if opts.Sort {
			SortResults(results)
		}
		switch opts.Format {
		case "json":
			return FormatJSON(w, results)
		default:
			return FormatText(w, results)
		}
	}

	// Consolidated output (default)
	consolidated := ConsolidateResults(results)
	switch opts.Format {
	case "json":
		return FormatJSONConsolidated(w, consolidated)
	default:
		return FormatTextConsolidated(w, consolidated)
	}
}
