package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// OutputOptions controls how results are formatted and filtered.
type OutputOptions struct {
	Format       string // "text" or "json"
	ResolvedOnly bool   // Only show IPs with PTR records
	NXDomainOnly bool   // Only show IPs without PTR records
	Sort         bool   // Sort output by IP address
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

// WriteOutput writes results in the specified format.
func WriteOutput(w io.Writer, results []LookupResult, opts OutputOptions) error {
	// Apply filtering
	results = FilterResults(results, opts)

	// Apply sorting
	if opts.Sort {
		SortResults(results)
	}

	// Format output
	switch opts.Format {
	case "json":
		return FormatJSON(w, results)
	default:
		return FormatText(w, results)
	}
}
