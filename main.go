package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	concurrency  int
	outputFormat string
	resolvedOnly bool
	nxdomainOnly bool
	sortOutput   bool
	maxIPs       uint64
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sr <cidr> [cidr...]",
		Short: "Perform bulk reverse DNS lookups on CIDR ranges",
		Long: `sr (ShowReverse) performs bulk PTR lookups on IP addresses
specified in CIDR notation. It uses concurrent lookups for speed.

Supports both IPv4 and IPv6 addresses. Note that many IPv6 addresses
won't have PTR records - ISPs typically can't maintain individual
records for the vast IPv6 address space.

Large CIDR ranges are automatically truncated to --max-ips addresses,
allowing you to sample huge ranges like IPv6 /64 without errors.

Examples:
  sr 8.8.8.0/30
  sr -c 100 192.168.1.0/24
  sr -o json --resolved-only 10.0.0.0/24
  sr 2001:4860:4860::8888/128       # Google DNS IPv6
  sr 2001:db8::/126                 # Small IPv6 range (4 addresses)
  sr --max-ips 1000000 10.0.0.0/8   # Override default limit
  sr --max-ips 100 2001:db8::/64    # Sample first 100 of huge range`,
		Args: cobra.MinimumNArgs(1),
		RunE: run,
	}

	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent lookups")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text, json")
	rootCmd.Flags().BoolVarP(&resolvedOnly, "resolved-only", "r", false, "Only show IPs with PTR records")
	rootCmd.Flags().BoolVarP(&nxdomainOnly, "nxdomain-only", "n", false, "Only show IPs without PTR records")
	rootCmd.Flags().BoolVarP(&sortOutput, "sort", "s", false, "Sort output by IP address")
	rootCmd.Flags().Uint64VarP(&maxIPs, "max-ips", "m", 65536, "Maximum IPs to process (large ranges truncated to this)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Validate flags
	if resolvedOnly && nxdomainOnly {
		return fmt.Errorf("--resolved-only and --nxdomain-only are mutually exclusive")
	}

	if outputFormat != "text" && outputFormat != "json" {
		return fmt.Errorf("invalid output format %q: must be text or json", outputFormat)
	}

	if concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1")
	}

	// Parse CIDR blocks
	ips, err := ParseCIDRs(args, maxIPs)
	if err != nil {
		return err
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses in specified CIDR blocks")
	}

	// Perform lookups
	ctx := context.Background()
	resolver := DefaultResolver()
	resultChan := LookupWorkers(ctx, ips, concurrency, resolver)

	// Collect results
	results := make([]LookupResult, 0, len(ips))
	for result := range resultChan {
		results = append(results, result)
	}

	// Output results
	opts := OutputOptions{
		Format:       outputFormat,
		ResolvedOnly: resolvedOnly,
		NXDomainOnly: nxdomainOnly,
		Sort:         sortOutput,
	}

	return WriteOutput(os.Stdout, results, opts)
}
