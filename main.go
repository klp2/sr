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
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sr <cidr> [cidr...]",
		Short: "Perform bulk reverse DNS lookups on CIDR ranges",
		Long: `sr (ShowReverse) performs bulk PTR lookups on IP addresses
specified in CIDR notation. It uses concurrent lookups for speed.

Examples:
  sr 8.8.8.0/30
  sr -c 100 192.168.1.0/24
  sr -o json --resolved-only 10.0.0.0/24`,
		Args: cobra.MinimumNArgs(1),
		RunE: run,
	}

	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent lookups")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text, json")
	rootCmd.Flags().BoolVar(&resolvedOnly, "resolved-only", false, "Only show IPs with PTR records")
	rootCmd.Flags().BoolVar(&nxdomainOnly, "nxdomain-only", false, "Only show IPs without PTR records")
	rootCmd.Flags().BoolVar(&sortOutput, "sort", false, "Sort output by IP address")

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
	ips, err := ParseCIDRs(args)
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
