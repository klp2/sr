package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	version = "dev"

	concurrency  int
	outputFormat string
	resolvedOnly bool
	nxdomainOnly bool
	sortOutput   bool
	expandOutput bool
	maxIPs       uint64
	dnsServer    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sr <cidr> [cidr...]",
		Short: "Perform bulk reverse DNS lookups on CIDR ranges",
		Long: `sr (ShowReverse) performs bulk PTR lookups on IP addresses
specified in CIDR notation. It uses concurrent lookups for speed.

By default, IPs with the same PTR record are consolidated into CIDR
networks, making output much more compact. Use --expand to show
individual IPs instead.

Supports both IPv4 and IPv6 addresses. Note that many IPv6 addresses
won't have PTR records - ISPs typically can't maintain individual
records for the vast IPv6 address space.

Large CIDR ranges are automatically truncated to --max-ips addresses,
allowing you to sample huge ranges like IPv6 /64 without errors.

Examples:
  sr 8.8.8.0/30                     # Consolidated output (default)
  sr -e 8.8.8.0/30                  # Per-IP output (expanded)
  sr -c 100 192.168.1.0/24
  sr -o json --resolved-only 10.0.0.0/24
  sr 2001:4860:4860::8888/128       # Google DNS IPv6
  sr 2001:db8::/126                 # Small IPv6 range (4 addresses)
  sr --max-ips 1000000 10.0.0.0/8   # Override default limit
  sr --max-ips 100 2001:db8::/64    # Sample first 100 of huge range
  sr --server 8.8.8.8 10.0.0.0/24  # Use specific DNS server
  sr -S 1.1.1.1 192.168.1.0/24     # Short form`,
		Args: cobra.MinimumNArgs(1),
		RunE: run,
	}

	rootCmd.Version = version

	rootCmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Number of concurrent lookups")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text, json")
	rootCmd.Flags().BoolVarP(&resolvedOnly, "resolved-only", "r", false, "Only show IPs with PTR records")
	rootCmd.Flags().BoolVarP(&nxdomainOnly, "nxdomain-only", "n", false, "Only show IPs without PTR records")
	rootCmd.Flags().BoolVarP(&sortOutput, "sort", "s", false, "Sort output by IP address (only with --expand)")
	rootCmd.Flags().BoolVarP(&expandOutput, "expand", "e", false, "Show per-IP output instead of consolidated CIDRs")
	rootCmd.Flags().Uint64VarP(&maxIPs, "max-ips", "m", 65536, "Maximum IPs to process (large ranges truncated to this)")
	rootCmd.Flags().StringVarP(&dnsServer, "server", "S", "", "DNS server to use (default: system resolver)")

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
	var resolver Resolver
	if dnsServer != "" {
		resolver = CustomResolver(dnsServer)
	} else {
		resolver = DefaultResolver()
	}
	resultChan := LookupWorkers(ctx, ips, concurrency, resolver)

	// Collect results
	total := len(ips)
	results := make([]LookupResult, 0, total)
	showProgress := term.IsTerminal(int(os.Stderr.Fd()))

	if showProgress {
		start := time.Now()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for result := range resultChan {
			results = append(results, result)
			select {
			case <-ticker.C:
				if time.Since(start) >= 2*time.Second {
					fmt.Fprintf(os.Stderr, "\rLooking up IPs... %d/%d (%d%%)", len(results), total, 100*len(results)/total)
				}
			default:
			}
		}
		// Clear the progress line
		fmt.Fprintf(os.Stderr, "\r%-60s\r", "")
	} else {
		for result := range resultChan {
			results = append(results, result)
		}
	}

	// Output results
	opts := OutputOptions{
		Format:       outputFormat,
		ResolvedOnly: resolvedOnly,
		NXDomainOnly: nxdomainOnly,
		Sort:         sortOutput,
		Expand:       expandOutput,
	}

	return WriteOutput(os.Stdout, results, opts)
}
