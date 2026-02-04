# sr - bulk reverse DNS lookups

Fast PTR lookups for IP ranges. Give it CIDR blocks, get hostnames back.

```
$ sr 8.8.8.8/30
8.8.8.8         dns.google
8.8.8.9         NXDOMAIN
8.8.8.10        NXDOMAIN
8.8.8.11        NXDOMAIN
```

## Install

```
go install github.com/klp2/sr@latest
```

Or build from source:
```
go build -o sr .
```

## Usage

```
sr [flags] <cidr> [cidr...]

Flags:
  -c, --concurrency int   Concurrent lookups (default 50)
  -o, --output string     Output format: text, json (default "text")
      --resolved-only     Only show IPs with PTR records
      --nxdomain-only     Only show IPs without PTR records
      --sort              Sort output by IP address
```

### Examples

```bash
# Basic lookup
sr 192.168.1.0/24

# JSON output, only resolved hosts
sr -o json --resolved-only 10.0.0.0/24

# Multiple ranges, sorted
sr --sort 8.8.8.0/24 8.8.4.0/24

# Crank up concurrency for large ranges
sr -c 100 172.16.0.0/16
```

## Performance

On a /24 (256 IPs):

| Concurrency | Time |
|-------------|------|
| 1 (sequential) | ~90s |
| 50 (default) | ~5s |
| 100 | ~3s |

The sweet spot depends on your DNS resolver. Default of 50 is conservative.

## Why not just use dig?

You can! For small ranges, `dig -x` works fine. This tool is useful when you:
- Need to scan larger ranges without fork-bombing your system
- Want JSON output for scripting
- Need filtering (resolved-only, nxdomain-only)
- Don't want to write the same bash loop again

## See also

- [App-showreverse](https://github.com/klp2/App-showreverse) - the Perl original
