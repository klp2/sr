# sr - Project Notes

## Structure

Single-package Go app. All code in main package:
- `main.go` - CLI (cobra), orchestration
- `cidr.go` - CIDR parsing, IP expansion
- `lookup.go` - DNS lookups, worker pool
- `output.go` - Formatting, filtering, sorting

## Testing

```bash
go test ./...           # unit tests
go test -v              # verbose
go test -race           # race detection
go test -bench=.        # benchmarks
```

E2E tests make real DNS queries to 8.8.8.8 etc. Skip with `-short`.

## Key patterns

- `Resolver` interface in lookup.go enables mock DNS for tests
- Worker pool: jobs channel → workers → results channel
- Results collected before output (needed for sorting/filtering)

## Linting

```bash
golangci-lint run
```

## Adding features

Phase 2 stuff that's not done yet:
- Custom DNS server (`--server`)
- CSV output
- IPv6 support
- Stdin input
- TTL-based caching
