package nstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// ValidateDelegations checks each NSDelegation to see if the delegated hosted
// zone still exists by querying the delegated nameserver directly. Returns
// dangling delegations where the nameserver cannot serve the zone.
func ValidateDelegations(delegations []NSDelegation, concurrency int) ([]DanglingNSDelegation, error) {
	if concurrency <= 0 {
		concurrency = 5
	}

	sem := semaphore.NewWeighted(int64(concurrency))
	ctx := context.Background()

	type result struct {
		dangling *DanglingNSDelegation
	}

	results := make(chan result, len(delegations))
	var wg sync.WaitGroup

	for _, d := range delegations {
		d := d // capture loop var
		if err := sem.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("acquire semaphore: %w", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer sem.Release(1)

			dangling, err := checkDelegation(d)
			if err != nil {
				slog.Warn("dns validation error",
					"record", d.RecordName,
					"error", err,
				)
				results <- result{}
				return
			}
			results <- result{dangling: dangling}
		}()
	}

	// Wait for all goroutines to complete then close the channel.
	go func() {
		wg.Wait()
		close(results)
	}()

	var dangling []DanglingNSDelegation
	for r := range results {
		if r.dangling != nil {
			dangling = append(dangling, *r.dangling)
		}
	}

	return dangling, nil
}

// checkDelegation queries the first nameserver in the delegation directly
// to determine whether the hosted zone still exists. Returns a
// DanglingNSDelegation if the zone is gone, or nil if the zone is alive.
func checkDelegation(d NSDelegation) (*DanglingNSDelegation, error) {
	if len(d.Nameservers) == 0 {
		return nil, fmt.Errorf("delegation %s has no nameservers", d.RecordName)
	}

	nameserver := d.Nameservers[0]

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "udp", nameserver+":53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query the delegated subdomain's NS records directly against the delegated
	// nameserver. NS records always exist at a zone apex, so this correctly
	// distinguishes "zone exists" from "zone deleted". Using LookupHost (A/AAAA)
	// would false-positive on zones that have no A records at the apex.
	_, err := resolver.LookupNS(ctx, d.RecordName)
	if err == nil {
		// The nameserver responded with a result — zone exists, not dangling.
		return nil, nil
	}

	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		// Non-DNS error (e.g., network unreachable) — treat as transient.
		slog.Warn("transient dns error validating delegation",
			"record", d.RecordName,
			"nameserver", nameserver,
			"error", err,
		)
		return nil, nil
	}

	// IsTimeout indicates a transient network condition — not dangling.
	if dnsErr.IsTimeout {
		slog.Warn("dns timeout validating delegation",
			"record", d.RecordName,
			"nameserver", nameserver,
		)
		return nil, nil
	}

	// Classify the DNS error to determine if the zone is gone.
	errMsg := strings.ToUpper(err.Error())
	queryErrorType := classifyDNSError(dnsErr, errMsg)

	if queryErrorType == "" {
		// Unknown DNS error — log as warning but don't flag as dangling.
		slog.Warn("unknown dns error validating delegation",
			"record", d.RecordName,
			"nameserver", nameserver,
			"error", err,
		)
		return nil, nil
	}

	slog.Info("dangling ns delegation detected",
		"record", d.RecordName,
		"zone", d.ZoneName,
		"nameserver", nameserver,
		"error_type", queryErrorType,
	)

	return &DanglingNSDelegation{
		ZoneID:      d.ZoneID,
		ZoneName:    d.ZoneName,
		RecordName:  d.RecordName,
		Nameservers: d.Nameservers,
		QueryError:  queryErrorType,
	}, nil
}

// classifyDNSError returns the DNS error category (SERVFAIL, REFUSED, NXDOMAIN)
// or an empty string if the error does not indicate the zone is gone.
func classifyDNSError(dnsErr *net.DNSError, errMsg string) string {
	// IsNotFound maps to NXDOMAIN
	if dnsErr.IsNotFound {
		return "NXDOMAIN"
	}

	// Check error message for SERVFAIL or REFUSED indicators
	if strings.Contains(errMsg, "SERVFAIL") || strings.Contains(errMsg, "SERVER FAILURE") {
		return "SERVFAIL"
	}
	if strings.Contains(errMsg, "REFUSED") {
		return "REFUSED"
	}
	// Go's pure resolver translates REFUSED (and other non-standard rcodes) to "server misbehaving"
	if strings.Contains(errMsg, "SERVER MISBEHAVING") {
		return "REFUSED"
	}
	if strings.Contains(errMsg, "NXDOMAIN") || strings.Contains(errMsg, "NO SUCH HOST") {
		return "NXDOMAIN"
	}

	return ""
}
