package dnstakeover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("NS", "ns-delegation", checkNS)
}

var nsRoute53Pattern = regexp.MustCompile(`(?i)^ns-\d+\.awsdns-\d+\.\w+`)

func checkNS(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	// Skip apex NS records — these are the zone's own nameservers, not delegations.
	if rec.RecordName == rec.ZoneName {
		return nil
	}

	// Collect only Route53-pattern nameservers.
	var route53NSes []string
	for _, ns := range rec.Values {
		ns = strings.TrimSuffix(ns, ".")
		if nsRoute53Pattern.MatchString(ns) {
			route53NSes = append(route53NSes, ns)
		}
	}

	if len(route53NSes) == 0 {
		return nil
	}

	queryErr := validateNSDelegation(ctx.Ctx, rec.RecordName, route53NSes[0])
	if queryErr == "" {
		return nil // zone is alive
	}

	slog.Info("dangling ns delegation detected",
		"record", rec.RecordName,
		"zone", rec.ZoneName,
		"nameserver", route53NSes[0],
		"error_type", queryErr,
	)

	out.Send(NewTakeoverRisk(
		"ns-delegation-takeover",
		output.RiskSeverityHigh,
		rec,
		ctx.AccountID,
		map[string]any{
			"nameservers": route53NSes,
			"query_error": queryErr,
			"description": fmt.Sprintf(
				"Route53 NS delegation %q delegates to Route53 nameservers (%s) "+
					"but the hosted zone no longer exists (DNS: %s). An attacker can "+
					"exploit the Form3 bypass to gain full DNS control.",
				rec.RecordName, strings.Join(route53NSes, ", "), queryErr,
			),
			"recommendation": "Remove the stale NS delegation record from zone " + rec.ZoneName + ".",
			"references": []string{
				"https://www.form3.tech/blog/engineering/dangling-danger",
				"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
				"https://0xpatrik.com/subdomain-takeover-ns/",
			},
		},
	))

	return nil
}

func validateNSDelegation(parentCtx context.Context, recordName, nameserver string) string {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "udp", nameserver+":53")
		},
	}

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	_, err := resolver.LookupNS(ctx, recordName)
	if err == nil {
		return "" // zone exists
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || dnsErr.IsTimeout {
		return "" // transient — don't flag
	}

	return classifyDNSError(dnsErr)
}

func classifyDNSError(dnsErr *net.DNSError) string {
	if dnsErr.IsNotFound {
		return "NXDOMAIN"
	}

	errMsg := strings.ToUpper(dnsErr.Error())
	switch {
	case strings.Contains(errMsg, "SERVFAIL") || strings.Contains(errMsg, "SERVER FAILURE"):
		return "SERVFAIL"
	case strings.Contains(errMsg, "REFUSED"):
		return "REFUSED"
	case strings.Contains(errMsg, "SERVER MISBEHAVING"):
		return "REFUSED" // Go translates REFUSED to "server misbehaving"
	case strings.Contains(errMsg, "NXDOMAIN") || strings.Contains(errMsg, "NO SUCH HOST"):
		return "NXDOMAIN"
	default:
		return "" // unknown — don't flag
	}
}
