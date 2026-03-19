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
	mustRegister("NS", "ns-delegation", checkNSDelegation)
}

// Azure DNS nameservers: ns1-01.azure-dns.com, ns2-01.azure-dns.net, ns3-01.azure-dns.org, ns4-01.azure-dns.info
var azureDNSNSPattern = regexp.MustCompile(`(?i)^ns\d+-\d+\.azure-dns\.(com|net|org|info)$`)

func checkNSDelegation(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	var azureNSes []string
	for _, ns := range rec.Values {
		ns = strings.TrimSuffix(ns, ".")
		if azureDNSNSPattern.MatchString(ns) {
			azureNSes = append(azureNSes, ns)
		}
	}

	if len(azureNSes) == 0 {
		return nil
	}

	delegatedZone := rec.RecordName + "." + rec.ZoneName

	queryErr := validateAzureNSDelegation(ctx.Ctx, delegatedZone, azureNSes[0])
	if queryErr == "" {
		return nil
	}

	slog.Info("dangling azure ns delegation detected",
		"record", rec.RecordName,
		"zone", rec.ZoneName,
		"nameserver", azureNSes[0],
		"error_type", queryErr,
	)

	out.Send(NewTakeoverRisk(
		"ns-delegation-takeover",
		output.RiskSeverityCritical,
		rec,
		map[string]any{
			"service":     "Azure DNS",
			"nameservers": azureNSes,
			"query_error": queryErr,
			"description": fmt.Sprintf(
				"NS delegation %q delegates to Azure DNS nameservers (%s) "+
					"but the hosted zone no longer exists (DNS: %s). An attacker can "+
					"create a new Azure DNS zone with matching nameserver assignment to gain full DNS control.",
				delegatedZone, strings.Join(azureNSes, ", "), queryErr,
			),
			"remediation": "Remove the stale NS delegation record from zone " + rec.ZoneName + ".",
			"references": []string{
				"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				"https://learn.microsoft.com/en-us/azure/dns/dns-delegate-domain-azure-dns",
			},
		},
	))

	return nil
}

func validateAzureNSDelegation(parentCtx context.Context, recordName, nameserver string) string {
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
		return ""
	}

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || dnsErr.IsTimeout {
		return ""
	}

	return classifyAzureDNSError(dnsErr)
}

func classifyAzureDNSError(dnsErr *net.DNSError) string {
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
		return "REFUSED"
	case strings.Contains(errMsg, "NXDOMAIN") || strings.Contains(errMsg, "NO SUCH HOST"):
		return "NXDOMAIN"
	default:
		return ""
	}
}
