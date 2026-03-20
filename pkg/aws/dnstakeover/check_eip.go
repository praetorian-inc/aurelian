package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	mustRegister("A", "eip-dangling", checkEIP)
}

const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

type ipPrefixEntry struct {
	IPPrefix string `json:"ip_prefix"`
	Region   string `json:"region"`
	Service  string `json:"service"`
}

func checkEIP(ctx CheckContext, rec Route53Record, out *pipeline.P[model.AurelianModel]) error {
	if rec.IsAlias {
		return nil // alias A records point to AWS endpoints, not raw IPs
	}

	cache := ctx.EIPCache
	cache.once.Do(func() {
		cache.ranges, cache.allocatedIPs, cache.err = initEIPState(ctx)
	})
	if cache.err != nil {
		return fmt.Errorf("eip state initialization failed: %w", cache.err)
	}

	for _, ip := range rec.Values {
		awsRegion, awsService, inAWS := containsIP(cache.ranges, ip)
		if !inAWS {
			continue
		}
		if cache.allocatedIPs[ip] {
			continue
		}

		out.Send(NewTakeoverRisk(
			"eip-dangling-a-record",
			output.RiskSeverityMedium,
			rec,
			ctx.AccountID,
			map[string]any{
				"dangling_ip": ip,
				"aws_region":  awsRegion,
				"aws_service": awsService,
				"description": fmt.Sprintf(
					"Route53 A record %q points to %s which is in AWS IP space (%s/%s) "+
						"but is not allocated as an EIP in this account.",
					rec.RecordName, ip, awsService, awsRegion,
				),
				"recommendation": "Remove the stale A record or re-allocate the Elastic IP.",
				"references": []string{
					"https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains",
					"https://kmsec.uk/blog/passive-takeover/",
				},
			},
		))
	}

	return nil
}

func initEIPState(ctx CheckContext) ([]parsedPrefix, map[string]bool, error) {
	slog.Info("eip checker: fetching aws ip ranges")
	ranges, err := fetchAWSIPRanges(ctx.Ctx)
	if err != nil {
		return nil, nil, err
	}
	slog.Info("eip checker: loaded aws ip prefixes", "count", len(ranges))

	slog.Info("eip checker: enumerating allocated eips across regions")
	allocated, err := fetchAllocatedEIPs(ctx)
	if err != nil {
		return nil, nil, err
	}
	slog.Info("eip checker: found allocated eips", "count", len(allocated))

	return ranges, allocated, nil
}

func fetchAWSIPRanges(ctx context.Context) ([]parsedPrefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, awsIPRangesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create aws ip ranges request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch aws ip ranges: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch aws ip ranges: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read aws ip ranges: %w", err)
	}

	var raw struct {
		Prefixes []ipPrefixEntry `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse aws ip ranges: %w", err)
	}

	var prefixes []parsedPrefix
	for _, p := range raw.Prefixes {
		if p.IPPrefix == "" {
			continue
		}
		_, network, err := net.ParseCIDR(p.IPPrefix)
		if err != nil {
			continue
		}
		prefixes = append(prefixes, parsedPrefix{
			network: network,
			region:  p.Region,
			service: p.Service,
		})
	}

	return prefixes, nil
}

func containsIP(prefixes []parsedPrefix, ip string) (region, service string, ok bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", false
	}
	for _, p := range prefixes {
		if p.network.Contains(parsed) {
			return p.region, p.service, true
		}
	}
	return "", "", false
}

func fetchAllocatedEIPs(ctx CheckContext) (map[string]bool, error) {
	allocated := make(map[string]bool)
	var mu sync.Mutex

	actor := ratelimit.NewCrossRegionActor(ctx.Opts.Concurrency)
	err := actor.ActInRegions(ctx.Opts.Regions, func(region string) error {
		cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    ctx.Opts.Profile,
			ProfileDir: ctx.Opts.ProfileDir,
		})
		if err != nil {
			return fmt.Errorf("region %s: %w", region, err)
		}

		client := ec2.NewFromConfig(cfg)
		resp, err := client.DescribeAddresses(ctx.Ctx, &ec2.DescribeAddressesInput{})
		if err != nil {
			return fmt.Errorf("region %s describe addresses: %w", region, err)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, addr := range resp.Addresses {
			if addr.PublicIp != nil {
				allocated[aws.ToString(addr.PublicIp)] = true
			}
		}
		return nil
	})

	return allocated, err
}
