package eiptakeover

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// FetchAllocatedEIPs returns a set of all public IP addresses currently
// allocated as Elastic IPs across all specified regions.
func FetchAllocatedEIPs(opts ScanOptions) (map[string]bool, error) {
	allocated := make(map[string]bool)
	var mu sync.Mutex

	actor := ratelimit.NewCrossRegionActor(opts.Concurrency)
	err := actor.ActInRegions(opts.Regions, func(region string) error {
		cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			return fmt.Errorf("region %s: create aws config: %w", region, err)
		}

		ips, err := describeAddresses(cfg, region)
		if err != nil {
			return fmt.Errorf("region %s: describe addresses: %w", region, err)
		}

		mu.Lock()
		defer mu.Unlock()
		for _, ip := range ips {
			allocated[ip] = true
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return allocated, nil
}

// describeAddresses calls ec2:DescribeAddresses for the given region and
// returns the public IP addresses of all allocated EIPs.
func describeAddresses(cfg aws.Config, region string) ([]string, error) {
	client := ec2.NewFromConfig(cfg)

	out, err := client.DescribeAddresses(context.Background(), &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, fmt.Errorf("ec2 describe addresses in %s: %w", region, err)
	}

	var ips []string
	for _, addr := range out.Addresses {
		if addr.PublicIp != nil {
			ips = append(ips, aws.ToString(addr.PublicIp))
		}
	}

	return ips, nil
}
