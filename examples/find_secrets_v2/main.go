package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func main() {
	// Parse command-line flags
	profile := flag.String("profile", "default", "AWS profile to use")
	regionsStr := flag.String("regions", "us-east-1", "Comma-separated list of AWS regions")
	maxEvents := flag.Int("max-events", 10000, "Maximum log events to fetch per log group")
	maxStreams := flag.Int("max-streams", 10, "Maximum log streams to sample per log group")
	newestFirst := flag.Bool("newest-first", false, "Fetch newest log events first")
	resourceTypesStr := flag.String("resource-types", "", "Comma-separated list of resource types (empty = all)")

	flag.Parse()

	// Parse regions
	regions := strings.Split(*regionsStr, ",")
	for i, region := range regions {
		regions[i] = strings.TrimSpace(region)
	}

	// Create finder
	finder := recon.NewFindAWSSecretsV2(*profile, regions)
	finder.MaxEvents = *maxEvents
	finder.MaxStreams = *maxStreams
	finder.NewestFirst = *newestFirst

	// Parse resource types if provided
	if *resourceTypesStr != "" {
		resourceTypes := strings.Split(*resourceTypesStr, ",")
		for i, rt := range resourceTypes {
			resourceTypes[i] = strings.TrimSpace(rt)
		}
		finder.ResourceTypes = resourceTypes
	}

	// Print configuration
	fmt.Fprintf(os.Stderr, "AWS Find Secrets V2\n")
	fmt.Fprintf(os.Stderr, "===================\n\n")
	fmt.Fprintf(os.Stderr, "Configuration:\n")
	fmt.Fprintf(os.Stderr, "  Profile: %s\n", finder.Profile)
	fmt.Fprintf(os.Stderr, "  Regions: %s\n", strings.Join(finder.Regions, ", "))
	fmt.Fprintf(os.Stderr, "  Resource Types: %d types\n", len(finder.ResourceTypes))
	fmt.Fprintf(os.Stderr, "  Max Events: %d\n", finder.MaxEvents)
	fmt.Fprintf(os.Stderr, "  Max Streams: %d\n", finder.MaxStreams)
	fmt.Fprintf(os.Stderr, "  Newest First: %v\n\n", finder.NewestFirst)

	// Run the scan
	ctx := context.Background()
	fmt.Fprintf(os.Stderr, "Starting scan...\n\n")

	results, err := finder.Run(ctx)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print results
	fmt.Fprintf(os.Stderr, "\nScan Complete!\n")
	fmt.Fprintf(os.Stderr, "==============\n\n")
	fmt.Fprintf(os.Stderr, "Found %d potential secrets\n\n", len(results))

	// Print results summary by resource type
	if len(results) > 0 {
		resourceCounts := make(map[string]int)
		for _, result := range results {
			resourceType := result.Provenance.ResourceType
			resourceCounts[resourceType]++
		}

		fmt.Fprintf(os.Stderr, "Secrets by Resource Type:\n")
		for resourceType, count := range resourceCounts {
			fmt.Fprintf(os.Stderr, "  %s: %d\n", resourceType, count)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	// Output results as JSON to stdout
	// (In a real implementation, you'd format the results properly)
	// For now, just print a summary
	for i, result := range results {
		fmt.Printf("Secret %d:\n", i+1)
		fmt.Printf("  Platform: %s\n", result.Provenance.Platform)
		fmt.Printf("  Resource Type: %s\n", result.Provenance.ResourceType)
		fmt.Printf("  Resource ID: %s\n", result.Provenance.ResourceID)
		fmt.Printf("  Region: %s\n", result.Provenance.Region)
		fmt.Printf("  Account ID: %s\n", result.Provenance.AccountID)
		fmt.Printf("  Content Length: %d bytes\n", len(result.Content))
		fmt.Printf("\n")
	}
}
