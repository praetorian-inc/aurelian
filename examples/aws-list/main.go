// Package main provides a standalone example for listing AWS resources using Cloud Control API.
//
// This example demonstrates direct use of aws-sdk-go-v2 to list AWS resources by type,
// without depending on the aurelian helpers. It's useful for understanding how the
// AWS List Resources module works internally.
//
// Usage:
//
//	go run main.go -resource-type AWS::S3::Bucket
//	go run main.go -resource-type AWS::EC2::Instance -region us-west-2
//	go run main.go -resource-type AWS::Lambda::Function -profile my-profile
//	go run main.go -t AWS::S3::Bucket -r us-west-2 -p my-profile
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
)

func main() {
	// Parse CLI flags
	resourceType := flag.String("resource-type", "", "AWS resource type (e.g., AWS::S3::Bucket, AWS::EC2::Instance)")
	resourceTypeShort := flag.String("t", "", "Shorthand for -resource-type")
	region := flag.String("region", "us-east-1", "AWS region")
	regionShort := flag.String("r", "us-east-1", "Shorthand for -region")
	profile := flag.String("profile", "", "AWS profile name")
	profileShort := flag.String("p", "", "Shorthand for -profile")
	flag.Parse()

	// Use shorthand if main flag not provided
	if *resourceType == "" && *resourceTypeShort != "" {
		resourceType = resourceTypeShort
	}
	if *region == "us-east-1" && *regionShort != "us-east-1" {
		region = regionShort
	}
	if *profile == "" && *profileShort != "" {
		profile = profileShort
	}

	// Validate required parameters
	if *resourceType == "" {
		fmt.Fprintf(os.Stderr, "Error: -resource-type is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load AWS config
	ctx := context.Background()
	var opts []func(*config.LoadOptions) error

	// Set region
	opts = append(opts, config.WithRegion(*region))

	// Set profile if provided
	if *profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(*profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// List resources
	resources, err := listResources(ctx, cfg, *resourceType)
	if err != nil {
		log.Fatalf("Failed to list resources: %v", err)
	}

	// Output results as JSON
	output := map[string]interface{}{
		"resource_type":  *resourceType,
		"region":         *region,
		"resource_count": len(resources),
		"resources":      resources,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		log.Fatalf("Failed to encode JSON: %v", err)
	}
}

// Resource represents a parsed AWS resource with structured data
type Resource struct {
	Identifier string                 `json:"identifier"`
	Properties map[string]interface{} `json:"properties"`
}

// listResources lists AWS resources of the specified type using Cloud Control API
func listResources(ctx context.Context, cfg aws.Config, resourceType string) ([]Resource, error) {
	client := cloudcontrol.NewFromConfig(cfg)

	var resources []Resource
	var nextToken *string

	for {
		input := &cloudcontrol.ListResourcesInput{
			TypeName: &resourceType,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		output, err := client.ListResources(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources of type %s: %w", resourceType, err)
		}

		// Process resource descriptions
		for _, desc := range output.ResourceDescriptions {
			resource := Resource{}

			if desc.Identifier != nil {
				resource.Identifier = *desc.Identifier
			}

			// Parse Properties JSON string into structured map
			if desc.Properties != nil {
				var props map[string]interface{}
				if err := json.Unmarshal([]byte(*desc.Properties), &props); err != nil {
					// If parsing fails, store as raw string
					resource.Properties = map[string]interface{}{
						"_raw": *desc.Properties,
					}
				} else {
					resource.Properties = props
				}
			}

			resources = append(resources, resource)
		}

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return resources, nil
}
