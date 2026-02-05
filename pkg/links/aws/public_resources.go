package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/lambda"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AwsPublicResources struct {
	*base.NativeAWSLink
	processedS3   map[string]bool // Track processed S3 buckets to avoid duplicates
	processedS3Mu sync.RWMutex    // Protect concurrent access to processedS3
}

func NewAwsPublicResources(args map[string]any) *AwsPublicResources {
	return &AwsPublicResources{
		NativeAWSLink: base.NewNativeAWSLink("aws-public-resources", args),
		processedS3:   make(map[string]bool),
	}
}

func (a *AwsPublicResources) SupportedResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::S3::Bucket",
		"AWS::RDS::DBInstance",
	}
}

func (a *AwsPublicResources) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	// Deduplication for S3 buckets - only process each bucket once
	if resource.TypeName == "AWS::S3::Bucket" {
		// Create unique key using account_id:bucket_name
		bucketKey := resource.AccountId + ":" + resource.Identifier

		a.processedS3Mu.Lock()
		if a.processedS3[bucketKey] {
			a.processedS3Mu.Unlock()
			slog.Debug("Skipping already processed S3 bucket", "bucket", resource.Identifier, "account", resource.AccountId)
			return nil, nil
		}
		a.processedS3[bucketKey] = true
		a.processedS3Mu.Unlock()

		slog.Debug("Processing S3 bucket for first time", "bucket", resource.Identifier, "account", resource.AccountId)
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Create args map for passing to sub-links
	// Include known parameters that sub-links may need
	args := map[string]any{
		"profile":     a.Profile,
		"profile-dir": a.ProfileDir,
		"regions":     a.Regions,
	}

	// TODO: Re-implement PropertyFilterLink and AwsResourcePolicyChecker without cfg.Config dependency
	// These require new implementations that follow the native link pattern

	// Process based on resource type - inline chain execution
	switch resource.TypeName {
	case "AWS::EC2::Instance":
		// CloudControl Get -> Property Filter (PublicIp)
		outputs, err := cloudcontrol.NewCloudControlGet(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		// TODO: Property filter needs reimplementation
		slog.Warn("PropertyFilterLink not yet migrated", "resource_type", resource.TypeName)
		return outputs, nil

	case "AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::EFS::FileSystem", "AWS::S3::Bucket":
		// CloudControl Get -> Resource Policy Checker
		outputs, err := cloudcontrol.NewCloudControlGet(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		// TODO: Resource policy checker needs reimplementation
		slog.Warn("AwsResourcePolicyChecker not yet migrated", "resource_type", resource.TypeName)
		return outputs, nil

	case "AWS::Lambda::Function":
		// CloudControl Get -> Function URL -> Resource Policy Checker
		outputs, err := cloudcontrol.NewCloudControlGet(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		outputs, err = lambda.NewAWSLambdaFunctionURL(args).Process(ctx, outputs)
		if err != nil {
			return nil, err
		}
		// TODO: Resource policy checker needs reimplementation
		slog.Warn("AwsResourcePolicyChecker not yet migrated", "resource_type", resource.TypeName)
		return outputs, nil

	case "AWS::RDS::DBInstance":
		// CloudControl Get -> Property Filter (PubliclyAccessible)
		outputs, err := cloudcontrol.NewCloudControlGet(args).Process(ctx, resource)
		if err != nil {
			return nil, err
		}
		// TODO: Property filter needs reimplementation
		slog.Warn("PropertyFilterLink not yet migrated", "resource_type", resource.TypeName)
		return outputs, nil

	default:
		slog.Error("Unsupported resource type", "resource", resource)
		return nil, nil
	}
}
