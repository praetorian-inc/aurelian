package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsS3FixResourceRegion fixes the region of an S3 bucket
func AwsS3FixResourceRegion(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "S3FixResourceRegion")
	logger.Info("Fixing S3 bucket regions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				return
			}
			s3Client := s3.NewFromConfig(config)
			locationParams := &s3.GetBucketLocationInput{
				Bucket: aws.String(resource.Identifier),
			}
			locationOutput, err := s3Client.GetBucketLocation(ctx, locationParams)
			if err != nil {
				if !strings.Contains(err.Error(), "StatusCode: 404") {
					logger.Error("Could not get bucket location, error: " + err.Error())
				}
				return
			}

			var location string
			if locationOutput.LocationConstraint == "" {
				location = "us-east-1"
			} else {
				location = string(locationOutput.LocationConstraint)
			}

			out <- types.EnrichedResourceDescription{
				Identifier: resource.Identifier,
				TypeName:   resource.TypeName,
				Region:     location,
				Properties: resource.Properties,
				AccountId:  resource.AccountId,
			}
		}
		close(out)
	}()
	return out
}

// AwsS3CheckBucketPAB checks the public access block configuration of an S3 bucket
func AwsS3CheckBucketPAB(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "S3CheckBucketPAB")
	logger.Info("Checking S3 public access block configs")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			s3Client := s3.NewFromConfig(config)

			pabInput := &s3.GetPublicAccessBlockInput{
				Bucket: aws.String(resource.Identifier),
			}
			pabOutput, err := s3Client.GetPublicAccessBlock(ctx, pabInput)
			if err != nil {
				if strings.Contains(err.Error(), "StatusCode: 404") {
					out <- resource
				} else {
					logger.Error("Could not get PAB for " + resource.Identifier + ", error: " + err.Error())
					out <- resource
				}
			} else {
				publicAccessBlockConfig := pabOutput.PublicAccessBlockConfiguration
				if !utils.S3BucketPABConfigFullyBlocks(publicAccessBlockConfig) || strings.Contains(resource.Properties.(string), "root") {
					out <- resource
				} else {
					continue
				}
			}
		}
		close(out)
	}()
	return out
}

// AwsS3CheckBucketACL checks the ACL of an S3 bucket
func AwsS3CheckBucketACL(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "S3CheckBucketACL")
	logger.Info("Checking S3 bucket ACLs")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			s3Client := s3.NewFromConfig(config)

			aclInput := &s3.GetBucketAclInput{
				Bucket: aws.String(resource.Identifier),
			}
			aclOutput, err := s3Client.GetBucketAcl(ctx, aclInput)
			if err != nil {
				logger.Error("Could not get ACL for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				aclResultString := utils.S3BucketACLPublic(aclOutput)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + aclResultString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}

// AwsS3CheckBucketPolicy checks the access policy of an S3 bucket
func AwsS3CheckBucketPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "S3CheckBucketPolicy")
	logger.Info("Checking S3 bucket access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			s3Client := s3.NewFromConfig(config)

			policyInput := &s3.GetBucketPolicyInput{
				Bucket: aws.String(resource.Identifier),
			}
			policyOutput, err := s3Client.GetBucketPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get bucket access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.Policy)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}
