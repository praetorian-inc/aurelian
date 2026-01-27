package aws

import (
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/aws/lambda"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsPublicResources struct {
	*base.AwsReconLink
	resourceMap     map[string]func() chain.Chain
	processedS3     map[string]bool // Track processed S3 buckets to avoid duplicates
	processedS3Mu   sync.RWMutex    // Protect concurrent access to processedS3
}

func NewAwsPublicResources(configs ...cfg.Config) chain.Link {
	a := &AwsPublicResources{}
	// Initialize the embedded AwsReconLink with fs as the link
	a.AwsReconLink = base.NewAwsReconLink(a, configs...)
	return a
}

func (a *AwsPublicResources) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())
	params = append(params, options.AwsEnableEC2SecurityEnrichment())
	return params
}

func (a *AwsPublicResources) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	a.resourceMap = a.ResourceMap()
	a.processedS3 = make(map[string]bool)
	return nil
}

func (a *AwsPublicResources) Process(resource *types.EnrichedResourceDescription) error {
	constructor, ok := a.resourceMap[resource.TypeName]
	if !ok {
		slog.Error("Unsupported resource type", "resource", resource)
		return nil
	}

	// Deduplication for S3 buckets - only process each bucket once
	if resource.TypeName == "AWS::S3::Bucket" {
		// Create unique key using account_id:bucket_name
		bucketKey := resource.AccountId + ":" + resource.Identifier
		
		a.processedS3Mu.Lock()
		if a.processedS3[bucketKey] {
			a.processedS3Mu.Unlock()
			slog.Debug("Skipping already processed S3 bucket", "bucket", resource.Identifier, "account", resource.AccountId)
			return nil
		}
		a.processedS3[bucketKey] = true
		a.processedS3Mu.Unlock()
		
		slog.Debug("Processing S3 bucket for first time", "bucket", resource.Identifier, "account", resource.AccountId)
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Create pair and send to processor
	pair := &ResourceChainPair{
		Resource:         resource,
		ChainConstructor: constructor,
		Args:             a.Args(),
	}

	return a.Send(pair)
}

func (a *AwsPublicResources) SupportedResourceTypes() []model.CloudResourceType {
	resources := a.ResourceMap()
	types := make([]model.CloudResourceType, 0, len(resources))
	for resourceType := range resources {
		types = append(types, model.CloudResourceType(resourceType))
	}
	return types
}

func (a *AwsPublicResources) ResourceMap() map[string]func() chain.Chain {
	resourceMap := make(map[string]func() chain.Chain)

	// Check if EC2 security enrichment is enabled
	enableEC2SecurityEnrichment := false
	if args := a.Args(); args != nil {
		if val, exists := args["enable-ec2-security-enrichment"]; exists {
			if boolVal, ok := val.(bool); ok {
				enableEC2SecurityEnrichment = boolVal
			}
		}
	}

	resourceMap["AWS::EC2::Instance"] = func() chain.Chain {
		links := []chain.Link{
			cloudcontrol.NewCloudControlGet(),
			NewPropertyFilterLink(cfg.WithArg("property", "PublicIp")),
		}

		// Only add EC2 security enrichment if the flag is enabled
		if enableEC2SecurityEnrichment {
			links = append(links, NewEC2SecurityEnrichmentLink())
		}

		return chain.NewChain(links...)
	}

	resourceMap["AWS::SNS::Topic"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::SQS::Queue"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::Lambda::Function"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			lambda.NewAWSLambdaFunctionURL(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::EFS::FileSystem"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	// resourceMap["AWS::Elasticsearch::Domain"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		NewAwsResourcePolicyChecker(),
	// 	)
	// }

	resourceMap["AWS::S3::Bucket"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::RDS::DBInstance"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewPropertyFilterLink(cfg.WithArg("property", "PubliclyAccessible")),
		)
	}

	return resourceMap
}
