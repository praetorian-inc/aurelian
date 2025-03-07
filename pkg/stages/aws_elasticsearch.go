package stages

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsEsListDomains lists ElasticSearch domains in a given region.
func AwsEsListDomains(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListESDomains")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing ElasticSearch Domains")
	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logger.Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)
				esClient := elasticsearchservice.NewFromConfig(config)
				params := &elasticsearchservice.ListDomainNamesInput{}
				res, err := esClient.ListDomainNames(ctx, params)
				if err != nil {
					logger.Error(err.Error())
					return
				}

				for _, resource := range res.DomainNames {
					propertiesStr, err := json.Marshal(resource)
					if err != nil {
						logger.Error("Could not marshal properties for ElasticSearch domain")
						continue
					}

					out <- types.EnrichedResourceDescription{
						Identifier: *resource.DomainName,
						TypeName:   rtype,
						Region:     region,
						Properties: propertiesStr,
						AccountId:  acctId,
					}
				}
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// AwsEsDomainCheckResourcePolicy checks the access policy of an ElasticSearch domain.
func AwsEsDomainCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ESDomainCheckResourcePolicy")
	logger.Info("Checking ElasticSearch domain resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			esClient := elasticsearchservice.NewFromConfig(config)

			policyInput := &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
				DomainName: aws.String(resource.Identifier),
			}
			policyOutput, err := esClient.DescribeElasticsearchDomainConfig(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get ElasticSearch domain resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.DomainConfig == nil || policyOutput.DomainConfig.AccessPolicies == nil || policyOutput.DomainConfig.AccessPolicies.Options == nil {
				logger.Debug("Could not get ElasticSearch domain resource access policy for " + resource.Identifier + ", no policy exists")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.DomainConfig.AccessPolicies.Options)

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
