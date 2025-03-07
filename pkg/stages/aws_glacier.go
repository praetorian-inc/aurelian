package stages

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsGlacierListVaults lists Glacier Vaults in a given region.
func AwsGlacierListVaults(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ListGlacierVaults")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing Glacier Vaults")
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

				glacierClient := glacier.NewFromConfig(config)
				params := &glacier.ListVaultsInput{
					AccountId: aws.String(acctId),
				}
				for {
					res, err := glacierClient.ListVaults(ctx, params)
					if err != nil {
						logger.Error(err.Error())
						return
					}

					for _, vault := range res.VaultList {
						properties, err := json.Marshal(vault)
						if err != nil {
							logger.Error("Could not marshal Glacier vault")
							continue
						}

						out <- types.EnrichedResourceDescription{
							Identifier: *vault.VaultName,
							TypeName:   rtype,
							Region:     region,
							Properties: string(properties),
							AccountId:  acctId,
						}
					}

					if res.Marker == nil {
						break
					}
					params.Marker = res.Marker
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

// AwsGlacierVaultCheckResourcePolicy checks the access policy for a Glacier Vault.
func AwsGlacierVaultCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "GlacierVaultCheckResourcePolicy")
	logger.Info("Checking Glacier Vault resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			glacierClient := glacier.NewFromConfig(config)

			policyInput := &glacier.GetVaultAccessPolicyInput{
				AccountId: aws.String(resource.AccountId),
				VaultName: aws.String(resource.Identifier),
			}
			policyOutput, err := glacierClient.GetVaultAccessPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get Glacier Vault resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.Policy.Policy)

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
