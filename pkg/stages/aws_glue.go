package stages

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsGlueCheckResourcePolicy checks the resource access policy for Glue Catalogs.
func AwsGlueCheckResourcePolicy(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "GlueCheckResourcePolicy")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Checking Glue resource access policies")
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
			logger.Debug("Getting Glue resource access policies in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)

				glueClient := glue.NewFromConfig(config)

				policyInput := &glue.GetResourcePolicyInput{}
				policyOutput, err := glueClient.GetResourcePolicy(ctx, policyInput)

				if err != nil {
					logger.Debug("Could not get Glue resource access policy, error: " + err.Error())
					return
				} else {
					glueCatalogArn := fmt.Sprintf("arn:aws:glue:%s:%s:catalog", region, acctId)
					policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.PolicyInJson)

					newProperties := "{\"Arn\":\"" + glueCatalogArn + "\"," + policyResultString + "}"

					out <- types.EnrichedResourceDescription{
						Identifier: glueCatalogArn,
						TypeName:   rtype,
						Region:     region,
						Properties: newProperties,
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
