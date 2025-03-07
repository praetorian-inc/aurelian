package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsBackupVaultCheckResourcePolicy checks the resource access policy for Backup Vaults.
func AwsBackupVaultCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "BackupVaultCheckResourcePolicy")
	logger.Info("Checking Backup Vaults resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			backupClient := backup.NewFromConfig(config)

			policyInput := &backup.GetBackupVaultAccessPolicyInput{
				BackupVaultName: aws.String(resource.Identifier),
			}

			policyOutput, err := backupClient.GetBackupVaultAccessPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get Backup Vault resource access policy for " + resource.Identifier + ", error: " + err.Error())
				continue
			}

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
		close(out)
	}()
	return out
}
