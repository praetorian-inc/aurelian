package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/mediastore"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/serverlessapplicationrepository"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

func GetRegions(ctx context.Context, opts []*types.Option) <-chan string {
	regChan := make(chan string)
	go func() {
		defer close(regChan)
		enabled, _ := helpers.EnabledRegions(types.GetOptionByName("profile", opts).Value)

		for _, region := range enabled {
			regChan <- region
		}
	}()

	return regChan
}

func CloudControlListResources(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing resources")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)
				cc := cloudcontrol.NewFromConfig(config)
				params := &cloudcontrol.ListResourcesInput{
					TypeName: &rtype,
				}
				res, err := cc.ListResources(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.ResourceDescriptions {
					out <- types.EnrichedResourceDescription{
						Identifier: *resource.Identifier,
						TypeName:   rtype,
						Region:     region,
						Properties: *resource.Properties,
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

func CloudControlGetResource(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Getting resource to populate properties")
	go func() {
		defer close(out)
		for resource := range in {
			logs.ConsoleLogger().Info("Now getting resource: " + resource.Identifier)
			cfg, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error getting AWS config: %s", err))
				continue
			}

			cc := cloudcontrol.NewFromConfig(cfg)

			params := &cloudcontrol.GetResourceInput{
				Identifier: &resource.Identifier,
				TypeName:   &resource.TypeName,
			}

			retries := 3
			backoff := 1000

			for i := 0; i < retries; i++ {
				res, err := cc.GetResource(ctx, params)
				if err != nil && strings.Contains(err.Error(), "ThrottlingException") {
					logs.ConsoleLogger().Info("ThrottlingException encountered. Retrying in " + strconv.Itoa(backoff) + "ms")
					b := time.Duration(backoff) * time.Millisecond * time.Duration(i)
					time.Sleep(b)
					continue
				}

				if err != nil {
					logs.ConsoleLogger().Error(fmt.Sprintf("Error getting resource: %s, %s", resource.Identifier, err))
					break
				}

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: res.ResourceDescription.Properties,
					AccountId:  resource.AccountId,
				}
				break
			}
		}
	}()
	return out
}

func ParseTypes(types string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		for _, t := range strings.Split(types, ",") {
			out <- t
		}
	}()
	return out
}

func GetAccountAuthorizationDetailsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		// Get AWS config
		config, err := helpers.GetAWSCfg("", types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting AWS config: %s", err))
			return
		}

		// Get account ID
		accountId, err := helpers.GetAccountId(config)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account ID: %s", err))
			return
		}
		logs.ConsoleLogger().Info("Got account ID:", "id", accountId)

		// Initialize IAM client and pagination
		client := iam.NewFromConfig(config)
		var completeOutput *iam.GetAccountAuthorizationDetailsOutput
		var marker *string

		// Paginate through results
		for {
			input := &iam.GetAccountAuthorizationDetailsInput{
				Filter: []iamtypes.EntityType{
					iamtypes.EntityTypeUser,
					iamtypes.EntityTypeRole,
					iamtypes.EntityTypeGroup,
					iamtypes.EntityTypeLocalManagedPolicy,
					iamtypes.EntityTypeAWSManagedPolicy,
				},
				Marker: marker,
			}
			output, err := client.GetAccountAuthorizationDetails(ctx, input)
			if err != nil {
				logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account authorization details: %s", err))
				return
			}

			// Initialize or append to completeOutput
			if completeOutput == nil {
				completeOutput = output
			} else {
				completeOutput.UserDetailList = append(completeOutput.UserDetailList, output.UserDetailList...)
				completeOutput.GroupDetailList = append(completeOutput.GroupDetailList, output.GroupDetailList...)
				completeOutput.RoleDetailList = append(completeOutput.RoleDetailList, output.RoleDetailList...)
				completeOutput.Policies = append(completeOutput.Policies, output.Policies...)
			}

			if output.Marker == nil {
				break
			}
			marker = output.Marker
		}

		// Marshal the complete output
		rawData, err := json.Marshal(completeOutput)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error marshaling authorization details: %s", err))
			return
		}

		// Replace URL-encoded policies with decoded versions
		decodedData, err := utils.GaadReplaceURLEncodedPolicies(rawData)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error replacing URL-encoded policies: %s", err))
			return
		}

		out <- decodedData
	}()
	return out
}

func BackupVaultCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Backup Vaults resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			backupClient := backup.NewFromConfig(config)

			policyInput := &backup.GetBackupVaultAccessPolicyInput{
				BackupVaultName: aws.String(resource.Identifier),
			}
			policyOutput, err := backupClient.GetBackupVaultAccessPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get Backup Vault resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func CloudWatchDestinationCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking CloudWatch destination resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			logsClient := cloudwatchlogs.NewFromConfig(config)
			logs.ConsoleLogger().Info("Trying to get CloudWatch destination resource access policy for " + resource.Identifier)

			destinationsInput := &cloudwatchlogs.DescribeDestinationsInput{
				DestinationNamePrefix: aws.String(resource.Identifier),
			}
			destinationsOutput, err := logsClient.DescribeDestinations(ctx, destinationsInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get CloudWatch destination resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				var newProperties string
				for _, destination := range destinationsOutput.Destinations {
					if destination.DestinationName == &resource.Identifier {
						policyResultString := utils.CheckResourceAccessPolicy(*destination.AccessPolicy)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties = resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
			}
		}
		close(out)
	}()
	return out
}

func CognitoUserPoolGetDomains(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Cognito user pool domains")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			cognitoClient := cognitoidentityprovider.NewFromConfig(config)

			cognitoInput := &cognitoidentityprovider.DescribeUserPoolInput{
				UserPoolId: aws.String(resource.Identifier),
			}
			cognitoOutput, err := cognitoClient.DescribeUserPool(ctx, cognitoInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not describe " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				if cognitoOutput.UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly {
					out <- resource
					continue
				}

				domainString := "\"Domains\":["

				domain := cognitoOutput.UserPool.Domain
				var formattedDomain string
				if domain != nil {
					formattedDomain = fmt.Sprintf("https://%s.auth.%s.amazoncognito.com", *domain, resource.Region)
					domainString = domainString + "\"" + formattedDomain + "\","
				}

				customDomain := cognitoOutput.UserPool.CustomDomain
				var formattedCustomDomain string
				if customDomain != nil {
					formattedCustomDomain = fmt.Sprintf("https://%s", *customDomain)
					domainString = domainString + "\"" + formattedCustomDomain + "\","
				}

				if domain == nil && customDomain == nil {
					out <- resource
					continue
				}

				domainString = strings.TrimSuffix(domainString, ",")
				domainString = domainString + "]"

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + domainString + "}"

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

func CognitoUserPoolDescribeClients(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Cognito user pool clients")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			cognitoClient := cognitoidentityprovider.NewFromConfig(config)

			cognitoInput := &cognitoidentityprovider.ListUserPoolClientsInput{
				UserPoolId: aws.String(resource.Identifier),
			}

			clientPropertiesString := "\"ClientProperties\":["
			for {
				clientsOutput, err := cognitoClient.ListUserPoolClients(ctx, cognitoInput)
				if err != nil {
					logs.ConsoleLogger().Info("Could not list user pool clients for " + resource.Identifier + ", error: " + err.Error())
					out <- resource
					break
				}
				for _, client := range clientsOutput.UserPoolClients {
					describeClientInput := &cognitoidentityprovider.DescribeUserPoolClientInput{
						UserPoolId: aws.String(resource.Identifier),
						ClientId:   client.ClientId,
					}
					describeClientOutput, err := cognitoClient.DescribeUserPoolClient(ctx, describeClientInput)
					if err != nil {
						logs.ConsoleLogger().Info("Could not describe user pool client " + *client.ClientId + " for " + resource.Identifier + ", error: " + err.Error())
						continue
					}

					clientProperties := map[string]interface{}{
						"CallbackURLs":       describeClientOutput.UserPoolClient.CallbackURLs,
						"ClientId":           describeClientOutput.UserPoolClient.ClientId,
						"AllowedOAuthFlows":  describeClientOutput.UserPoolClient.AllowedOAuthFlows,
						"AllowedOAuthScopes": describeClientOutput.UserPoolClient.AllowedOAuthScopes,
					}

					clientPropertiesBytes, err := json.Marshal(clientProperties)
					if err != nil {
						logs.ConsoleLogger().Info("Could not marshal user pool client properties for " + *client.ClientId + ", error: " + err.Error())
						continue
					}
					clientPropertiesString = clientPropertiesString + string(clientPropertiesBytes) + ","
				}

				if clientsOutput.NextToken == nil {
					break
				}
				cognitoInput.NextToken = clientsOutput.NextToken
			}

			if clientPropertiesString == "\"ClientProperties\":[" {
				clientPropertiesString = "\"ClientProperties\":null"
			} else {
				clientPropertiesString = strings.TrimSuffix(clientPropertiesString, ",")
				clientPropertiesString = clientPropertiesString + "]"
			}
			lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
			newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + clientPropertiesString + "}"
			logs.ConsoleLogger().Info(newProperties)

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

func ListEBSSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing EBS snapshots")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeSnapshotsInput{
					OwnerIds: []string{acctId},
				}
				for {
					for {
						res, err := ec2Client.DescribeSnapshots(ctx, params)
						if err != nil {
							logs.ConsoleLogger().Error(err.Error())
							return
						}

						for _, snapshot := range res.Snapshots {
							properties, err := json.Marshal(snapshot)
							if err != nil {
								logs.ConsoleLogger().Error("Could not marshal EBS snapshot description")
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *snapshot.SnapshotId,
								TypeName:   rtype,
								Region:     region,
								Properties: string(properties),
								AccountId:  acctId,
							}
						}

						if res.NextToken == nil {
							break
						}
						params.NextToken = res.NextToken
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

func EBSSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking EBS snapshot create volume permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			loadPermissionInput := &ec2.DescribeSnapshotAttributeInput{
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
				SnapshotId: aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeSnapshotAttribute(ctx, loadPermissionInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not describe EBS snapshot create volume permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				loadPermissions, err := json.Marshal(permissionsOutput.CreateVolumePermissions)
				if err != nil {
					logs.ConsoleLogger().Error("Could not marshal EBS snapshot create volume permissions")
					continue
				}
				loadPermissionsString := "\"CreateVolumePermissions\":" + string(loadPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "}"

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

func ListEC2FPGAImages(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing EC2 FPGA images")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeFpgaImagesInput{
					Owners: []string{acctId},
				}
				for {
					for {
						res, err := ec2Client.DescribeFpgaImages(ctx, params)
						if err != nil {
							logs.ConsoleLogger().Error(err.Error())
							return
						}

						for _, image := range res.FpgaImages {
							properties, err := json.Marshal(image)
							if err != nil {
								logs.ConsoleLogger().Error("Could not marshal EC2 FPGA image description")
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *image.FpgaImageId,
								TypeName:   rtype,
								Region:     region,
								Properties: string(properties),
								AccountId:  acctId,
							}
						}

						if res.NextToken == nil {
							break
						}
						params.NextToken = res.NextToken
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

func EC2FPGAImageDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking EC2 FPGA image load permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			loadPermissionInput := &ec2.DescribeFpgaImageAttributeInput{
				Attribute:   ec2types.FpgaImageAttributeNameLoadPermission,
				FpgaImageId: aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeFpgaImageAttribute(ctx, loadPermissionInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not describe EC2 FPGA image load permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				loadPermissions, err := json.Marshal(permissionsOutput.FpgaImageAttribute.LoadPermissions)
				if err != nil {
					logs.ConsoleLogger().Error("Could not marshal EC2 FPGA image load permissions")
					continue
				}
				loadPermissionsString := "\"LoadPermissions\":" + string(loadPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "}"

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

func ListEC2Images(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing EC2 AMIs")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				ec2Client := ec2.NewFromConfig(config)
				params := &ec2.DescribeImagesInput{
					Owners: []string{acctId},
				}
				for {
					for {
						res, err := ec2Client.DescribeImages(ctx, params)
						if err != nil {
							logs.ConsoleLogger().Error(err.Error())
							return
						}

						for _, image := range res.Images {
							properties, err := json.Marshal(image)
							if err != nil {
								logs.ConsoleLogger().Error("Could not marshal EC2 image description")
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *image.ImageId,
								TypeName:   rtype,
								Region:     region,
								Properties: string(properties),
								AccountId:  acctId,
							}
						}

						if res.NextToken == nil {
							break
						}
						params.NextToken = res.NextToken
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

func EC2ImageDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking EC2 AMI launch permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ec2Client := ec2.NewFromConfig(config)

			launchPermissionInput := &ec2.DescribeImageAttributeInput{
				Attribute: ec2types.ImageAttributeNameLaunchPermission,
				ImageId:   aws.String(resource.Identifier),
			}
			permissionsOutput, err := ec2Client.DescribeImageAttribute(ctx, launchPermissionInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get EC2 image launch permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				launchPermissions, err := json.Marshal(permissionsOutput.LaunchPermissions)
				if err != nil {
					logs.ConsoleLogger().Error("Could not marshal EC2 image launch permissions")
					continue
				}
				launchPermissionsString := "\"LaunchPermissions\":" + string(launchPermissions)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + launchPermissionsString + "}"

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

func Ec2ListPublic(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for region := range in {
				logs.ConsoleLogger().Debug("Listing public EC2 resources for " + region)
				config, _ := helpers.GetAWSCfg(region, types.GetOptionByName("profile", opts).Value)
				client := ec2.NewFromConfig(config)

				ec2Input := ec2.DescribeInstancesInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("network-interface.association.public-ip"),
							Values: []string{"*"}, // Filters instances with a public IP
						},
						{
							Name:   aws.String("network-interface.association.public-dns-name"),
							Values: []string{"*"}, // Filters instances with a public DNS name
						},
					},
				}
				output, err := client.DescribeInstances(ctx, &ec2Input)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					continue
				}

				for _, reservation := range output.Reservations {
					for _, instance := range reservation.Instances {
						for _, networkInterface := range instance.NetworkInterfaces {
							if networkInterface.Association != nil {
								if networkInterface.Association.PublicIp != nil {
									out <- *networkInterface.Association.PublicIp
								}
								if networkInterface.Association.PublicDnsName != nil {
									out <- *networkInterface.Association.PublicDnsName
								}
							}
						}
					}
				}

			}

		}()
		return out
	}
}

func ECRCheckRepoPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking ECR repository access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ecrClient := ecr.NewFromConfig(config)

			policyInput := &ecr.GetRepositoryPolicyInput{
				RepositoryName: aws.String(resource.Identifier),
			}
			policyOutput, err := ecrClient.GetRepositoryPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get ECR repository access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.PolicyText)

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

func ECRCheckPublicRepoPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking ECR public repository access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ecrPublicClient := ecrpublic.NewFromConfig(config)

			policyInput := &ecrpublic.GetRepositoryPolicyInput{
				RepositoryName: aws.String(resource.Identifier),
			}
			policyOutput, err := ecrPublicClient.GetRepositoryPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get ECR public repository access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.PolicyText)

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

func EFSFileSystemCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking EFS File Systems resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			efsClient := efs.NewFromConfig(config)

			policyInput := &efs.DescribeFileSystemPolicyInput{
				FileSystemId: aws.String(resource.Identifier),
			}
			policyOutput, err := efsClient.DescribeFileSystemPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get EFS File Systems resource access policy for " + resource.Identifier + ", error: " + err.Error())
				if strings.Contains(err.Error(), "PolicyNotFound") {
					lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
					newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"AccessPolicy\":\"Default (all users with network access can mount)\"}"

					out <- types.EnrichedResourceDescription{
						Identifier: resource.Identifier,
						TypeName:   resource.TypeName,
						Region:     resource.Region,
						Properties: newProperties,
						AccountId:  resource.AccountId,
					}
				} else {
					out <- resource
				}
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

func ListESDomains(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing ElasticSearch Domains")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)
				esClient := elasticsearchservice.NewFromConfig(config)
				params := &elasticsearchservice.ListDomainNamesInput{}
				res, err := esClient.ListDomainNames(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.DomainNames {
					propertiesStr, err := json.Marshal(resource)
					if err != nil {
						logs.ConsoleLogger().Error("Could not marshal properties for ElasticSearch domain")
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

func ESDomainCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking ElasticSearch domain resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			esClient := elasticsearchservice.NewFromConfig(config)

			policyInput := &elasticsearchservice.DescribeElasticsearchDomainConfigInput{
				DomainName: aws.String(resource.Identifier),
			}
			policyOutput, err := esClient.DescribeElasticsearchDomainConfig(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get ElasticSearch domain resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.DomainConfig == nil || policyOutput.DomainConfig.AccessPolicies == nil || policyOutput.DomainConfig.AccessPolicies.Options == nil {
				logs.ConsoleLogger().Debug("Could not get ElasticSearch domain resource access policy for " + resource.Identifier + ", no policy exists")
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

func EventBusCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking event bus resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			eventsClient := eventbridge.NewFromConfig(config)

			describeInput := &eventbridge.DescribeEventBusInput{
				Name: aws.String(resource.Identifier),
			}
			describeOutput, err := eventsClient.DescribeEventBus(ctx, describeInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get event bus resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if describeOutput.Policy == nil {
				logs.ConsoleLogger().Debug("Could not get event bus resource access policy for " + resource.Identifier + ", no policy found")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*describeOutput.Policy)

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

func ListGlacierVaults(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing Glacier Vaults")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				glacierClient := glacier.NewFromConfig(config)
				params := &glacier.ListVaultsInput{
					AccountId: aws.String(acctId),
				}
				for {
					res, err := glacierClient.ListVaults(ctx, params)
					if err != nil {
						logs.ConsoleLogger().Error(err.Error())
						return
					}

					for _, vault := range res.VaultList {
						properties, err := json.Marshal(vault)
						if err != nil {
							logs.ConsoleLogger().Error("Could not marshal Glacier vault")
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

func GlacierVaultCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Glacier Vault resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			glacierClient := glacier.NewFromConfig(config)

			policyInput := &glacier.GetVaultAccessPolicyInput{
				AccountId: aws.String(resource.AccountId),
				VaultName: aws.String(resource.Identifier),
			}
			policyOutput, err := glacierClient.GetVaultAccessPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get Glacier Vault resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func GlueCheckResourcePolicy(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Checking Glue resource access policies")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Getting Glue resource access policies in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				glueClient := glue.NewFromConfig(config)

				policyInput := &glue.GetResourcePolicyInput{}
				policyOutput, err := glueClient.GetResourcePolicy(ctx, policyInput)

				if err != nil {
					logs.ConsoleLogger().Debug("Could not get Glue resource access policy, error: " + err.Error())
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

func IAMRoleCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking IAM Role AssumeRole policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			iamClient := iam.NewFromConfig(config)

			policyInput := &iam.GetRoleInput{
				RoleName: aws.String(resource.Identifier),
			}
			roleOutput, err := iamClient.GetRole(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get IAM Role AssumeRole policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*roleOutput.Role.AssumeRolePolicyDocument)

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

func KMSKeyCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking KMS key resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			kmsClient := kms.NewFromConfig(config)

			policyInput := &kms.GetKeyPolicyInput{
				KeyId: aws.String(resource.Identifier),
			}
			policyOutput, err := kmsClient.GetKeyPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get KMS key resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func KMSKeyCheckGrants(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking KMS key grants")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			kmsClient := kms.NewFromConfig(config)

			policyInput := &kms.ListGrantsInput{
				KeyId: aws.String(resource.Identifier),
			}
			for {
				policyOutput, err := kmsClient.ListGrants(ctx, policyInput)
				if err != nil {
					logs.ConsoleLogger().Debug("Could not get KMS key grants for " + resource.Identifier + ", error: " + err.Error())
					out <- resource
					break
				}

				var grantees []string
				for _, grant := range policyOutput.Grants {
					if strings.Contains(*grant.GranteePrincipal, "*") || strings.Contains(*grant.GranteePrincipal, "root") {
						grantees = append(grantees, *grant.GranteePrincipal)
					}
				}

				if len(grantees) == 0 {
					out <- resource
					break
				}

				granteesJson, err := json.Marshal(grantees)
				if err != nil {
					logs.ConsoleLogger().Error("Could not marshal grantees")
					continue
				}

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"Grantees\":" + string(granteesJson) + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}

				if policyOutput.NextMarker == nil {
					break
				}
				policyInput.Marker = policyOutput.NextMarker
			}
		}
		close(out)
	}()
	return out
}

func LambdaGetFunctionUrl(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logs.ConsoleLogger().Info("Getting Lambda function URLs")
	out := make(chan string)
	go func() {
		for resource := range in {
			logs.ConsoleLogger().Debug("Getting URL for Lambda function: " + resource.Identifier)
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				out <- ""
			}
			client := lambda.NewFromConfig(config)
			params := &lambda.GetFunctionUrlConfigInput{
				FunctionName: aws.String(resource.Identifier),
			}
			output, err := client.GetFunctionUrlConfig(ctx, params)
			if err != nil {
				if !strings.Contains(err.Error(), "StatusCode: 404") {
					logs.ConsoleLogger().Error(err.Error())
				}
				continue
			}

			out <- *output.FunctionUrl
		}
		close(out)
	}()
	return out
}

func ListLambdaFunctions(ctx context.Context, profile string) Stage[string, string] {
	return func(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
		out := make(chan string)
		go func() {
			defer close(out)
			for region := range in {
				logs.ConsoleLogger().Debug("Listing Lambda functions " + region)
				config, err := helpers.GetAWSCfg(region, profile)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					continue
				}
				client := lambda.NewFromConfig(config)
				params := &lambda.ListFunctionsInput{}
				output, err := client.ListFunctions(ctx, params)
				if err != nil {
					out <- ""
					logs.ConsoleLogger().Error(err.Error())
				}

				for _, function := range output.Functions {
					out <- *function.FunctionArn
				}
			}
		}()
		return out
	}
}

func ListLambdaLayers(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing Lambda Layers")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)
				lambdaClient := lambda.NewFromConfig(config)
				params := &lambda.ListLayersInput{}
				res, err := lambdaClient.ListLayers(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.Layers {
					latestMatchingVersionStr, err := json.Marshal(resource.LatestMatchingVersion)
					if err != nil {
						logs.ConsoleLogger().Error("Could not marshal Lambda layer version")
						continue
					}
					lastBracketIndex := strings.LastIndex(string(latestMatchingVersionStr), "}")
					newProperties := string(latestMatchingVersionStr)[:lastBracketIndex] + "," + "\"LayerName\":\"" + *resource.LayerName + "\"" + "}"

					out <- types.EnrichedResourceDescription{
						Identifier: *resource.LayerName,
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

func LambdaCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Lambda function resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			lambdaClient := lambda.NewFromConfig(config)

			policyInput := &lambda.GetPolicyInput{
				FunctionName: aws.String(resource.Identifier),
			}
			policyOutput, err := lambdaClient.GetPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get Lambda function resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func LambdaLayerCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking Lambda layer resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			lambdaClient := lambda.NewFromConfig(config)

			var properties map[string]interface{}
			if err := json.Unmarshal([]byte(resource.Properties.(string)), &properties); err != nil {
				logs.ConsoleLogger().Error("Could not unmarshal Lambda layer version, error: " + err.Error())
				continue
			}
			version, ok := properties["Version"].(float64)
			if !ok {
				logs.ConsoleLogger().Error("Could not find Lambda layer version")
				continue
			}

			policyInput := &lambda.GetLayerVersionPolicyInput{
				LayerName:     aws.String(resource.Identifier),
				VersionNumber: aws.Int64(int64(version)),
			}
			policyOutput, err := lambdaClient.GetLayerVersionPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get Lambda layer resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func ListMediaStoreContainers(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing MediaStore Containers")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)
				mediastoreClient := mediastore.NewFromConfig(config)
				params := &mediastore.ListContainersInput{}
				res, err := mediastoreClient.ListContainers(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.Containers {
					propertiesStr, err := json.Marshal(resource)
					if err != nil {
						logs.ConsoleLogger().Error("Could not marshal properties for MediaStore container")
						continue
					}

					out <- types.EnrichedResourceDescription{
						Identifier: *resource.Name,
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

func MediaStoreContainerCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking MediaStore container resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			mediastoreClient := mediastore.NewFromConfig(config)

			policyInput := &mediastore.GetContainerPolicyInput{
				ContainerName: aws.String(resource.Identifier),
			}
			policyOutput, err := mediastoreClient.GetContainerPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get MediaStore container resource access policy for " + resource.Identifier + ", error: " + err.Error())
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

func OSSDomainCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking OpenSearch domain resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ossClient := opensearch.NewFromConfig(config)

			policyInput := &opensearch.DescribeDomainConfigInput{
				DomainName: aws.String(resource.Identifier),
			}
			policyOutput, err := ossClient.DescribeDomainConfig(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get OpenSearch domain resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.DomainConfig == nil || policyOutput.DomainConfig.AccessPolicies == nil || policyOutput.DomainConfig.AccessPolicies.Options == nil {
				logs.ConsoleLogger().Debug("Could not get OpenSearch domain resource access policy for " + resource.Identifier + ", no policy exists")
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

func ListRDSDBSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing RDS DB snapshots")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				rdsClient := rds.NewFromConfig(config)
				params := &rds.DescribeDBSnapshotsInput{
					IncludePublic: aws.Bool(true),
					SnapshotType:  aws.String("manual"),
				}
				for {
					for {
						res, err := rdsClient.DescribeDBSnapshots(ctx, params)
						if err != nil {
							logs.ConsoleLogger().Error(err.Error())
							return
						}

						for _, snapshot := range res.DBSnapshots {
							properties, err := json.Marshal(snapshot)
							if err != nil {
								logs.ConsoleLogger().Error("Could not marshal RDS DB snapshot description")
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *snapshot.DBSnapshotIdentifier,
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

func RDSDBSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking RDS DB snapshot restore snapshot permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			rdsClient := rds.NewFromConfig(config)

			loadPermissionInput := &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: aws.String(resource.Identifier),
			}
			permissionsOutput, err := rdsClient.DescribeDBSnapshotAttributes(ctx, loadPermissionInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not describe RDS DB snapshot restore snapshot permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				for _, attribute := range permissionsOutput.DBSnapshotAttributesResult.DBSnapshotAttributes {
					if *attribute.AttributeName == "restore" {
						restorePermissions, err := json.Marshal(attribute.AttributeValues)
						if err != nil {
							logs.ConsoleLogger().Error("Could not marshal RDS DB snapshot restore snapshot permissions")
							continue
						}
						loadPermissionsString := "\"RestorePermissions\":[" + string(restorePermissions)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "]}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
				out <- resource

			}
		}
		close(out)
	}()
	return out
}

func ListRDSDBClusterSnapshots(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing RDS DB cluster snapshots")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				rdsClient := rds.NewFromConfig(config)
				params := &rds.DescribeDBClusterSnapshotsInput{
					IncludePublic: aws.Bool(true),
					SnapshotType:  aws.String("manual"),
				}
				for {
					for {
						res, err := rdsClient.DescribeDBClusterSnapshots(ctx, params)
						if err != nil {
							logs.ConsoleLogger().Error(err.Error())
							return
						}

						for _, snapshot := range res.DBClusterSnapshots {
							properties, err := json.Marshal(snapshot)
							if err != nil {
								logs.ConsoleLogger().Error("Could not marshal RDS DB snapshot description")
								continue
							}

							out <- types.EnrichedResourceDescription{
								Identifier: *snapshot.DBClusterIdentifier,
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

func RDSDBClusterSnapshotDescribeAttributes(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking RDS DB cluster snapshot restore snapshot permissions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			rdsClient := rds.NewFromConfig(config)

			loadPermissionInput := &rds.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: aws.String(resource.Identifier),
			}
			permissionsOutput, err := rdsClient.DescribeDBClusterSnapshotAttributes(ctx, loadPermissionInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not describe RDS DB cluster snapshot restore snapshot permissions for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				for _, attribute := range permissionsOutput.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
					if *attribute.AttributeName == "restore" {
						restorePermissions, err := json.Marshal(attribute.AttributeValues)
						if err != nil {
							logs.ConsoleLogger().Error("Could not marshal RDS DB cluster snapshot restore snapshot permissions")
							continue
						}
						loadPermissionsString := "\"RestorePermissions\":[" + string(restorePermissions)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + loadPermissionsString + "]}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
				out <- resource

			}
		}
		close(out)
	}()
	return out
}

func S3FixResourceRegion(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Fixing S3 bucket regions")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				return
			}
			s3Client := s3.NewFromConfig(config)
			locationParams := &s3.GetBucketLocationInput{
				Bucket: aws.String(resource.Identifier),
			}
			locationOutput, err := s3Client.GetBucketLocation(ctx, locationParams)
			if err != nil {
				if !strings.Contains(err.Error(), "StatusCode: 404") {
					logs.ConsoleLogger().Error("Could not get bucket location, error: " + err.Error())
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

func S3CheckBucketPAB(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking S3 public access block configs")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
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
					logs.ConsoleLogger().Error("Could not get PAB for " + resource.Identifier + ", error: " + err.Error())
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

func S3CheckBucketACL(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking S3 bucket ACLs")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			s3Client := s3.NewFromConfig(config)

			aclInput := &s3.GetBucketAclInput{
				Bucket: aws.String(resource.Identifier),
			}
			aclOutput, err := s3Client.GetBucketAcl(ctx, aclInput)
			if err != nil {
				logs.ConsoleLogger().Error("Could not get ACL for " + resource.Identifier + ", error: " + err.Error())
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

func S3CheckBucketPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking S3 bucket access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			s3Client := s3.NewFromConfig(config)

			policyInput := &s3.GetBucketPolicyInput{
				Bucket: aws.String(resource.Identifier),
			}
			policyOutput, err := s3Client.GetBucketPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get bucket access policy for " + resource.Identifier + ", error: " + err.Error())
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

func SecretCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking SecretsManager secret access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			smClient := secretsmanager.NewFromConfig(config)

			policyInput := &secretsmanager.GetResourcePolicyInput{
				SecretId: aws.String(resource.Identifier),
			}
			policyOutput, err := smClient.GetResourcePolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get SecretsManager secret access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.ResourcePolicy == nil {
				logs.ConsoleLogger().Debug("Could not get SecretsManager secret access policy for " + resource.Identifier + ", policy doesn't exist")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.ResourcePolicy)

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

func ListServerlessRepoApplications(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	out := make(chan types.EnrichedResourceDescription)
	logs.ConsoleLogger().Info("Listing serverless repo applications")
	profile := types.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(types.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logs.ConsoleLogger().Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		// Capture the current value of rtype by passing it to the goroutine
		for _, region := range regions {
			logs.ConsoleLogger().Debug("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile)

				serverlessrepoClient := serverlessapplicationrepository.NewFromConfig(config)
				params := &serverlessapplicationrepository.ListApplicationsInput{}
				res, err := serverlessrepoClient.ListApplications(ctx, params)
				if err != nil {
					logs.ConsoleLogger().Error(err.Error())
					return
				}

				for _, resource := range res.Applications {
					properties, err := json.Marshal(resource)
					if err != nil {
						logs.ConsoleLogger().Error("Could not marshal serverless repo application")
						continue
					}

					out <- types.EnrichedResourceDescription{
						Identifier: *resource.ApplicationId,
						TypeName:   rtype,
						Region:     region,
						Properties: string(properties),
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

func ServerlessRepoAppCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking serverless repo app resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			serverlessrepoClient := serverlessapplicationrepository.NewFromConfig(config)

			policyInput := &serverlessapplicationrepository.GetApplicationPolicyInput{
				ApplicationId: aws.String(resource.Identifier),
			}
			policyOutput, err := serverlessrepoClient.GetApplicationPolicy(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get serverless repo app resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckServerlessRepoAppResourceAccessPolicy(policyOutput.Statements)

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

func SESIdentityCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking SES email identity resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			sesClient := ses.NewFromConfig(config)

			policyInput := &ses.ListIdentityPoliciesInput{
				Identity: aws.String(resource.Identifier),
			}
			policyOutput, err := sesClient.ListIdentityPolicies(ctx, policyInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get SES email identity resource access policies for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				var policyResultStrings []string
				for i := 0; i < len(policyOutput.PolicyNames); i += 20 {
					end := i + 20
					if end > len(policyOutput.PolicyNames) {
						end = len(policyOutput.PolicyNames)
					}
					policyNamesChunk := policyOutput.PolicyNames[i:end]

					policyInput := &ses.GetIdentityPoliciesInput{
						Identity:    aws.String(resource.Identifier),
						PolicyNames: policyNamesChunk,
					}
					policyDetails, err := sesClient.GetIdentityPolicies(ctx, policyInput)
					if err != nil {
						logs.ConsoleLogger().Debug("Could not get SES email identity policy details for " + resource.Identifier + ", error: " + err.Error())
						continue
					}

					for _, policyDocument := range policyDetails.Policies {
						policyResultString := utils.CheckResourceAccessPolicy(policyDocument)
						start := strings.Index(policyResultString, "[")
						end := strings.LastIndex(policyResultString, "]")
						if start != -1 && end != -1 {
							policyResultStrings = append(policyResultStrings, policyResultString[start+1:end])
						}
					}
				}

				if len(policyResultStrings) > 0 {
					lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
					newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"AccessPolicy\":{\"Statement\":[" + strings.Join(policyResultStrings, ",") + "]}}"

					out <- types.EnrichedResourceDescription{
						Identifier: resource.Identifier,
						TypeName:   resource.TypeName,
						Region:     resource.Region,
						Properties: newProperties,
						AccountId:  resource.AccountId,
					}
				} else {
					out <- resource
				}
			}
		}
		close(out)
	}()
	return out
}

func SNSTopicCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking SNS topic access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			snsClient := sns.NewFromConfig(config)

			attributeInput := &sns.GetTopicAttributesInput{
				TopicArn: aws.String(resource.Identifier),
			}
			attributeOutput, err := snsClient.GetTopicAttributes(ctx, attributeInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not getSNS topic access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			}

			policyString, ok := attributeOutput.Attributes["Policy"]
			if !ok {
				logs.ConsoleLogger().Debug("Could not find policy attribute for " + resource.Identifier)
				out <- resource
				continue
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(policyString)

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

func SQSQueueCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logs.ConsoleLogger().Info("Checking SQS queue access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
			if err != nil {
				logs.ConsoleLogger().Error("Could not set up client config, error: " + err.Error())
				continue
			}
			sqsClient := sqs.NewFromConfig(config)

			attributeInput := &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(resource.Identifier),
				AttributeNames: []sqsTypes.QueueAttributeName{
					sqsTypes.QueueAttributeNamePolicy,
				},
			}
			attributeOutput, err := sqsClient.GetQueueAttributes(ctx, attributeInput)
			if err != nil {
				logs.ConsoleLogger().Debug("Could not get SQS queue access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			}

			policyString, ok := attributeOutput.Attributes["Policy"]
			if !ok {
				logs.ConsoleLogger().Debug("Could not find policy attribute for " + resource.Identifier)
				out <- resource
				continue
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(policyString)

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

func AwsPublicResources(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {

	out := make(chan string)
	//var pipelines []stages.Stage[string, string]

	go func() {
		defer close(out)
		for rtype := range in {

			logs.ConsoleLogger().Debug("Running recon for resource type: " + rtype)
			var pl Stage[string, string]
			var err error
			switch rtype {
			case "AWS::Backup::BackupVault":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					BackupVaultCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .BackupVaultName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Cognito::UserPool":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					CognitoUserPoolGetDomains,
					CognitoUserPoolDescribeClients,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"Domains\")) | {Type: .TypeName, Identifier: .Identifier, Domains: (.Properties | fromjson | .Domains), ClientProperties: (.Properties | fromjson | .ClientProperties // null)}"),
					ToString[[]byte],
				)

			case "AWS::EBS::Snapshot":
				pl, err = ChainStages[string, string](
					ListEBSSnapshots,
					EBSSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::FPGAImage":
				pl, err = ChainStages[string, string](
					ListEC2FPGAImages,
					EC2FPGAImageDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"LoadPermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, LoadPermissions: (.Properties | fromjson | .LoadPermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::Image":
				pl, err = ChainStages[string, string](
					ListEC2Images,
					EC2ImageDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"LaunchPermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, LaunchPermissions: (.Properties | fromjson | .LaunchPermissions)}"),
					ToString[[]byte],
				)

			case "AWS::EC2::Instance":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"PublicIp\")) | {Identifier: .TypeName, Identifier: .Identifier, PublicIp: (.Properties | fromjson | .PublicIp)}"),
					ToString[[]byte],
				)

			case "AWS::ECR::Repository":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ECRCheckRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .RepositoryName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ECR::PublicRepository":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ECRCheckPublicRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("{Type: .TypeName, Identifier: (.Properties | fromjson | .RepositoryName), VulnerableAccessPolicies: \"all users can pull by default\", AdditionalVulnerablePermissions: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::EFS::FileSystem":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					EFSFileSystemCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .FileSystemId), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ElasticSearch::Domain":
				pl, err = ChainStages[string, string](
					ListESDomains,
					ESDomainCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DomainName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Events::EventBus":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					EventBusCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Name), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Glacier::Vault":
				pl, err = ChainStages[string, string](
					ListGlacierVaults,
					GlacierVaultCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .VaultName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Glue::ResourcePolicy":
				pl, err = ChainStages[string, string](
					GlueCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Arn), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::IAM::Role":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					IAMRoleCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .RoleName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::KMS::Key":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					KMSKeyCheckResourcePolicy,
					KMSKeyCheckGrants,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null) or (has(\"Grantees\") and $input.Grantees != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .KeyId), VulnerableGrantees: (.Properties | fromjson | .Grantees // null), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Lambda::Function":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					LambdaCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .FunctionName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Lambda::LayerVersion":
				pl, err = ChainStages[string, string](
					ListLambdaLayers,
					LambdaLayerCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .LayerName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::Logs::Destination":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					CloudControlGetResource,
					CloudWatchDestinationCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DestinationName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			// this is an untested resource type
			case "AWS::Logs::ResourcePolicy":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					CloudControlGetResource,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"PolicyDocument\") and $input.PolicyDocument != null)) | {Type: .TypeName, VulnerableAccessPolicies: (.Properties | fromjson | .PolicyDocument // null)}"),
					ToString[[]byte],
				)

			case "AWS::MediaStore::Container":
				pl, err = ChainStages[string, string](
					ListMediaStoreContainers,
					MediaStoreContainerCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Name), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::OpenSearchService::Domain":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					OSSDomainCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .DomainName), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::RDS::DBClusterSnapshot":
				pl, err = ChainStages[string, string](
					ListRDSDBClusterSnapshots,
					RDSDBClusterSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::RDS::DBSnapshot":
				pl, err = ChainStages[string, string](
					ListRDSDBSnapshots,
					RDSDBSnapshotDescribeAttributes,
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | has(\"CreateVolumePermissions\")) | {Identifier: .TypeName, Identifier: .Identifier, CreateVolumePermissions: (.Properties | fromjson | .CreateVolumePermissions)}"),
					ToString[[]byte],
				)

			case "AWS::S3::Bucket":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					S3FixResourceRegion,
					S3CheckBucketACL,
					S3CheckBucketPolicy,
					S3CheckBucketPAB,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | ((has(\"BucketACL\") and $input.BucketACL != null) or (has(\"AccessPolicy\") and $input.AccessPolicy != null))) | {Type: .TypeName, Identifier: (.Properties | fromjson | .BucketName), VulnerableBucketACLs: (.Properties | fromjson | .BucketACL // null), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SecretsManager::Secret":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					SecretCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .Id), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::ServerlessRepo::Application":
				pl, err = ChainStages[string, string](
					ListServerlessRepoApplications,
					ServerlessRepoAppCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .ApplicationId), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SES::EmailIdentity":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					SESIdentityCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .EmailIdentity), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SNS::Topic":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					SNSTopicCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .TopicArn), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			case "AWS::SQS::Queue":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					SQSQueueCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter("select(.Properties | fromjson | . as $input | (has(\"AccessPolicy\") and $input.AccessPolicy != null)) | {Type: .TypeName, Identifier: (.Properties | fromjson | .QueueUrl), VulnerableAccessPolicies: (.Properties | fromjson | .AccessPolicy // null)}"),
					ToString[[]byte],
				)

			default:
				continue
			}

			if err != nil {
				logs.ConsoleLogger().Error("Failed to " + rtype + " create pipeline: " + err.Error())
				continue
			}

			wg := new(sync.WaitGroup)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range pl(ctx, opts, Generator([]string{rtype})) {
					out <- s
				}
			}()
			wg.Wait()
		}

		//stages.FanStages(ctx, opts, in, out, pipelines...)
	}()

	return out

}

func ToJson[In any](ctx context.Context, opts []*types.Option, in <-chan In) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)
		for resource := range in {
			res, err := json.Marshal(resource)
			if err != nil {
				logs.ConsoleLogger().Error(err.Error())
				continue
			}
			out <- res
		}
	}()
	return out
}
