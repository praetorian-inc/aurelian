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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/glacier"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/serverlessapplicationrepository"
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

func CloudControlGetResource(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan *cloudcontrol.GetResourceOutput {
	out := make(chan *cloudcontrol.GetResourceOutput)

	for resource := range in {
		cfg, err := helpers.GetAWSCfg(resource.Region, types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)
		if err != nil {
			panic(err)
		}

		cc := cloudcontrol.NewFromConfig(cfg)

		params := &cloudcontrol.GetResourceInput{
			Identifier: &resource.Identifier,
			TypeName:   &resource.TypeName,
		}
		go func(resource types.EnrichedResourceDescription) {
			defer close(out)
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

				out <- res
				return
			}
		}(resource)
	}

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

		config, err := helpers.GetAWSCfg("", types.GetOptionByName(options.AwsProfileOpt.Name, opts).Value)

		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting AWS config: %s", err))
			return
		}

		accountId, err := helpers.GetAccountId(config)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account ID: %s", err))
		}
		fmt.Println(accountId)

		client := iam.NewFromConfig(config)
		output, err := client.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{})
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error getting account authorization details: %s", err))
			return
		}

		res, err := json.Marshal(output)
		if err != nil {
			logs.ConsoleLogger().Error(fmt.Sprintf("Error marshalling account authorization details: %s", err))
		}

		out <- res
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
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Vault: \\($input.BackupVaultName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::EC2::Instance":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ToJson[types.EnrichedResourceDescription],
					// TODO - add jq filter to get public ip and public dns name
					JqFilter("select(.Properties | fromjson | has(\"PublicIp\")) | \"\\(.Identifier),\\(.Properties | fromjson | .PublicIp)\""),
					ToString[[]byte],
				)

			case "AWS::ECR::Repository":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ECRCheckRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Repository: \\($input.RepositoryName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::ECR::PublicRepository":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					ECRCheckPublicRepoPolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | \"Repository: \\($input.RepositoryName), Access Policy: all users can pull by default\" + (if (has(\"AccessPolicy\") and $input.AccessPolicy != null and ($input.AccessPolicy | type) == \"object\" and $input.AccessPolicy.Statement != null and $input.AccessPolicy.Statement) then \", Additional Permissions: \\($input.AccessPolicy | tostring)\" else \"\" end)"),
					ToString[[]byte],
				)

			case "AWS::EFS::FileSystem":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					EFSFileSystemCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"FileSystem: \\($input.FileSystemId)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::Glacier::Vault":
				pl, err = ChainStages[string, string](
					ListGlacierVaults,
					GlacierVaultCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Glacier Vault : \\($input.VaultName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::IAM::Role":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					IAMRoleCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"IAM Role: \\($input.RoleName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::KMS::Key":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					KMSKeyCheckResourcePolicy,
					KMSKeyCheckGrants,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if ((has(\"AccessPolicy\") and $input.AccessPolicy != null) or (has(\"Grantees\") and $input.Grantees != null)) then \"KMS Key ID: \\($input.KeyId)\" + (if has(\"Grantees\") and $input.Grantees != null and ($input.Grantees | type) == \"object\" then \", Grantees: \\($input.Grantees | tostring)\" else \"\" end) + (if has(\"AccessPolicy\") and $input.AccessPolicy != null and ($input.AccessPolicy | type) == \"object\" and $input.AccessPolicy.Statement != null and $input.AccessPolicy.Statement then \", Access Policy: \\($input.AccessPolicy | tostring)\" else \"\" end) else empty end"),
					ToString[[]byte],
				)

			case "AWS::Lambda::Function":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					LambdaCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Repository: \\($input.FunctionName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::Lambda::LayerVersion":
				pl, err = ChainStages[string, string](
					ListLambdaLayers,
					LambdaLayerCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Lambda Layer: \\($input.LayerName)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
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
					JqFilter(".Properties | fromjson | . as $input | if ((has(\"BucketACL\") and $input.BucketACL != null) or (has(\"AccessPolicy\") and $input.AccessPolicy != null)) then \"Bucket: \\($input.BucketName)\" + (if has(\"BucketACL\") and $input.BucketACL != null and ($input.BucketACL | type) == \"object\" and $input.BucketACL.Grants != null and $input.BucketACL.Grants then \", ACL: \\($input.BucketACL | tostring)\" else \"\" end) + (if has(\"AccessPolicy\") and $input.AccessPolicy != null and ($input.AccessPolicy | type) == \"object\" and $input.AccessPolicy.Statement != null and $input.AccessPolicy.Statement then \", Access Policy: \\($input.AccessPolicy | tostring)\" else \"\" end) else empty end"),
					ToString[[]byte],
				)

			case "AWS::SecretsManager::Secret":
				pl, err = ChainStages[string, string](
					CloudControlListResources,
					SecretCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Secret ID: \\($input.Id)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
					ToString[[]byte],
				)

			case "AWS::ServerlessRepo::Application":
				pl, err = ChainStages[string, string](
					ListServerlessRepoApplications,
					ServerlessRepoAppCheckResourcePolicy,
					// Echo[types.EnrichedResourceDescription],
					ToJson[types.EnrichedResourceDescription],
					JqFilter(".Properties | fromjson | . as $input | if (has(\"AccessPolicy\") and $input.AccessPolicy != null) then \"Application ID: \\($input.ApplicationId)\" + \", Access Policy: \\($input.AccessPolicy | tostring)\" else empty end"),
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
