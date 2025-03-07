package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsGetAccountAuthorizationDetailsStage retrieves account authorization details for a given profile.
func AwsGetAccountAuthorizationDetailsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan []byte {
	logger := logs.NewStageLogger(ctx, opts, "GetAccountAuthorizationDetailsStage")

	out := make(chan []byte)
	var wg sync.WaitGroup

	go func() {
		for profile := range in {
			wg.Add(1)
			go func(profile string) {
				defer wg.Done()

				type gaadOut struct {
					Data     []byte
					Filename string
				}

				// Get AWS config for this profile
				config, err := helpers.GetAWSCfg("", profile, opts)
				if err != nil {
					logger.Error("Error getting AWS config for profile %s: %s", profile, err)
					return
				}

				// Get account ID
				accountId, err := helpers.GetAccountId(config)
				if err != nil {
					logger.Error("Error getting account ID for profile %s: %s", profile, err)
					return
				}

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
						logger.Error("Error getting account authorization details for profile %s: %s", profile, err)
						return
					}

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

				if completeOutput == nil {
					return
				}

				// Marshal and decode the output
				rawData, err := json.Marshal(completeOutput)
				if err != nil {
					logger.Error("Error marshaling authorization details for profile %s: %s", profile, err)
					return
				}

				decodedData, err := utils.GaadReplaceURLEncodedPolicies(rawData)
				if err != nil {
					logger.Error("Error replacing URL-encoded policies for profile %s: %s", profile, err)
					return
				}

				// filename := fmt.Sprintf("authorization-details-%s-%s-%s-gaad.json", profile, accountId, strconv.FormatInt(time.Now().Unix(), 10))
				filename := fmt.Sprintf("authorization-details-%s-%s-gaad.json", profile, accountId)
				types.OverrideResultFilename(filename)

				// Send the result with profile-specific filename
				out <- decodedData
			}(profile)
		}

		wg.Wait()
		close(out)
	}()

	return out
}

// AwsIamRoleCheckResourcePolicy checks the AssumeRole policy for an IAM role.
func AwsIamRoleCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "IAMRoleCheckResourcePolicy")
	logger.Info("Checking IAM Role AssumeRole policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			iamClient := iam.NewFromConfig(config)

			policyInput := &iam.GetRoleInput{
				RoleName: aws.String(resource.Identifier),
			}
			roleOutput, err := iamClient.GetRole(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get IAM Role AssumeRole policy for " + resource.Identifier + ", error: " + err.Error())
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
