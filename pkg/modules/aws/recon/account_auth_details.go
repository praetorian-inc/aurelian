package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AccountAuthDetailsModule{})
}

type AccountAuthDetailsModule struct{}

func (m *AccountAuthDetailsModule) ID() string { return "account-auth-details" }

func (m *AccountAuthDetailsModule) Name() string { return "AWS Get Account Authorization Details" }

func (m *AccountAuthDetailsModule) Description() string {
	return "Get authorization details in an AWS account."
}

func (m *AccountAuthDetailsModule) Platform() plugin.Platform { return plugin.PlatformAWS }

func (m *AccountAuthDetailsModule) Category() plugin.Category { return plugin.CategoryRecon }

func (m *AccountAuthDetailsModule) OpsecLevel() string { return "moderate" }

func (m *AccountAuthDetailsModule) Authors() []string { return []string{"Praetorian"} }

func (m *AccountAuthDetailsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
		"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/iam#Client.GetAccountAuthorizationDetails",
	}
}

func (m *AccountAuthDetailsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AwsProfile(),
		options.AwsProfileDir(),
	}
}

func (m *AccountAuthDetailsModule) SupportedResourceTypes() []string {
	return []string{plugin.AnyResourceType} // IAM authorization details aren't tied to specific resource types
}

func (m *AccountAuthDetailsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Build parameters
	params := plugin.NewParameters(m.Parameters()...)
	for k, v := range cfg.Args {
		params.Set(k, v)
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	profile := params.String("profile")
	profileDir := params.String("profile-dir")

	// IAM is a global service - use us-east-1
	region := "us-east-1"

	// Build opts for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	awsCfg, err := helpers.GetAWSCfg(region, profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get account ID
	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	// Get authorization details with pagination
	authDetails, err := m.getAccountAuthDetails(cfg.Context, awsCfg, profile, accountID)
	if err != nil {
		return nil, err
	}

	// Return as CloudResource
	resource := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::AccountAuthorizationDetails",
		ResourceID:   accountID,
		Region:       region,
		AccountRef:   accountID,
		Properties:   authDetails,
	}

	return []plugin.Result{{Data: resource}}, nil
}

// getAccountAuthDetails retrieves IAM authorization details with full pagination
func (m *AccountAuthDetailsModule) getAccountAuthDetails(
	ctx context.Context,
	awsCfg aws.Config,
	profile string,
	accountID string,
) (map[string]any, error) {
	client := iam.NewFromConfig(awsCfg)

	var completeOutput *iam.GetAccountAuthorizationDetailsOutput
	maxItems := int32(1000)
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(client, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	// Paginate through all results
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error retrieving authorization details page: %w", err)
		}

		if completeOutput == nil {
			completeOutput = page
		} else {
			// Accumulate results from all pages
			completeOutput.UserDetailList = append(completeOutput.UserDetailList, page.UserDetailList...)
			completeOutput.GroupDetailList = append(completeOutput.GroupDetailList, page.GroupDetailList...)
			completeOutput.RoleDetailList = append(completeOutput.RoleDetailList, page.RoleDetailList...)
			completeOutput.Policies = append(completeOutput.Policies, page.Policies...)
		}
	}

	// Marshal to JSON
	rawData, err := json.Marshal(completeOutput)
	if err != nil {
		return nil, fmt.Errorf("error marshaling authorization details: %w", err)
	}

	// Decode URL-encoded policies
	decodedData, err := replaceURLEncodedPolicies(rawData)
	if err != nil {
		return nil, fmt.Errorf("error replacing URL-encoded policies: %w", err)
	}

	// Unmarshal decoded data
	var authDetails map[string]any
	if err := json.Unmarshal(decodedData, &authDetails); err != nil {
		return nil, fmt.Errorf("error unmarshaling decoded data: %w", err)
	}

	return authDetails, nil
}

// replaceURLEncodedPolicies decodes URL-encoded JSON policy strings in AWS IAM policy documents
// This is CRITICAL because AWS returns policy documents URL-encoded (starting with %7B)
func replaceURLEncodedPolicies(data []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	var decode func(interface{}) interface{}
	decode = func(v interface{}) interface{} {
		switch val := v.(type) {
		case map[string]interface{}:
			for k, v := range val {
				if str, ok := v.(string); ok && strings.HasPrefix(str, "%7B") {
					decoded, err := url.QueryUnescape(str)
					if err == nil {
						var policy interface{}
						if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
							val[k] = policy
						}
					}
				} else {
					val[k] = decode(v)
				}
			}
			return val
		case []interface{}:
			for i, item := range val {
				val[i] = decode(item)
			}
			return val
		default:
			return v
		}
	}

	jsonData = decode(jsonData)
	return json.Marshal(jsonData)
}
