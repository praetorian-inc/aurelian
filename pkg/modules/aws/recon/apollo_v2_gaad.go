package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	sdktypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// gatherGaad fetches AWS IAM GetAccountAuthorizationDetails (GAAD) data using direct SDK calls.
// This replaces the Janus chain-based GAAD fetching pattern.
func (a *ApolloV2) gatherGaad(ctx context.Context) (*types.Gaad, error) {
	slog.Debug("Getting Account Authorization Details", "profile", a.Profile)

	// IAM is a global service - use us-east-1
	region := "us-east-1"
	slog.Debug("Getting Account Authorization Details", "region", region)

	// Create IAM client from existing config
	iamClient := iam.NewFromConfig(a.config)

	// Use paginator to fetch all authorization details
	maxItems := int32(1000)
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(iamClient, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	var completeOutput *iam.GetAccountAuthorizationDetailsOutput

	// Paginate through all results
	for paginator.HasMorePages() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get GAAD page: %w", err)
		}

		if completeOutput == nil {
			completeOutput = page
		} else {
			// Append paginated results
			completeOutput.UserDetailList = append(completeOutput.UserDetailList, page.UserDetailList...)
			completeOutput.GroupDetailList = append(completeOutput.GroupDetailList, page.GroupDetailList...)
			completeOutput.RoleDetailList = append(completeOutput.RoleDetailList, page.RoleDetailList...)
			completeOutput.Policies = append(completeOutput.Policies, page.Policies...)
		}
	}

	// Convert SDK types to internal types.Gaad structure
	gaad, err := a.convertGaadOutput(completeOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to convert GAAD output: %w", err)
	}

	slog.Info("Retrieved GAAD successfully", "users", len(gaad.UserDetailList), "roles", len(gaad.RoleDetailList), "groups", len(gaad.GroupDetailList), "policies", len(gaad.Policies))

	return gaad, nil
}

// convertGaadOutput converts AWS SDK GAAD output to internal types.Gaad structure.
// This includes decoding URL-encoded policy documents.
func (a *ApolloV2) convertGaadOutput(output *iam.GetAccountAuthorizationDetailsOutput) (*types.Gaad, error) {
	// Marshal SDK output to JSON
	rawData, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GAAD output: %w", err)
	}

	// Decode URL-encoded policies (AWS sometimes URL-encodes AssumeRolePolicyDocument)
	decodedData, err := replaceURLEncodedPolicies(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode URL-encoded policies: %w", err)
	}

	// Unmarshal to internal types.Gaad structure
	var gaad types.Gaad
	if err := json.Unmarshal(decodedData, &gaad); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GAAD: %w", err)
	}

	return &gaad, nil
}

// replaceURLEncodedPolicies decodes URL-encoded JSON policy strings in AWS IAM policy documents.
// AWS sometimes returns AssumeRolePolicyDocument as URL-encoded JSON strings.
// This function recursively decodes these strings to proper JSON structures.
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

// convertIAMTypes converts AWS SDK IAM types to internal types
// These helper functions handle the conversion from SDK types to internal types

func convertUser(user sdktypes.UserDetail) types.UserDL {
	return types.UserDL{
		Arn:      stringValue(user.Arn),
		UserName: stringValue(user.UserName),
		UserId:   stringValue(user.UserId),
		// Add other fields as needed
	}
}

func convertRole(role sdktypes.RoleDetail) types.RoleDL {
	return types.RoleDL{
		Arn:      stringValue(role.Arn),
		RoleName: stringValue(role.RoleName),
		RoleId:   stringValue(role.RoleId),
		// Add other fields as needed
	}
}

func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
