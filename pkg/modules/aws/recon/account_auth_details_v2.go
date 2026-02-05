package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// GetAccountAuthDetailsV2 retrieves AWS IAM authorization details using plain Go patterns
// instead of janus-framework chains.
type GetAccountAuthDetailsV2 struct {
	Profile string
	Region  string // Default: "us-east-1" (IAM is a global service)
}

// NewGetAccountAuthDetailsV2 creates a new v2 authorization details getter with sensible defaults.
func NewGetAccountAuthDetailsV2(profile string) *GetAccountAuthDetailsV2 {
	return &GetAccountAuthDetailsV2{
		Profile: profile,
		Region:  "us-east-1", // IAM is a global service
	}
}

// Run retrieves account authorization details.
// Returns the complete authorization details from AWS SDK.
func (g *GetAccountAuthDetailsV2) Run(ctx context.Context) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	// 1. Initialize AWS config using helpers.GetAWSCfg with defaultCacheOptions()
	opts := g.defaultCacheOptions()
	config, err := helpers.GetAWSCfg(g.Region, g.Profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// 2. Create IAM client with iam.NewFromConfig(config)
	iamClient := iam.NewFromConfig(config)

	// 3. Use iam.NewGetAccountAuthorizationDetailsPaginator with MaxItems: 1000
	maxItems := int32(1000)
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(iamClient, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	// 4. Paginate and accumulate results
	var completeOutput *iam.GetAccountAuthorizationDetailsOutput

	for paginator.HasMorePages() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve authorization details page: %w", err)
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

	// 5. Return complete output
	slog.Info("Retrieved account authorization details", "profile", g.Profile)
	return completeOutput, nil
}

// RunWithDecodedPolicies retrieves authorization details and decodes URL-encoded policy documents.
// This matches the output format of the V1 Janus implementation.
func (g *GetAccountAuthDetailsV2) RunWithDecodedPolicies(ctx context.Context) (interface{}, error) {
	// 1. Call Run(ctx)
	output, err := g.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to run authorization details retrieval: %w", err)
	}

	// 2. Marshal to JSON
	rawData, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorization details: %w", err)
	}

	// 3. Call replaceURLEncodedPoliciesV2
	decodedData, err := replaceURLEncodedPoliciesV2(rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode URL-encoded policies: %w", err)
	}

	// 4. Unmarshal back to interface{}
	var result interface{}
	if err := json.Unmarshal(decodedData, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decoded data: %w", err)
	}

	// 5. Return result
	return result, nil
}

// defaultCacheOptions returns the default cache options required by GetAWSCfg.
func (g *GetAccountAuthDetailsV2) defaultCacheOptions() []*types.Option {
	return []*types.Option{
		&options.AwsCacheDirOpt,
		&options.AwsCacheExtOpt,
		&options.AwsCacheTTLOpt,
		&options.AwsDisableCacheOpt,
		&options.AwsCacheErrorRespOpt,
		&options.AwsCacheErrorRespTypesOpt,
	}
}

// replaceURLEncodedPoliciesV2 decodes URL-encoded JSON policy strings in AWS IAM policy documents.
func replaceURLEncodedPoliciesV2(data []byte) ([]byte, error) {
	// 1. Unmarshal to interface{}
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// 2. Call decodeURLEncodedValues recursively
	jsonData = decodeURLEncodedValues(jsonData)

	// 3. Marshal back to []byte
	result, err := json.Marshal(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decoded data: %w", err)
	}

	return result, nil
}

// decodeURLEncodedValues recursively decodes URL-encoded policy strings.
func decodeURLEncodedValues(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Handle map[string]interface{}: for each string value starting with "%7B", decode and parse as JSON
		for k, value := range val {
			if str, ok := value.(string); ok && strings.HasPrefix(str, "%7B") {
				// Attempt to decode URL-encoded string
				decoded, err := url.QueryUnescape(str)
				if err == nil {
					// Try to parse as JSON
					var policy interface{}
					if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
						val[k] = policy
						continue
					}
				}
			}
			// Recursively process non-policy values
			val[k] = decodeURLEncodedValues(value)
		}
		return val

	case []interface{}:
		// Handle []interface{}: recursively process each element
		for i, item := range val {
			val[i] = decodeURLEncodedValues(item)
		}
		return val

	default:
		// Default: return unchanged
		return v
	}
}
