package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// GetAccountAuthorizationDetails retrieves all IAM authorization details
// and returns them as a typed Gaad struct with URL-decoded policies
func GetAccountAuthorizationDetails(ctx context.Context, opts plugin.AWSReconBase) (*types.Gaad, string, error) {
	// IAM is a global service - always use us-east-1
	region := "us-east-1"

	// Create AWS config for us-east-1
	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create AWS config: %w", err)
	}

	// Get account ID via STS
	accountID, err := awshelpers.GetAccountId(awsCfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get account ID: %w", err)
	}

	// Create IAM client and paginator
	iamClient := iam.NewFromConfig(awsCfg)
	maxItems := int32(1000)
	paginator := iam.NewGetAccountAuthorizationDetailsPaginator(iamClient, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	// Accumulate results across pages
	var userDetailList []iamtypes.UserDetail
	var groupDetailList []iamtypes.GroupDetail
	var roleDetailList []iamtypes.RoleDetail
	var policies []iamtypes.ManagedPolicyDetail

	pageNum := 0
	for paginator.HasMorePages() {
		pageNum++
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("error retrieving authorization details page %d: %w", pageNum, err)
		}

		userDetailList = append(userDetailList, page.UserDetailList...)
		groupDetailList = append(groupDetailList, page.GroupDetailList...)
		roleDetailList = append(roleDetailList, page.RoleDetailList...)
		policies = append(policies, page.Policies...)
	}

	// Convert AWS SDK types to our enhanced Gaad types
	gaad, err := convertToGaad(userDetailList, groupDetailList, roleDetailList, policies)
	if err != nil {
		return nil, "", fmt.Errorf("error converting to Gaad types: %w", err)
	}

	return gaad, accountID, nil
}

// convertToGaad converts AWS SDK types to our enhanced Gaad struct with URL-decoded policies
func convertToGaad(
	users []iamtypes.UserDetail,
	groups []iamtypes.GroupDetail,
	roles []iamtypes.RoleDetail,
	policies []iamtypes.ManagedPolicyDetail,
) (*types.Gaad, error) {
	// Marshal AWS SDK types to JSON
	usersJSON, err := json.Marshal(users)
	if err != nil {
		return nil, fmt.Errorf("error marshaling users: %w", err)
	}

	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return nil, fmt.Errorf("error marshaling groups: %w", err)
	}

	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return nil, fmt.Errorf("error marshaling roles: %w", err)
	}

	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		return nil, fmt.Errorf("error marshaling policies: %w", err)
	}

	// URL-decode policy documents
	usersJSON, err = decodeURLEncodedPolicies(usersJSON)
	if err != nil {
		return nil, fmt.Errorf("error decoding user policies: %w", err)
	}

	groupsJSON, err = decodeURLEncodedPolicies(groupsJSON)
	if err != nil {
		return nil, fmt.Errorf("error decoding group policies: %w", err)
	}

	rolesJSON, err = decodeURLEncodedPolicies(rolesJSON)
	if err != nil {
		return nil, fmt.Errorf("error decoding role policies: %w", err)
	}

	policiesJSON, err = decodeURLEncodedPolicies(policiesJSON)
	if err != nil {
		return nil, fmt.Errorf("error decoding managed policies: %w", err)
	}

	// Unmarshal into our enhanced types
	var userDL []types.UserDL
	if err := json.Unmarshal(usersJSON, &userDL); err != nil {
		return nil, fmt.Errorf("error unmarshaling users: %w", err)
	}

	var groupDL []types.GroupDL
	if err := json.Unmarshal(groupsJSON, &groupDL); err != nil {
		return nil, fmt.Errorf("error unmarshaling groups: %w", err)
	}

	var roleDL []types.RoleDL
	if err := json.Unmarshal(rolesJSON, &roleDL); err != nil {
		return nil, fmt.Errorf("error unmarshaling roles: %w", err)
	}

	var policiesDL []types.PoliciesDL
	if err := json.Unmarshal(policiesJSON, &policiesDL); err != nil {
		return nil, fmt.Errorf("error unmarshaling policies: %w", err)
	}

	return &types.Gaad{
		UserDetailList:  userDL,
		GroupDetailList: groupDL,
		RoleDetailList:  roleDL,
		Policies:        policiesDL,
	}, nil
}

// decodeURLEncodedPolicies recursively finds and decodes URL-encoded policy documents
func decodeURLEncodedPolicies(data []byte) ([]byte, error) {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data: %w", err)
	}

	// Recursively decode URL-encoded strings
	var decode func(interface{}) interface{}
	decode = func(v interface{}) interface{} {
		switch val := v.(type) {
		case map[string]interface{}:
			for k, v := range val {
				if str, ok := v.(string); ok {
					// Check if string is URL-encoded (starts with %7B = "{")
					if len(str) > 0 && str[0] == '%' {
						decoded, err := url.QueryUnescape(str)
						if err == nil {
							// Try parsing as JSON policy
							var policy interface{}
							if err := json.Unmarshal([]byte(decoded), &policy); err == nil {
								val[k] = policy
								continue
							}
						}
					}
				}
				val[k] = decode(v)
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
