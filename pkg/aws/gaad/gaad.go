package gaad

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/store"
	iampkg "github.com/praetorian-inc/aurelian/pkg/types"
	"net/url"
	"strings"
)

// GAAD wraps the collection of AWS IAM Account Authorization Details.
type GAAD struct {
	opts         plugin.AWSReconBase
	accountID    string
	iamPaginator *iam.GetAccountAuthorizationDetailsPaginator
}

// New creates a new GAAD instance.
func New(opts plugin.AWSReconBase) *GAAD {
	return &GAAD{opts: opts}
}

// Get collects all IAM users, roles, groups,
// and policies for the AWS account.
func (g *GAAD) Get() (*iampkg.AuthorizationAccountDetails, error) {
	ctx := context.Background()

	if err := g.initializeGAADClient(); err != nil {
		return nil, err
	}

	gaadData := &iampkg.AuthorizationAccountDetails{
		AccountID: g.accountID,
		Users:     store.NewMap[iampkg.UserDetail](),
		Groups:    store.NewMap[iampkg.GroupDetail](),
		Roles:     store.NewMap[iampkg.RoleDetail](),
		Policies:  store.NewMap[iampkg.ManagedPolicyDetail](),
	}

	paginator := ratelimit.NewPaginator()
	err := paginator.Paginate(func() (bool, error) {
		if !g.iamPaginator.HasMorePages() {
			return false, nil
		}

		page, err := g.iamPaginator.NextPage(ctx)
		if err != nil {
			return false, err
		}

		if err := convertSDKItems(page.UserDetailList, gaadData.Users, func(u iampkg.UserDetail) string { return u.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.GroupDetailList, gaadData.Groups, func(g iampkg.GroupDetail) string { return g.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.RoleDetailList, gaadData.Roles, func(r iampkg.RoleDetail) string { return r.Arn }); err != nil {
			return false, err
		}
		if err := convertSDKItems(page.Policies, gaadData.Policies, func(p iampkg.ManagedPolicyDetail) string { return p.Arn }); err != nil {
			return false, err
		}

		return g.iamPaginator.HasMorePages(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization details: %w", err)
	}

	return gaadData, nil
}

// initializeGAADClient sets up the AWS config, resolves the account ID,
// and creates the IAM GAAD paginator.
func (g *GAAD) initializeGAADClient() error {
	// IAM is a global service - always use us-east-1
	region := "us-east-1"

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    g.opts.Profile,
		ProfileDir: g.opts.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("failed to get account ID: %w", err)
	}
	g.accountID = accountID

	iamClient := iam.NewFromConfig(awsCfg)
	maxItems := int32(1000)
	g.iamPaginator = iam.NewGetAccountAuthorizationDetailsPaginator(iamClient, &iam.GetAccountAuthorizationDetailsInput{
		MaxItems: &maxItems,
	})

	return nil
}

// convertSDKItems converts a slice of AWS SDK types into internal types and stores
// them in the destination cache, keyed by ARN. The getArn function extracts the
// map key from each converted item.
func convertSDKItems[From any, To any](source []From, dest store.Map[To], getArn func(To) string) error {
	for _, item := range source {
		converted, err := convertOne[From, To](item)
		if err != nil {
			return err
		}
		dest.Set(getArn(converted), converted)
	}
	return nil
}

// convertOne marshals an AWS SDK type to JSON, URL-decodes any embedded policy
// documents, and unmarshals into the corresponding internal type.
func convertOne[From any, To any](src From) (To, error) {
	var zero To
	data, err := json.Marshal(src)
	if strings.Contains(string(data), "michael.jordan") {
		fmt.Println("foo")
	}
	if err != nil {
		return zero, fmt.Errorf("marshaling: %w", err)
	}
	data, err = decodeURLEncodedPolicies(data)
	if err != nil {
		return zero, fmt.Errorf("decoding policies: %w", err)
	}
	var dst To
	if err := json.Unmarshal(data, &dst); err != nil {
		return zero, fmt.Errorf("unmarshaling: %w", err)
	}
	return dst, nil
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
