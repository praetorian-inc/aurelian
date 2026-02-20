package gaad

import (
	"context"
	"fmt"
	iampkg "github.com/praetorian-inc/aurelian/pkg/types"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
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

	var iamUserDLs []iamtypes.UserDetail
	var iamGroupDLs []iamtypes.GroupDetail
	var iamRoleDLs []iamtypes.RoleDetail
	var iamPolicies []iamtypes.ManagedPolicyDetail

	paginator := ratelimit.NewPaginator()
	err := paginator.Paginate(func() (bool, error) {
		if !g.iamPaginator.HasMorePages() {
			return false, nil
		}

		page, err := g.iamPaginator.NextPage(ctx)
		if err != nil {
			return false, err
		}

		iamUserDLs = append(iamUserDLs, page.UserDetailList...)
		iamGroupDLs = append(iamGroupDLs, page.GroupDetailList...)
		iamRoleDLs = append(iamRoleDLs, page.RoleDetailList...)
		iamPolicies = append(iamPolicies, page.Policies...)

		return g.iamPaginator.HasMorePages(), nil
	})
	if err != nil {
		return nil, fmt.Errorf("error retrieving authorization details: %w", err)
	}

	// Convert AWS SDK types to our internal types
	userDLs, groupDLs, roleDLs, policies, err := convertToInternalTypes(iamUserDLs, iamGroupDLs, iamRoleDLs, iamPolicies)
	if err != nil {
		return nil, fmt.Errorf("error converting to internal types: %w", err)
	}

	return &iampkg.AuthorizationAccountDetails{
		AccountID:       g.accountID,
		UserDetailList:  userDLs,
		GroupDetailList: groupDLs,
		RoleDetailList:  roleDLs,
		Policies:        policies,
	}, nil
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
