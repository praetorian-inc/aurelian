package gaad

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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

// GetAccountAuthorizationDetails collects all IAM users, roles, groups,
// and policies for the AWS account.
func (g *GAAD) GetAccountAuthorizationDetails() error {
	ctx := context.Background()

	if err := g.initializeIAMClient(); err != nil {
		return err
	}

	var userDetailList []iamtypes.UserDetail
	var groupDetailList []iamtypes.GroupDetail
	var roleDetailList []iamtypes.RoleDetail
	var policies []iamtypes.ManagedPolicyDetail

	pageNum := 0
	for g.iamPaginator.HasMorePages() {
		pageNum++
		page, err := g.iamPaginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("error retrieving authorization details page %d: %w", pageNum, err)
		}

		userDetailList = append(userDetailList, page.UserDetailList...)
		groupDetailList = append(groupDetailList, page.GroupDetailList...)
		roleDetailList = append(roleDetailList, page.RoleDetailList...)
		policies = append(policies, page.Policies...)
	}

	gaad, err := convertToGaad(userDetailList, groupDetailList, roleDetailList, policies)
	if err != nil {
		return fmt.Errorf("error converting to Gaad types: %w", err)
	}
	_ = gaad

	return nil
}

// initializeIAMClient sets up the AWS config, resolves the account ID,
// and creates the IAM paginator.
func (g *GAAD) initializeIAMClient() error {
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
