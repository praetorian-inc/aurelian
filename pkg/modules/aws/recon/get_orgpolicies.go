package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	//AwsOrganizationPolicies.New().Initialize()
	registry.Register("aws", "recon", "org-policies", *AwsOrganizationPolicies)
}

var AwsOrganizationPolicies = chain.NewModule(
	cfg.NewMetadata(
		"AWS Get Organization Policies",
		"Get SCPs and RCPs of an AWS organization and the targets to which they are attached.",
	).WithProperties(map[string]any{
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListRoots.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListOrganizationalUnitsForParent.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccountsForParent.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribePolicy.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListTargetsForPolicy.html",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/organizations#Client.ListRoots",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/organizations#Client.ListOrganizationalUnitsForParent",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/organizations#Client.ListAccountsForParent",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/organizations#Client.DescribePolicy",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/organizations#Client.ListTargetsForPolicy",
		},
	}).WithChainInputParam(
		options.AwsResourceType().Name()),
).WithLinks(
	orgpolicies.NewAWSOrganizationPolicies,
).WithOutputters(
	output.NewJSONOutputter,
)
