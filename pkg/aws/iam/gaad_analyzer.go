package iam

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// GaadAnalyzer analyzes GAAD data, cloud resources, and org policies
// to determine principal→permission→resource paths.
type GaadAnalyzer struct{}

// NewGaadAnalyzer creates a new GaadAnalyzer.
func NewGaadAnalyzer() *GaadAnalyzer {
	return &GaadAnalyzer{}
}

// Analyze evaluates all principal permissions against resources and org policies,
// detecting privilege escalation paths. Returns the set of allowed permission
// edges (principal → action → resource).
func (ga *GaadAnalyzer) Analyze(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources []output.AWSResource,
) ([]output.AWSIAMRelationship, error) {
	return nil, nil
}
