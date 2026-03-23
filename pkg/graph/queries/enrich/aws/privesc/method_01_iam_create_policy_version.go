package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method01IAMCreatePolicyVersion is a Go-backed version of:
// enrich/aws/privesc/method_01_iam_create_policy_version.yaml
type Method01IAMCreatePolicyVersion struct{}

func NewMethod01IAMCreatePolicyVersion() AWSPrivesc { return &Method01IAMCreatePolicyVersion{} }

func (m *Method01IAMCreatePolicyVersion) ID() string {
	return "aws/enrich/privesc/method_01"
}

func (m *Method01IAMCreatePolicyVersion) Name() string {
	return "Method01 IAM CreatePolicyVersion"
}

func (m *Method01IAMCreatePolicyVersion) Description() string {
	return "Detects principals with iam:CreatePolicyVersion permission that can modify managed policies."
}

func (m *Method01IAMCreatePolicyVersion) Severity() string { return "high" }

func (m *Method01IAMCreatePolicyVersion) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:CreatePolicyVersion"),
		dsl.ManagedPolicy(),
	)
}
