package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method04IAMCreateLoginProfile is a Go-backed version of:
// enrich/aws/privesc/method_04_iam_create_login_profile.yaml
type Method04IAMCreateLoginProfile struct{}

func NewMethod04IAMCreateLoginProfile() AWSPrivesc { return &Method04IAMCreateLoginProfile{} }

func (m *Method04IAMCreateLoginProfile) ID() string {
	return "aws/enrich/privesc/method_04"
}

func (m *Method04IAMCreateLoginProfile) Name() string {
	return "Method04 IAM CreateLoginProfile"
}

func (m *Method04IAMCreateLoginProfile) Description() string {
	return "Detects principals with iam:CreateLoginProfile permission that can create console passwords for other IAM users."
}

func (m *Method04IAMCreateLoginProfile) Severity() string { return "high" }

func (m *Method04IAMCreateLoginProfile) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:CreateLoginProfile"),
		dsl.Principal(),
	)
}
