package methods

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method03IAMCreateAccessKey is a Go-backed version of:
// enrich/aws/privesc/method_03_iam_create_access_key.yaml
type Method03IAMCreateAccessKey struct{}

func NewMethod03IAMCreateAccessKey() AWSPrivesc { return &Method03IAMCreateAccessKey{} }

func (m *Method03IAMCreateAccessKey) ID() string {
	return "aws/enrich/privesc/method_03"
}

func (m *Method03IAMCreateAccessKey) Name() string {
	return "IAM CreateAccessKey"
}

func (m *Method03IAMCreateAccessKey) Description() string {
	return "Detects principals with iam:CreateAccessKey permission that can create access keys for other users."
}

func (m *Method03IAMCreateAccessKey) Severity() string { return "high" }

func (m *Method03IAMCreateAccessKey) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:CreateAccessKey"),
		dsl.Principal(),
	)
}
