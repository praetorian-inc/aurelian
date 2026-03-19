package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method08IAMAttachRolePolicy is a Go-backed version of:
// enrich/aws/privesc/method_08_iam_attach_role_policy.yaml
type Method08IAMAttachRolePolicy struct{}

func NewMethod08IAMAttachRolePolicy() AWSPrivesc { return &Method08IAMAttachRolePolicy{} }

func (m *Method08IAMAttachRolePolicy) ID() string          { return "aws/enrich/privesc/method_08" }
func (m *Method08IAMAttachRolePolicy) Name() string        { return "Method08 IAM AttachRolePolicy" }
func (m *Method08IAMAttachRolePolicy) Description() string {
	return "Detects principals with iam:AttachRolePolicy permission that can attach managed policies to IAM roles."
}
func (m *Method08IAMAttachRolePolicy) Severity() string { return "high" }

func (m *Method08IAMAttachRolePolicy) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:AttachRolePolicy"),
		dsl.Principal(),
	)
}
