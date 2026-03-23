package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method06IAMAttachUserPolicy is a Go-backed version of:
// enrich/aws/privesc/method_06_iam_attach_user_policy.yaml
type Method06IAMAttachUserPolicy struct{}

func NewMethod06IAMAttachUserPolicy() AWSPrivesc { return &Method06IAMAttachUserPolicy{} }

func (m *Method06IAMAttachUserPolicy) ID() string          { return "aws/enrich/privesc/method_06" }
func (m *Method06IAMAttachUserPolicy) Name() string        { return "Method06 IAM AttachUserPolicy" }
func (m *Method06IAMAttachUserPolicy) Description() string {
	return "Detects principals with iam:AttachUserPolicy permission that can attach managed policies to IAM users."
}
func (m *Method06IAMAttachUserPolicy) Severity() string { return "high" }

func (m *Method06IAMAttachUserPolicy) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:AttachUserPolicy"),
		dsl.Principal(),
	)
}
