package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method07IAMAttachGroupPolicy is a Go-backed version of:
// enrich/aws/privesc/method_07_iam_attach_group_policy.yaml
type Method07IAMAttachGroupPolicy struct{}

func NewMethod07IAMAttachGroupPolicy() AWSPrivesc { return &Method07IAMAttachGroupPolicy{} }

func (m *Method07IAMAttachGroupPolicy) ID() string          { return "aws/enrich/privesc/method_07" }
func (m *Method07IAMAttachGroupPolicy) Name() string        { return "Method07 IAM AttachGroupPolicy" }
func (m *Method07IAMAttachGroupPolicy) Description() string {
	return "Detects principals with iam:AttachGroupPolicy permission that can attach managed policies to IAM groups."
}
func (m *Method07IAMAttachGroupPolicy) Severity() string { return "high" }

func (m *Method07IAMAttachGroupPolicy) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:AttachGroupPolicy"),
		dsl.Principal(),
	)
}
