package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method09IAMPutUserPolicy is a Go-backed version of:
// enrich/aws/privesc/method_09_iam_put_user_policy.yaml
type Method09IAMPutUserPolicy struct{}

func NewMethod09IAMPutUserPolicy() AWSPrivesc { return &Method09IAMPutUserPolicy{} }

func (m *Method09IAMPutUserPolicy) ID() string          { return "aws/enrich/privesc/method_09" }
func (m *Method09IAMPutUserPolicy) Name() string        { return "Method09 IAM PutUserPolicy" }
func (m *Method09IAMPutUserPolicy) Description() string {
	return "Detects principals with iam:PutUserPolicy permission that can add or modify inline policies on IAM users."
}
func (m *Method09IAMPutUserPolicy) Severity() string { return "high" }

func (m *Method09IAMPutUserPolicy) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:PutUserPolicy"),
		dsl.Principal(),
	)
}
