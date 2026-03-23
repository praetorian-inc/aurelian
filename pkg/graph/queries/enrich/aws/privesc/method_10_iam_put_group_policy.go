package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method10IAMPutGroupPolicy is a Go-backed version of:
// enrich/aws/privesc/method_10_iam_put_group_policy.yaml
type Method10IAMPutGroupPolicy struct{}

func NewMethod10IAMPutGroupPolicy() AWSPrivesc { return &Method10IAMPutGroupPolicy{} }

func (m *Method10IAMPutGroupPolicy) ID() string          { return "aws/enrich/privesc/method_10" }
func (m *Method10IAMPutGroupPolicy) Name() string        { return "Method10 IAM PutGroupPolicy" }
func (m *Method10IAMPutGroupPolicy) Description() string {
	return "Detects principals with iam:PutGroupPolicy permission that can add or modify inline policies on IAM groups."
}
func (m *Method10IAMPutGroupPolicy) Severity() string { return "high" }

func (m *Method10IAMPutGroupPolicy) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:PutGroupPolicy"),
		dsl.Principal(),
	)
}
