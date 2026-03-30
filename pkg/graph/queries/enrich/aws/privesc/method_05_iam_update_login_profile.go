package privesc

import (
	"github.com/praetorian-inc/aurelian/pkg/graph/queries/dsl"
)

// Method05IAMUpdateLoginProfile is a Go-backed version of:
// enrich/aws/privesc/method_05_iam_update_login_profile.yaml
type Method05IAMUpdateLoginProfile struct{}

func NewMethod05IAMUpdateLoginProfile() AWSPrivesc { return &Method05IAMUpdateLoginProfile{} }

func (m *Method05IAMUpdateLoginProfile) ID() string          { return "aws/enrich/privesc/method_05" }
func (m *Method05IAMUpdateLoginProfile) Name() string        { return "Method05 IAM UpdateLoginProfile" }
func (m *Method05IAMUpdateLoginProfile) Description() string {
	return "Detects principals with iam:UpdateLoginProfile permission that can reset console passwords for other IAM users."
}
func (m *Method05IAMUpdateLoginProfile) Severity() string { return "high" }

func (m *Method05IAMUpdateLoginProfile) Query() dsl.Query {
	return dsl.Match(
		dsl.Principal(),
		dsl.HasPermission("iam:UpdateLoginProfile"),
		dsl.Principal(),
	)
}
