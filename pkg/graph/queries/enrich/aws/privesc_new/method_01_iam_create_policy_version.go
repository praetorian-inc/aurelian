package privescnew

// AWSPrivesc defines the minimal contract for read-only privilege escalation queries.
type AWSPrivesc interface {
	ID() string
	Name() string
	Description() string
	Severity() string
	Query() Query
}

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

func (m *Method01IAMCreatePolicyVersion) Query() Query {
	return Match(
		Principal(),
		HasPermission("iam:CreatePolicyVersion"),
		ManagedPolicy(),
	)
}
