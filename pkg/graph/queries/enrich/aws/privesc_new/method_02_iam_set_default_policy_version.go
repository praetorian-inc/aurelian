package privescnew

// Method02IAMSetDefaultPolicyVersion is a Go-backed version of:
// enrich/aws/privesc/method_02_iam_set_default_policy_version.yaml
type Method02IAMSetDefaultPolicyVersion struct{}

func NewMethod02IAMSetDefaultPolicyVersion() AWSPrivesc {
	return &Method02IAMSetDefaultPolicyVersion{}
}

func (m *Method02IAMSetDefaultPolicyVersion) ID() string {
	return "aws/enrich/privesc/method_02"
}

func (m *Method02IAMSetDefaultPolicyVersion) Name() string {
	return "IAM SetDefaultPolicyVersion Privilege Escalation"
}

func (m *Method02IAMSetDefaultPolicyVersion) Description() string {
	return "Detects principals with iam:SetDefaultPolicyVersion permission that can activate previous policy versions to gain elevated access."
}

func (m *Method02IAMSetDefaultPolicyVersion) Severity() string { return "high" }

func (m *Method02IAMSetDefaultPolicyVersion) Query() Query {
	return Match(
		Principal(),
		HasPermission("iam:SetDefaultPolicyVersion"),
		ManagedPolicy(),
	)
}
