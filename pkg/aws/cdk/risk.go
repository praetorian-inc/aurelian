package cdk

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// References lists the external write-ups describing the CDK bucket-takeover
// class. Single source of truth for the proof References section.
var References = []string{
	"https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
	"https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
}

// NewBucketTakeoverRisk builds a platform capmodel.Risk for a missing CDK
// staging bucket (potential account takeover via bucket-name claiming).
func NewBucketTakeoverRisk(role RoleInfo) (capmodel.Risk, error) {
	description := fmt.Sprintf("AWS CDK staging S3 bucket '%s' is missing but CDK bootstrap role '%s' exists in region %s. This allows potential account takeover through bucket name claiming and CloudFormation template injection.", role.BucketName, role.RoleName, role.Region)
	impact := "Attackers can claim the predictable CDK staging bucket name and inject malicious CloudFormation templates, potentially creating admin roles for account takeover."
	recommendation := fmt.Sprintf("Re-run 'cdk bootstrap --qualifier %s' in region %s or upgrade to CDK v2.149.0+ and re-bootstrap to apply security patches.", role.Qualifier, role.Region)

	proof, err := json.Marshal(buildTakeoverProof(role, description, impact, recommendation))
	if err != nil {
		return capmodel.Risk{}, err
	}
	return newCdkRisk(role, "cdk-bucket-takeover", output.RiskSeverityHigh, proof), nil
}

// NewBucketHijackedRisk builds a platform capmodel.Risk for a CDK staging
// bucket that appears to be owned by a different account.
func NewBucketHijackedRisk(role RoleInfo) (capmodel.Risk, error) {
	description := fmt.Sprintf("AWS CDK staging S3 bucket '%s' appears to be owned by a different account, but CDK role '%s' still exists. This indicates a potential bucket takeover.", role.BucketName, role.RoleName)
	impact := "CDK deployments may fail or push sensitive CloudFormation templates to an attacker-controlled bucket."
	recommendation := fmt.Sprintf("Verify bucket ownership and re-run 'cdk bootstrap --qualifier <new-qualifier>' with a unique qualifier in region %s.", role.Region)

	proof, err := json.Marshal(buildTakeoverProof(role, description, impact, recommendation))
	if err != nil {
		return capmodel.Risk{}, err
	}
	return newCdkRisk(role, "cdk-bucket-hijacked", output.RiskSeverityMedium, proof), nil
}

// NewPolicyRisk builds a platform capmodel.Risk for a CDK FilePublishingRole
// whose S3 permissions lack an aws:ResourceAccount restriction.
func NewPolicyRisk(role RoleInfo) (capmodel.Risk, error) {
	description := fmt.Sprintf("AWS CDK FilePublishingRole '%s' lacks proper account restrictions in S3 permissions. This role can potentially access S3 buckets in other accounts, making it vulnerable to bucket takeover attacks.", role.RoleName)
	impact := "The role may inadvertently access attacker-controlled S3 buckets with the same predictable name, allowing CloudFormation template injection."
	recommendation := fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap' in region %s, or manually add 'aws:ResourceAccount' condition to the role's S3 permissions.", role.Region)

	proof, err := json.Marshal(buildMisconfigurationProof(role, nil, description, impact, recommendation))
	if err != nil {
		return capmodel.Risk{}, err
	}
	return newCdkRisk(role, "cdk-policy-unrestricted", output.RiskSeverityMedium, proof), nil
}

// NewBootstrapRisk builds a platform capmodel.Risk for a missing or outdated
// CDK bootstrap version. A missing version is Medium (cdk-bootstrap-missing);
// an outdated version (< v21) is High (cdk-bootstrap-outdated).
func NewBootstrapRisk(role RoleInfo, info BootstrapInfo) (capmodel.Risk, error) {
	name := "cdk-bootstrap-missing"
	severity := output.RiskSeverityMedium
	description := fmt.Sprintf(
		"AWS CDK bootstrap parameter '/cdk-bootstrap/%s/version' not found in region %s. "+
			"CDK was never properly bootstrapped or bootstrap artifacts were deleted.",
		role.Qualifier, role.Region,
	)
	if info.HasVersion {
		name = "cdk-bootstrap-outdated"
		severity = output.RiskSeverityHigh
		description = fmt.Sprintf(
			"AWS CDK bootstrap version %d is outdated in region %s (< v21). "+
				"Versions before v21 lack security protections against S3 bucket takeover attacks.",
			info.Version, role.Region,
		)
	}

	impact := "CDK deployments may be vulnerable to S3 bucket takeover attacks, potentially allowing attackers to inject malicious CloudFormation templates and gain account access."
	recommendation := fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap --qualifier %s' in region %s to apply security patches.", role.Qualifier, role.Region)

	bootstrapVersion := "Missing"
	if info.HasVersion {
		bootstrapVersion = fmt.Sprintf("%d", info.Version)
	}
	extra := []capmodel.ProofKeyValueRow{{Key: "Bootstrap Version", Value: bootstrapVersion}}

	proof, err := json.Marshal(buildMisconfigurationProof(role, extra, description, impact, recommendation))
	if err != nil {
		return capmodel.Risk{}, err
	}
	return newCdkRisk(role, name, severity, proof), nil
}

// newCdkRisk assembles the common capmodel.Risk shell shared by every CDK
// finding. TargetName preserves the legacy Target.ResourceID (account root ARN).
func newCdkRisk(role RoleInfo, name string, severity output.RiskSeverity, proof []byte) capmodel.Risk {
	return capmodel.Risk{
		TargetName: fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID),
		Name:       name,
		Source:     "aurelian",
		Status:     severityToStatus(severity),
		Proof:      proof,
		// TODO(LAB-3740): populate a typed capmodel asset (e.g. capmodel.AwsResource
		// for the account root) once Aurelian emits the SDK `_type` envelope and
		// Guard's ingest consumes Risk.Target. Inert until then — Guard's
		// convertRisk falls back to a bare Asset without a `_type` discriminator.
		Target: nil,
	}
}

// buildTakeoverProof assembles the proof for the bucket-takeover risk class.
// The bucket-takeover findings carry no risk-specific CDK Details rows.
func buildTakeoverProof(role RoleInfo, description, impact, recommendation string) capmodel.Proof {
	return buildMisconfigurationProof(role, nil, description, impact, recommendation)
}

// buildMisconfigurationProof assembles the proof for the misconfiguration risk
// class (bootstrap / policy). extra rows are appended to the CDK details.
func buildMisconfigurationProof(role RoleInfo, extra []capmodel.ProofKeyValueRow, description, impact, recommendation string) capmodel.Proof {
	return capmodel.Proof{
		Format: "v1.0.0",
		Sections: []capmodel.ProofSection{
			{Title: "Summary", Elements: []capmodel.ProofElement{paragraph(description)}},
			{Title: "CDK Details", Elements: []capmodel.ProofElement{cdkKeyValue(role, extra)}},
			{Title: "Impact", Elements: []capmodel.ProofElement{paragraph(impact)}},
			{Title: "Recommendation", Elements: []capmodel.ProofElement{list([]string{recommendation})}},
			{Title: "References", Elements: []capmodel.ProofElement{referenceList(References)}},
		},
	}
}

// cdkKeyValue carries the context the legacy Target.Properties + Comment held:
// account, region, qualifier, role, and bucket, plus any risk-specific rows.
func cdkKeyValue(role RoleInfo, extra []capmodel.ProofKeyValueRow) capmodel.ProofElement {
	rows := []capmodel.ProofKeyValueRow{
		{Key: "Account ID", Value: role.AccountID, Copyable: true},
		{Key: "Region", Value: role.Region},
		{Key: "Qualifier", Value: role.Qualifier, Copyable: true},
		{Key: "Role Name", Value: role.RoleName, Copyable: true},
		{Key: "Bucket Name", Value: role.BucketName, Copyable: true},
	}
	rows = append(rows, extra...)
	return keyValue(rows)
}

// severityToStatus maps a risk severity to a Chariot triage status code.
func severityToStatus(sev output.RiskSeverity) string {
	switch output.NormalizeSeverity(sev) {
	case output.RiskSeverityCritical:
		return "TC"
	case output.RiskSeverityHigh:
		return "TH"
	case output.RiskSeverityMedium:
		return "TM"
	case output.RiskSeverityLow:
		return "TL"
	default:
		return "TI"
	}
}

func paragraph(text string) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "paragraph", Paragraph: &capmodel.ProofParagraph{Text: text}}
}

func keyValue(rows []capmodel.ProofKeyValueRow) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "key_value", KeyValue: &capmodel.ProofKeyValue{Rows: rows}}
}

func list(items []string) capmodel.ProofElement {
	listItems := make([]capmodel.ProofListItem, 0, len(items))
	for _, item := range items {
		listItems = append(listItems, capmodel.ProofListItem{Label: item})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: listItems}}
}

func referenceList(urls []string) capmodel.ProofElement {
	items := make([]capmodel.ProofListItem, 0, len(urls))
	for _, u := range urls {
		items = append(items, capmodel.ProofListItem{Label: u, Href: u})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: items}}
}
