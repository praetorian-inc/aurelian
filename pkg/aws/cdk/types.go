package cdk

import "github.com/praetorian-inc/aurelian/pkg/output"

// QualifierInfo represents discovered CDK qualifier information.
type QualifierInfo struct {
	Qualifiers []string
	AccountID  string
	Regions    []string
}

// RoleInfo represents a detected CDK bootstrap role.
type RoleInfo struct {
	RoleName      string
	RoleArn       string
	Qualifier     string
	Region        string
	AccountID     string
	CreationDate  string
	RoleType      string
	BucketName    string
	TrustPolicy   string
	AssumeRoleDoc string
}

// BootstrapInfo represents CDK bootstrap version information.
type BootstrapInfo struct {
	AccountID    string
	Region       string
	Qualifier    string
	Version      int
	HasVersion   bool
	AccessDenied bool
}

// ScanOptions configures the CDK bucket takeover scan.
type ScanOptions struct {
	Qualifiers  []string
	Regions     []string
	Concurrency int
	Profile     string
	ProfileDir  string
}

// ScanResult contains all findings from a CDK bucket takeover scan.
type ScanResult struct {
	Risks     []output.Risk
	AccountID string
	Roles     []RoleInfo
}

// cdkRoleTypes maps CDK role type suffixes to display names.
var cdkRoleTypes = map[string]string{
	"file-publishing-role":  "File Publishing Role",
	"cfn-exec-role":         "CloudFormation Execution Role",
	"image-publishing-role": "Image Publishing Role",
	"lookup-role":           "Lookup Role",
	"deploy-role":           "Deploy Role",
}
