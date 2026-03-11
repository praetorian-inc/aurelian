package cdk

import "github.com/praetorian-inc/aurelian/pkg/output"

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

// cdkRoleTypes lists CDK role type suffixes used in bootstrap role naming.
var cdkRoleTypes = []string{
	"file-publishing-role",
	"cfn-exec-role",
	"image-publishing-role",
	"lookup-role",
	"deploy-role",
}
