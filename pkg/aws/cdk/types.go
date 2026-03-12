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
	// OnRisk is called for each discovered risk as regions complete.
	// It must be safe for concurrent use from multiple goroutines.
	OnRisk func(output.Risk)
}

// ScanResult contains metadata from a CDK bucket takeover scan.
// Risks are streamed via the OnRisk callback in ScanOptions as regions complete.
type ScanResult struct {
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
