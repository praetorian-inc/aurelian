// Package resourcetypes defines the canonical list of AWS resource types used
// by list-all and other Aurelian modules.
//
// GetAll() returns the union of three checked-in sources:
//   - baseline:        types we want list-all to enumerate even if no consumer
//     module currently declares them (general inventory).
//   - consumer modules: every registered AWS module's SupportedResourceTypes().
//   - minus exclusions: types that must never be enumerated even when declared.
//
// The union is computed once per process via sync.Once on first call to
// GetAll(). See union.go for the computation; exclusions.go for the subtraction
// list.
//
// Cache lifecycle: the union cache is process-lifetime and is NOT invalidated
// when plugin.ResetRegistry() is called. Do not call GetAll, IsValid, or
// Validate from a package init() function — if invoked before all module
// init() functions have registered, the cached union will be permanently
// incomplete. Tests that need a fresh union should call ResetForTest (defined
// in export_test.go).
package resourcetypes

import "fmt"

// baseline holds resource types list-all should enumerate even when no
// consumer module declares them. Used for "general inventory" coverage so that
// list-all behavior does not shrink to only-what-modules-consume.
//
// Adding to baseline: add types you want listed by default (network primitives,
// IAM, security inventory, etc.). Types declared by a consumer module's
// SupportedResourceTypes() do NOT need to be added — they are auto-included.
var baseline = []string{
	"AWS::ApiGateway::RestApi",
	"AWS::ApiGatewayV2::Api",
	"AWS::AutoScaling::AutoScalingGroup",
	"AWS::CloudWatch::Alarm",
	"AWS::DynamoDB::Table",
	"AWS::EC2::SecurityGroup",
	"AWS::EC2::Subnet",
	"AWS::EC2::VPC",
	"AWS::EC2::Volume",
	"AWS::ECS::Cluster",
	"AWS::ECS::Service",
	"AWS::EKS::Cluster",
	"AWS::ElasticLoadBalancingV2::LoadBalancer",
	"AWS::IAM::Policy",
	"AWS::IAM::Role",
	"AWS::IAM::User",
	"AWS::KMS::Key",
	"AWS::RDS::DBCluster",
	"AWS::SecretsManager::Secret",
}

// summary is the curated subset for fast scans. Hand-curated UX choice; not
// derived. Must remain a subset of GetAll() (asserted by TestSummary_SubsetOfGetAll).
var summary = []string{
	"AWS::DynamoDB::Table",
	"AWS::EC2::Instance",
	"AWS::ECS::Cluster",
	"AWS::EKS::Cluster",
	"AWS::IAM::Role",
	"AWS::IAM::User",
	"AWS::Lambda::Function",
	"AWS::RDS::DBInstance",
	"AWS::S3::Bucket",
	"AWS::SNS::Topic",
	"AWS::SQS::Queue",
}

// GetAll returns the runtime-computed union of supported resource types.
// The returned slice is a defensive copy; callers may mutate it freely.
func GetAll() []string {
	ensureComputed()
	out := make([]string, len(allCache))
	copy(out, allCache)
	return out
}

// GetSummary returns the key resource types used for summary scans.
func GetSummary() []string {
	out := make([]string, len(summary))
	copy(out, summary)
	return out
}

// IsValid reports whether rt is a known resource type (i.e., in GetAll()).
func IsValid(rt string) bool {
	ensureComputed()
	return allSet[rt]
}

// Validate returns an error if any type in the slice is not a known resource type.
func Validate(types []string) error {
	ensureComputed()
	for _, rt := range types {
		if !allSet[rt] {
			return fmt.Errorf("unsupported resource type: %s", rt)
		}
	}
	return nil
}
