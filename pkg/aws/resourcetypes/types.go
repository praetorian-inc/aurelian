// Package resourcetypes defines the canonical list of AWS CloudControl resource
// types used across Aurelian modules.
package resourcetypes

import "fmt"

// all is the comprehensive list of CloudControl-supported resource types.
var all = []string{
	"AWS::ApiGateway::RestApi",
	"AWS::ApiGatewayV2::Api",
	"AWS::AutoScaling::AutoScalingGroup",
	"AWS::CloudFormation::Stack",
	"AWS::CloudWatch::Alarm",
	"AWS::DynamoDB::Table",
	"AWS::EC2::Instance",
	"AWS::EC2::SecurityGroup",
	"AWS::EC2::Subnet",
	"AWS::EC2::VPC",
	"AWS::EC2::Volume",
	"AWS::ECS::Cluster",
	"AWS::ECS::Service",
	"AWS::ECS::TaskDefinition",
	"AWS::EKS::Cluster",
	"AWS::ElasticLoadBalancingV2::LoadBalancer",
	"AWS::IAM::Policy",
	"AWS::IAM::Role",
	"AWS::IAM::User",
	"AWS::KMS::Key",
	"AWS::Lambda::Function",
	"AWS::Logs::LogGroup",
	"AWS::RDS::DBCluster",
	"AWS::RDS::DBInstance",
	"AWS::S3::Bucket",
	"AWS::SNS::Topic",
	"AWS::SQS::Queue",
	"AWS::SSM::Document",
	"AWS::SecretsManager::Secret",
	"AWS::StepFunctions::StateMachine",
}

// summary is the subset of key resource types used for quick scans.
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

// allSet is a precomputed lookup map for O(1) validation.
var allSet map[string]bool

func init() {
	allSet = make(map[string]bool, len(all))
	for _, rt := range all {
		allSet[rt] = true
	}
}

// GetAll returns all CloudControl-supported resource types.
func GetAll() []string {
	out := make([]string, len(all))
	copy(out, all)
	return out
}

// GetSummary returns the key resource types used for summary scans.
func GetSummary() []string {
	out := make([]string, len(summary))
	copy(out, summary)
	return out
}

// IsValid reports whether rt is a known resource type.
func IsValid(rt string) bool {
	return allSet[rt]
}

// Validate returns an error if any type in the slice is not a known resource type.
func Validate(types []string) error {
	for _, rt := range types {
		if !allSet[rt] {
			return fmt.Errorf("unsupported resource type: %s", rt)
		}
	}
	return nil
}
