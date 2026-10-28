// Package escalation defines types and builders for the escalation-solver
// model-v1 JSON format. The escalation-solver is an external Rust tool that
// discovers IAM privilege escalation paths; this package bridges Aurelian's
// internal types to the solver's input contract.
package escalation

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

// Model is the top-level escalation-solver input (model-v1.schema.json).
// It implements model.SingleObjectOutput so the JSON formatter writes it as
// a bare object rather than wrapping in an array.
type Model struct {
	model.BaseAurelianModel `json:"-"`
	Version            string              `json:"version"`
	CollectionCoverage *CollectionCoverage `json:"collection_coverage,omitempty"`
	CollectionErrors   []CollectionError   `json:"collection_errors,omitempty"`
	Accounts           []Account           `json:"accounts,omitempty"`
	Principals         []Principal         `json:"principals"`
	Resources          []Resource          `json:"resources,omitempty"`
	PermissionSource   PermissionSource    `json:"permission_source"`
	ResourcePolicies   []ResourcePolicy    `json:"resource_policies,omitempty"`
	StructuralFacts    []StructuralFact    `json:"structural_facts,omitempty"`
	Goal               Goal                `json:"goal"`
	Config             *SolverConfig       `json:"config,omitempty"`
}

// IsSingleObjectOutput marks Model for bare-object JSON serialization.
func (*Model) IsSingleObjectOutput() {}

// CollectionCoverage flags which data sources were attempted. true = attempted
// (even if zero results found), false/absent = not attempted. Pair with
// CollectionErrors to distinguish "empty account" from "collection failed".
type CollectionCoverage struct {
	IAMGAAD                bool `json:"iam_gaad,omitempty"`
	EC2InstanceProfiles    bool `json:"ec2_instance_profiles,omitempty"`
	LambdaExecutionRoles   bool `json:"lambda_execution_roles,omitempty"`
	ECSTaskRoles           bool `json:"ecs_task_roles,omitempty"`
	CodeBuildServiceRoles  bool `json:"codebuild_service_roles,omitempty"`
	S3BucketPolicies       bool `json:"s3_bucket_policies,omitempty"`
	LambdaResourcePolicies bool `json:"lambda_resource_policies,omitempty"`
	SQSQueuePolicies       bool `json:"sqs_queue_policies,omitempty"`
	KMSKeyPolicies         bool `json:"kms_key_policies,omitempty"`
	SNSTopicPolicies       bool `json:"sns_topic_policies,omitempty"`
}

// CollectionError records a failure during data collection.
type CollectionError struct {
	Source  string `json:"source"`  // data source key (matches collection_coverage keys)
	Error   string `json:"error"`   // error message
	Regions []string `json:"regions,omitempty"` // affected regions, if regional
}

// Account represents an AWS account in scope.
type Account struct {
	ID      string   `json:"id"`
	OrgPath []string `json:"org_path,omitempty"`
}

// PrincipalType is the IAM principal type.
type PrincipalType string

const (
	PrincipalTypeRole  PrincipalType = "role"
	PrincipalTypeUser  PrincipalType = "user"
	PrincipalTypeGroup PrincipalType = "group"
)

// Principal is an IAM principal in the model.
type Principal struct {
	ARN     string        `json:"arn"`
	Account string        `json:"account"`
	Type    PrincipalType `json:"type"`
	IsAdmin bool          `json:"is_admin,omitempty"`
}

// ResourceType is the solver's resource type enum.
type ResourceType string

const (
	ResourceTypeLambdaFunction   ResourceType = "lambda_function"
	ResourceTypeEC2Instance      ResourceType = "ec2_instance"
	ResourceTypeS3Bucket         ResourceType = "s3_bucket"
	ResourceTypeCodeBuildProject ResourceType = "codebuild_project"
	ResourceTypeECSTask          ResourceType = "ecs_task"
	ResourceTypeSQSQueue         ResourceType = "sqs_queue"
	ResourceTypeSNSTopic         ResourceType = "sns_topic"
	ResourceTypeKMSKey           ResourceType = "kms_key"
)

// Resource is a non-IAM resource in the model.
type Resource struct {
	ARN     string       `json:"arn"`
	Type    ResourceType `json:"type"`
	Account string       `json:"account"`
}

// PermissionSourceType identifies how permissions are provided.
type PermissionSourceType string

const (
	PermSourcePolicySummary    PermissionSourceType = "policy_summary"
	PermSourceEvaluatedTriples PermissionSourceType = "evaluated_triples"
	PermSourceExternal         PermissionSourceType = "external"
)

// PermissionSource controls which Solver 1 backend is used.
// JSON encoding depends on the Type field (schema uses oneOf).
type PermissionSource struct {
	Type    PermissionSourceType
	Entries []PolicySummaryEntry // used when Type == PermSourcePolicySummary
	Triples []EvaluatedTriple    // used when Type == PermSourceEvaluatedTriples
	Command string               // used when Type == PermSourceExternal
}

func (ps PermissionSource) MarshalJSON() ([]byte, error) {
	switch ps.Type {
	case PermSourcePolicySummary:
		return json.Marshal(struct {
			Type    PermissionSourceType `json:"type"`
			Entries []PolicySummaryEntry `json:"entries"`
		}{Type: ps.Type, Entries: ps.Entries})
	case PermSourceEvaluatedTriples:
		return json.Marshal(struct {
			Type    PermissionSourceType `json:"type"`
			Entries []EvaluatedTriple    `json:"entries"`
		}{Type: ps.Type, Entries: ps.Triples})
	case PermSourceExternal:
		return json.Marshal(struct {
			Type    PermissionSourceType `json:"type"`
			Command string               `json:"command"`
		}{Type: ps.Type, Command: ps.Command})
	default:
		return json.Marshal(struct {
			Type PermissionSourceType `json:"type"`
		}{Type: ps.Type})
	}
}

func (ps *PermissionSource) UnmarshalJSON(data []byte) error {
	var probe struct {
		Type    PermissionSourceType `json:"type"`
		Command string               `json:"command"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	ps.Type = probe.Type
	ps.Command = probe.Command

	switch probe.Type {
	case PermSourcePolicySummary:
		var wrapper struct {
			Entries []PolicySummaryEntry `json:"entries"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return err
		}
		ps.Entries = wrapper.Entries
	case PermSourceEvaluatedTriples:
		var wrapper struct {
			Entries []EvaluatedTriple `json:"entries"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return err
		}
		ps.Triples = wrapper.Entries
	}

	return nil
}

// PolicySummaryEntry holds the collapsed effective statements for a single principal.
type PolicySummaryEntry struct {
	Principal           string            `json:"principal"`
	EffectiveStatements []PolicyStatement `json:"effective_statements"`
}

// PolicyStatement is a collapsed IAM statement (Allow or Deny) with a single
// action and resource pattern.
type PolicyStatement struct {
	Effect     string      `json:"effect"`
	Action     string      `json:"action"`
	Resource   string      `json:"resource"`
	Source     string      `json:"source,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// EvaluatedTriple is a pre-evaluated permission (principal, action, target).
type EvaluatedTriple struct {
	Principal  string      `json:"principal"`
	Action     string      `json:"action"`
	Target     string      `json:"target"`
	Allowed    bool        `json:"allowed"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition represents an IAM condition key/operator/values tuple.
type Condition struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// StructuralFactType is the type of non-permission relationship.
type StructuralFactType string

const (
	FactLambdaExecutionRole    StructuralFactType = "lambda_execution_role"
	FactInstanceProfile        StructuralFactType = "instance_profile"
	FactTrustRelationship      StructuralFactType = "trust_relationship"
	FactCodeBuildServiceRole   StructuralFactType = "codebuild_service_role"
	FactECSTaskRole            StructuralFactType = "ecs_task_role"
	FactAthenaWorkgroupRole    StructuralFactType = "athena_workgroup_role"
	FactSageMakerSpaceRole     StructuralFactType = "sagemaker_space_role"
	FactGlueEndpointRole       StructuralFactType = "glue_endpoint_role"
	FactSageMakerNotebookRole  StructuralFactType = "sagemaker_notebook_role"
	FactBedrockInterpreterRole StructuralFactType = "bedrock_interpreter_role"
	FactGroupMembership        StructuralFactType = "group_membership"
	FactPolicyAttachment       StructuralFactType = "policy_attachment"
)

// StructuralFact is a non-permission relationship between entities.
type StructuralFact struct {
	Type       StructuralFactType `json:"type"`
	From       string             `json:"from"`
	To         string             `json:"to"`
	Confidence float64            `json:"confidence,omitempty"`
}

// ResourcePolicy holds a resource-based IAM policy attached to a specific resource.
type ResourcePolicy struct {
	Resource string      `json:"resource"`
	Policy   interface{} `json:"policy"`
}

// GoalType is the solver goal type.
type GoalType string

const (
	GoalReachAdmin      GoalType = "reach_admin"
	GoalReachPrincipal  GoalType = "reach_principal"
	GoalReachPermission GoalType = "reach_permission"
)

// Goal defines what the solver should look for.
type Goal struct {
	Type     GoalType `json:"type"`
	Attacker string   `json:"attacker"`
	Target   string   `json:"target,omitempty"`
	Action   string   `json:"action,omitempty"`
	Resource string   `json:"resource,omitempty"`
}

// SolverConfig holds optional solver configuration.
type SolverConfig struct {
	SyntheticResourceSlots int    `json:"synthetic_resource_slots,omitempty"`
	StepSemantics          string `json:"step_semantics,omitempty"`
	TimeoutSeconds         int    `json:"timeout_seconds,omitempty"`
	FindAllPaths           bool   `json:"find_all_paths,omitempty"`
	MaxPaths               int    `json:"max_paths,omitempty"`
}
