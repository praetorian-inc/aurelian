//go:build integration

// Package privescsynth holds the synthetic compute Resource nodes and action edges that the
// privesc integration tests seed for HAS_ROLE methods whose backing service is NOT provisioned
// in the Terraform fixture (App Runner, Glue DevEndpoint, SageMaker notebook, Bedrock AgentCore
// code interpreter), plus the Lambda/EC2 same-node action-edge anchors. It is the single source
// of truth shared by the live recon test (which seeds these alongside real collected resources)
// and the no-AWS snapshot replay test (which re-applies them to captured real data).
//
// It also defines the recon snapshot schema and its capture/load: a snapshot serializes the
// TYPED GAAD detail structs (RoleDetail/UserDetail/GroupDetail/ManagedPolicyDetail) rather than
// the lossy []AWSIAMResource, because NodeFromAWSIAMResource builds rich nodes (trusted_services,
// AssumeRolePolicyDocument, InstanceProfileList, ...) only from the typed OriginalData, which is
// json:"-". Capturing the typed structs lets the replay test rebuild identical rich nodes with
// no AWS access.
package privescsynth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// SnapshotPath is the repo-relative location of the captured recon snapshot, written by the live
// test under AURELIAN_CAPTURE_PRIVESC_SNAPSHOT=1 and read by the replay/freshness tests. A relative
// path is resolved against the repository root (not the test's working directory, which is the
// package dir) by resolvePath, so the snapshot lands in the real testdata directory.
const SnapshotPath = "pkg/modules/aws/recon/testdata/privesc_recon_snapshot.json"

// repoRoot derives the repository root from this source file's location
// (<root>/test/testutil/privescsynth/privescsynth.go → up four levels).
func repoRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// resolvePath turns a repo-relative path into an absolute one rooted at the repository, leaving an
// already-absolute path untouched.
func resolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(repoRoot(), path)
}

// SyntheticResource models a compute Resource node the harness seeds so resource_to_role /
// resource_service_role can build (Resource)-[:HAS_ROLE]->(role) for the HAS_ROLE methods.
//
// The :Resource node carries lowercase `arn` (CloudControl convention) and the property the
// matching enricher reads: resource_to_role keys EC2/Lambda on the TOP-LEVEL `Role` /
// `IamInstanceProfile` / `InstanceProfileList` props; resource_service_role keys the rest on
// the role ARN appearing as a quoted value inside the flattened `properties` JSON string.
type SyntheticResource struct {
	ARN          string
	ResourceType string
	Props        map[string]any // extra top-level node props (Role / InstanceProfileList / properties)
}

// Node builds the :Resource graph node for a synthetic compute resource.
func (s SyntheticResource) Node() *graph.Node {
	props := map[string]any{"arn": s.ARN, "_type": "Resource", "_resourceType": s.ResourceType}
	for k, v := range s.Props {
		props[k] = v
	}
	return &graph.Node{Labels: []string{"Resource", s.ResourceType}, Properties: props, UniqueKey: []string{"arn"}}
}

// SyntheticComputeResources returns the synthetic compute Resource nodes still required for the
// HAS_ROLE methods whose backing service is NOT provisioned in the fixture. The provisioned
// types (CFN Stack/StackSet, CodeBuild Project, Glue Job, ECS TaskDefinition, SFN StateMachine,
// Batch JobDefinition) are collected live and seeded via NodeFromAWSResource, so they have no
// synthetic stand-in here.
//
// Kept synthetic (collector unit-tested; live-fixture provisioning deferred for cost/complexity):
//   - AWS::Lambda::Function: real Lambda IS collected, but this node also anchors the same-node-
//     binding lambda_* action edges. Real Lambda + this node share the same role.
//   - AWS::EC2::Instance: real instance IS collected; this node carries the IamInstanceProfile
//     prop the EC2/SSM HAS_ROLE methods and the ec2_replace_profile EXISTS clause read.
//   - AWS::AppRunner::Service: App Runner needs a runnable container-image source and bills while
//     running. Synthetic stand-in (anchors the apprunner_update_service same-node binding).
//   - AWS::Glue::DevEndpoint: requires a VPC and bills hourly per DPU. Synthetic stand-in.
//   - AWS::SageMaker::NotebookInstance: bills while InService, slow to provision/delete. Synthetic.
//   - AWS::BedrockAgentCore::CodeInterpreter: AgentCore is a preview service with no Terraform
//     provider resource. Synthetic stand-in running the bedrock-agentcore-trusting role.
func SyntheticComputeResources(computeRoleARN, ec2InstanceARN, bedrockExecRoleARN string) []SyntheticResource {
	// resource_service_role matches '"' + role.Arn + '"' inside the flattened properties JSON.
	svcRoleARN := func(rt, resArn, roleARN string) SyntheticResource {
		return SyntheticResource{ARN: resArn, ResourceType: rt,
			Props: map[string]any{"properties": fmt.Sprintf(`{"RoleArn":"%s"}`, roleARN)}}
	}
	svcRole := func(rt, resArn string) SyntheticResource { return svcRoleARN(rt, resArn, computeRoleARN) }
	return []SyntheticResource{
		// Lambda: resource_to_role matches resource.Role = role.Arn.
		{ARN: "arn:aws:lambda:us-east-2:000000000000:function:pf-compute", ResourceType: "AWS::Lambda::Function",
			Props: map[string]any{"Role": computeRoleARN}},
		// EC2: resource_to_role matches InstanceProfileList CONTAINS the role's instance-profile.
		// The role's InstanceProfileList carries the compute-admin instance-profile ARN (seeded
		// via the rich GAAD role node); here we provide the matching IamInstanceProfile NAME so
		// the name-form clause ('instance-profile/' + name + '"') resolves.
		{ARN: ec2InstanceARN, ResourceType: "AWS::EC2::Instance",
			Props: map[string]any{"Role": computeRoleARN}},
		// App Runner not provisioned in fixture (needs a running container image; cost/complexity).
		svcRole("AWS::AppRunner::Service", "arn:aws:apprunner:us-east-2:000000000000:service/pf"),
		// Glue DevEndpoint not provisioned in fixture (needs a VPC + bills hourly per DPU).
		svcRole("AWS::Glue::DevEndpoint", "arn:aws:glue:us-east-2:000000000000:devEndpoint/pf"),
		// SageMaker NotebookInstance not provisioned in fixture (bills while InService, slow).
		svcRole("AWS::SageMaker::NotebookInstance", "arn:aws:sagemaker:us-east-2:000000000000:notebook-instance/pf"),
		// Bedrock AgentCore CodeInterpreter not provisioned in fixture (preview service, no
		// Terraform provider resource). Runs the bedrock-agentcore-trusting role the query expects.
		svcRoleARN("AWS::BedrockAgentCore::CodeInterpreter", "arn:aws:bedrock-agentcore:us-east-2:000000000000:code-interpreter/pf", bedrockExecRoleARN),
	}
}

// sameNodeActionBindings lists the existing-compute HAS_ROLE methods whose guard MATCHes the
// attacker's action edge and the (Resource)-[:HAS_ROLE]->(role) edge on the SAME node. Keyed by
// attackerKey; each entry names the synthetic resource type the action lands on plus every
// action relationship type the guard requires on that node. (lambda_update_function_code's
// trigger is an EXISTS against any target, so only UpdateFunctionCode must hit the function;
// the InvokeFunction trigger comes from the attacker's real '*' recon edge.)
var sameNodeActionBindings = map[string]struct {
	resourceType string
	actions      []string
}{
	"lambda_update_code":       {"AWS::Lambda::Function", []string{"LAMBDA_UPDATEFUNCTIONCODE"}},
	"lambda_updatecode_invoke": {"AWS::Lambda::Function", []string{"LAMBDA_UPDATEFUNCTIONCODE", "LAMBDA_INVOKEFUNCTION"}},
	"lambda_add_permission":    {"AWS::Lambda::Function", []string{"LAMBDA_UPDATEFUNCTIONCODE", "LAMBDA_ADDPERMISSION"}},
	"lambda_create_esm":        {"AWS::Lambda::Function", []string{"LAMBDA_UPDATEFUNCTIONCODE", "LAMBDA_CREATEEVENTSOURCEMAPPING"}},
	"apprunner_update_service": {"AWS::AppRunner::Service", []string{"APPRUNNER_UPDATESERVICE"}},
	"stepfunctions_update":     {"AWS::StepFunctions::StateMachine", []string{"STATES_UPDATESTATEMACHINE", "STATES_STARTEXECUTION"}},
}

// SyntheticActionEdges builds the attacker->resource action relationships the same-node-binding
// HAS_ROLE methods need. Each edge points the attacker's action at the Resource node that carries
// (Resource)-[:HAS_ROLE]->(privileged role), so the guard's same-node MATCH resolves — exactly
// what production recon emits when the real resource's '*'-scoped action edge binds to it.
//
// For a type whose REAL backing resource was provisioned + collected (e.g. SFN StateMachine), the
// action edge attaches to the REAL node's arn (realByType) so the SAME real node carries both the
// action edge and HAS_ROLE. For a kept-synthetic type (App Runner, Lambda) it attaches to the
// synthetic node (resources). This keeps stepfunctions_update on the real path while
// apprunner_update_service / lambda_* stay on their synthetic stand-ins.
func SyntheticActionEdges(attackerARNs map[string]string, resources []SyntheticResource, realByType map[string]string) []*graph.Relationship {
	// Prefer a real collected node's arn; fall back to the synthetic node's arn.
	arnByType := map[string]string{}
	for _, r := range resources {
		arnByType[r.ResourceType] = r.ARN
	}
	for rt, arn := range realByType {
		arnByType[rt] = arn // real overrides synthetic when both exist
	}
	endNode := func(rt string) *graph.Node {
		arn := arnByType[rt]
		if arn == "" {
			return nil
		}
		return &graph.Node{
			Labels:     []string{"Resource", rt},
			Properties: map[string]any{"arn": arn, "_type": "Resource", "_resourceType": rt},
			UniqueKey:  []string{"arn"},
		}
	}
	var rels []*graph.Relationship
	for key, b := range sameNodeActionBindings {
		attacker := attackerARNs[key]
		end := endNode(b.resourceType)
		if attacker == "" || end == nil {
			continue
		}
		start := &graph.Node{Labels: []string{"Principal"}, Properties: map[string]any{"Arn": attacker}, UniqueKey: []string{"Arn"}}
		for _, action := range b.actions {
			rels = append(rels, &graph.Relationship{
				Type:       action,
				Properties: map[string]any{"action": action, "_synthetic": true},
				StartNode:  start,
				EndNode:    end,
			})
		}
	}
	return rels
}

// SameNodeStubNode is the neutral shared target the same-node-binding stub edges point at. Its
// _resourceType matches no privesc method's resource filter, so it only satisfies the guard's
// same-node action clauses and never itself becomes a CAN_PRIVESC target.
func SameNodeStubNode() *graph.Node {
	const arn = "arn:aws:pf:us-east-2:000000000000:same-node-stub"
	return &graph.Node{
		Labels:     []string{"Resource", "AWS::PF::CompanionStub"},
		Properties: map[string]any{"arn": arn, "_type": "Resource", "_resourceType": "AWS::PF::CompanionStub"},
		UniqueKey:  []string{"arn"},
	}
}

// sameNodeStubBindings lists methods (keyed by attackerKey) whose guard MATCHes two genuinely-
// emitted action edges on the SAME node while the resource map binds them to DIFFERENT nodes.
// Seeding both onto one shared stub relocates the edges the evaluator already emits.
//
// lambda_passrole_addperm: lambda:CreateFunction (mapped→service stub) AND lambda:AddPermission
// (mapped→function node) are BOTH allowlisted and emitted, but
// lambda_passrole_createfunction_addpermission.yaml MATCHes both on the same svc node. PassRole→
// svcadmin-lambda is the recon-collected victim binding and is not re-seeded.
var sameNodeStubBindings = map[string][]string{
	"lambda_passrole_addperm": {"LAMBDA_CREATEFUNCTION", "LAMBDA_ADDPERMISSION"},
}

// SameNodeStubEdges builds the attacker->shared-stub action edges for the same-node-binding
// methods. Each action is seeded ONLY for its named TP attacker so no FP attacker gains an edge.
func SameNodeStubEdges(attackerARNs map[string]string, stub *graph.Node) []*graph.Relationship {
	var rels []*graph.Relationship
	for key, actions := range sameNodeStubBindings {
		attacker := attackerARNs[key]
		if attacker == "" {
			continue
		}
		start := &graph.Node{Labels: []string{"Principal"}, Properties: map[string]any{"Arn": attacker}, UniqueKey: []string{"Arn"}}
		for _, action := range actions {
			rels = append(rels, &graph.Relationship{
				Type:       action,
				Properties: map[string]any{"action": action, "_synthetic": true},
				StartNode:  start,
				EndNode:    stub,
			})
		}
	}
	return rels
}

// SyntheticInputs records the fixture-resolved ARNs the kept synthetics bind to plus the attacker
// ARN map, so a replay run can reconstruct the synthetic resources/edges and the case-target facts
// without any AWS access.
type SyntheticInputs struct {
	ComputeAdminARN  string            `json:"compute_admin_arn"`
	EC2InstanceARN   string            `json:"ec2_instance_arn"`
	BedrockExecRole  string            `json:"bedrock_exec_role_arn"`
	AdminTargetARN   string            `json:"admin_target_arn"`
	PrivUserARN      string            `json:"priv_user_arn"`
	Prefix           string            `json:"prefix"`
	AccountID        string            `json:"account_id"`
	ServiceAdminARNs map[string]string `json:"service_admin_arns"`
	AttackerARNs     map[string]string `json:"attacker_arns"`
	DecoyARNs        []string          `json:"decoy_arns"`
}

// PrivescReconSnapshot is the captured, replay-able recon output for the privesc fixture. The IAM
// entities are stored as TYPED GAAD detail structs (not []AWSIAMResource) so the replay rebuilds
// the SAME rich nodes the live run does via NodeFromGaad*. Relationships and non-IAM resources are
// stored as their lossless output types.
type PrivescReconSnapshot struct {
	Roles           []types.RoleDetail          `json:"roles"`
	Users           []types.UserDetail          `json:"users"`
	Groups          []types.GroupDetail         `json:"groups"`
	Policies        []types.ManagedPolicyDetail `json:"policies"`
	Relationships   []output.AWSIAMRelationship `json:"relationships"`
	Resources       []output.AWSResource        `json:"resources"`
	SyntheticInputs SyntheticInputs             `json:"synthetic_inputs"`
}

// CaptureToFile builds a snapshot from the collected recon entities and writes it as indented JSON
// to path (repo-relative paths land under the repo root), creating the parent directory if needed.
// It recovers each IAM entity's typed GAAD struct from AWSIAMResource.OriginalData via a type-switch
// so the rich-node inputs are preserved (OriginalData is json:"-" and would otherwise be lost);
// entities without recoverable typed data are skipped (they would only rebuild minimal {Arn} nodes).
func CaptureToFile(path string, iamResources []output.AWSIAMResource, rels []output.AWSIAMRelationship, resources []output.AWSResource, inputs SyntheticInputs) error {
	snap := PrivescReconSnapshot{
		Relationships:   rels,
		Resources:       resources,
		SyntheticInputs: inputs,
	}
	for _, r := range iamResources {
		switch d := r.OriginalData.(type) {
		case types.UserDetail:
			snap.Users = append(snap.Users, d)
		case types.RoleDetail:
			snap.Roles = append(snap.Roles, d)
		case types.GroupDetail:
			snap.Groups = append(snap.Groups, d)
		case types.ManagedPolicyDetail:
			snap.Policies = append(snap.Policies, d)
		}
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	abs := resolvePath(path)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return nil
}

// SnapshotExists reports whether the snapshot file at the given (repo-relative or absolute) path
// is present on disk, resolving the path the same way as Load/Capture.
func SnapshotExists(path string) bool {
	_, err := os.Stat(resolvePath(path))
	return err == nil
}

// LoadFromFile reads a snapshot from path (repo-relative paths are resolved against the repo root).
func LoadFromFile(path string) (*PrivescReconSnapshot, error) {
	data, err := os.ReadFile(resolvePath(path))
	if err != nil {
		return nil, err
	}
	var snap PrivescReconSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return &snap, nil
}
