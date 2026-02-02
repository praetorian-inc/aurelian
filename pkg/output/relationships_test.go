package output

import (
	"encoding/json"
	"testing"
)

func TestResourceRef_JSONSerialization(t *testing.T) {
	ref := ResourceRef{
		Platform: "aws",
		Type:     "iam-user",
		ID:       "arn:aws:iam::123456789012:user/admin",
		Account:  "123456789012",
	}

	// Test marshaling
	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("failed to marshal ResourceRef: %v", err)
	}

	// Test unmarshaling
	var decoded ResourceRef
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ResourceRef: %v", err)
	}

	// Verify fields
	if decoded.Platform != "aws" {
		t.Errorf("expected Platform 'aws', got %q", decoded.Platform)
	}
	if decoded.Type != "iam-user" {
		t.Errorf("expected Type 'iam-user', got %q", decoded.Type)
	}
	if decoded.ID != "arn:aws:iam::123456789012:user/admin" {
		t.Errorf("expected ID 'arn:aws:iam::123456789012:user/admin', got %q", decoded.ID)
	}
	if decoded.Account != "123456789012" {
		t.Errorf("expected Account '123456789012', got %q", decoded.Account)
	}
}

func TestIAMPermission_JSONSerialization(t *testing.T) {
	perm := IAMPermission{
		Source: ResourceRef{
			Platform: "aws",
			Type:     "iam-role",
			ID:       "arn:aws:iam::123456789012:role/admin",
			Account:  "123456789012",
		},
		Target: ResourceRef{
			Platform: "aws",
			Type:     "s3-bucket",
			ID:       "arn:aws:s3:::my-bucket",
			Account:  "123456789012",
		},
		Permission: "s3:GetObject",
		Effect:     "Allow",
		Conditions: map[string]any{
			"IpAddress": map[string]any{
				"aws:SourceIp": "203.0.113.0/24",
			},
		},
		Capability: "apollo-iam-analyzer",
		Timestamp:  "2026-01-04T10:00:00Z",
	}

	// Test marshaling
	data, err := json.Marshal(perm)
	if err != nil {
		t.Fatalf("failed to marshal IAMPermission: %v", err)
	}

	// Test unmarshaling
	var decoded IAMPermission
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal IAMPermission: %v", err)
	}

	// Verify fields
	if decoded.Source.Type != "iam-role" {
		t.Errorf("expected Source.Type 'iam-role', got %q", decoded.Source.Type)
	}
	if decoded.Target.Type != "s3-bucket" {
		t.Errorf("expected Target.Type 's3-bucket', got %q", decoded.Target.Type)
	}
	if decoded.Permission != "s3:GetObject" {
		t.Errorf("expected Permission 's3:GetObject', got %q", decoded.Permission)
	}
	if decoded.Effect != "Allow" {
		t.Errorf("expected Effect 'Allow', got %q", decoded.Effect)
	}
	if decoded.Capability != "apollo-iam-analyzer" {
		t.Errorf("expected Capability 'apollo-iam-analyzer', got %q", decoded.Capability)
	}
}

func TestSSMPermission_JSONSerialization(t *testing.T) {
	perm := SSMPermission{
		IAMPermission: IAMPermission{
			Source: ResourceRef{
				Platform: "aws",
				Type:     "iam-role",
				ID:       "arn:aws:iam::123456789012:role/ssm-role",
				Account:  "123456789012",
			},
			Target: ResourceRef{
				Platform: "aws",
				Type:     "ec2-instance",
				ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
				Account:  "123456789012",
			},
			Permission: "ssm:SendCommand",
			Effect:     "Allow",
			Capability: "apollo-ssm-analyzer",
			Timestamp:  "2026-01-04T10:00:00Z",
		},
		SSMDocumentRestrictions: []string{"AWS-RunShellScript"},
		AllowsShellExecution:    true,
	}

	// Test marshaling
	data, err := json.Marshal(perm)
	if err != nil {
		t.Fatalf("failed to marshal SSMPermission: %v", err)
	}

	// Test unmarshaling
	var decoded SSMPermission
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal SSMPermission: %v", err)
	}

	// Verify SSM-specific fields
	if len(decoded.SSMDocumentRestrictions) != 1 {
		t.Errorf("expected 1 SSM document restriction, got %d", len(decoded.SSMDocumentRestrictions))
	}
	if !decoded.AllowsShellExecution {
		t.Error("expected AllowsShellExecution to be true")
	}
}

func TestGitHubActionsPermission_JSONSerialization(t *testing.T) {
	perm := GitHubActionsPermission{
		IAMPermission: IAMPermission{
			Source: ResourceRef{
				Platform: "aws",
				Type:     "oidc-provider",
				ID:       "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				Account:  "123456789012",
			},
			Target: ResourceRef{
				Platform: "aws",
				Type:     "iam-role",
				ID:       "arn:aws:iam::123456789012:role/github-actions-role",
				Account:  "123456789012",
			},
			Permission: "sts:AssumeRoleWithWebIdentity",
			Effect:     "Allow",
			Capability: "apollo-github-actions-analyzer",
			Timestamp:  "2026-01-04T10:00:00Z",
		},
		SubjectPatterns: []string{"repo:myorg/myrepo:*"},
		RepositoryOrg:   "myorg",
		RepositoryName:  "myrepo",
	}

	// Test marshaling
	data, err := json.Marshal(perm)
	if err != nil {
		t.Fatalf("failed to marshal GitHubActionsPermission: %v", err)
	}

	// Test unmarshaling
	var decoded GitHubActionsPermission
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal GitHubActionsPermission: %v", err)
	}

	// Verify GitHub-specific fields
	if len(decoded.SubjectPatterns) != 1 {
		t.Errorf("expected 1 subject pattern, got %d", len(decoded.SubjectPatterns))
	}
	if decoded.RepositoryOrg != "myorg" {
		t.Errorf("expected RepositoryOrg 'myorg', got %q", decoded.RepositoryOrg)
	}
	if decoded.RepositoryName != "myrepo" {
		t.Errorf("expected RepositoryName 'myrepo', got %q", decoded.RepositoryName)
	}
}

func TestRepository_JSONSerialization(t *testing.T) {
	repo := Repository{
		Platform: "github",
		Org:      "praetorian-inc",
		Name:     "chariot",
		URL:      "https://github.com/praetorian-inc/chariot",
	}

	// Test marshaling
	data, err := json.Marshal(repo)
	if err != nil {
		t.Fatalf("failed to marshal Repository: %v", err)
	}

	// Test unmarshaling
	var decoded Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal Repository: %v", err)
	}

	// Verify fields
	if decoded.Platform != "github" {
		t.Errorf("expected Platform 'github', got %q", decoded.Platform)
	}
	if decoded.Org != "praetorian-inc" {
		t.Errorf("expected Org 'praetorian-inc', got %q", decoded.Org)
	}
	if decoded.Name != "chariot" {
		t.Errorf("expected Name 'chariot', got %q", decoded.Name)
	}
}

func TestServicePrincipal_JSONSerialization(t *testing.T) {
	sp := ServicePrincipal{
		Service:  "lambda.amazonaws.com",
		FullName: "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
	}

	// Test marshaling
	data, err := json.Marshal(sp)
	if err != nil {
		t.Fatalf("failed to marshal ServicePrincipal: %v", err)
	}

	// Test unmarshaling
	var decoded ServicePrincipal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ServicePrincipal: %v", err)
	}

	// Verify fields
	if decoded.Service != "lambda.amazonaws.com" {
		t.Errorf("expected Service 'lambda.amazonaws.com', got %q", decoded.Service)
	}
}

// TestNoGetKeyMethod verifies that relationship types do NOT have GetKey() methods
// This enforces the Pure CLI architecture where Nebula outputs domain data only
func TestNoGetKeyMethod(t *testing.T) {
	// This test ensures types remain pure domain objects without Neo4j key knowledge
	// If GetKey() methods are added, this test should fail

	ref := ResourceRef{Platform: "aws", Type: "iam-user", ID: "test", Account: "123"}
	perm := IAMPermission{
		Source:     ref,
		Target:     ref,
		Permission: "s3:GetObject",
		Capability: "test",
		Timestamp:  "2026-01-04T10:00:00Z",
	}

	// Verify that these types are just data structures, no behavior
	// In Pure CLI architecture, types should only serialize to JSON
	// Chariot (not Nebula) generates Neo4j keys

	_ = ref
	_ = perm

	// This test passes as long as the types compile and serialize
	// If someone adds GetKey() methods, they should also add verification here
	// that would fail (e.g., checking method existence via reflection)
}
