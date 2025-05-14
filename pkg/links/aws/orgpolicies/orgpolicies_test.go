package orgpolicies

import (
	"encoding/json"
	"testing"
)

func TestGetDirectScpStatementsForTarget(t *testing.T) {

	jsonData := `{
		"scps": [
			{
				"policySummary": {
					"Arn": "arn:aws:organizations::123456789012:policy/test-scp",
					"Id": "p-test123",
					"Name": "test-scp"
				},
				"policyContent": {
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": ["s3:*"],
							"Resource": ["*"]
						}
					]
				}
			}
		],
		"rcps": [],
		"targets": [
			{
				"id": "abcd",
				"name": "test-target",
				"type": "ACCOUNT",
				"account": {
					"id": "123",
					"name": "Test Account",
					"email": "test@example.com",
					"status": "ACTIVE"
				},
				"scps": {
					"direct": ["arn:aws:organizations::123456789012:policy/test-scp"],
					"parents": []
				},
				"rcps": {
					"direct": [],
					"parents": []
				}
			}
		]
	}`

	var orgPolicies OrgPolicies
	err := json.Unmarshal([]byte(jsonData), &orgPolicies)
	if err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	statements := orgPolicies.GetDirectScpStatementsForTarget("123")
	if statements == nil {
		t.Fatal("Expected statements but got nil")
	}

	if len(*statements) != 1 {
		t.Errorf("Expected 1 statement, got %d", len(*statements))
	}

	stmt := (*statements)[0]
	if stmt.Effect != "Allow" {
		t.Errorf("Expected Allow effect, got %s", stmt.Effect)
	}

	if len(*stmt.Action) != 1 || (*stmt.Action)[0] != "s3:*" {
		t.Errorf("Expected [s3:*] action, got %v", *stmt.Action)
	}

	if len(*stmt.Resource) != 1 || (*stmt.Resource)[0] != "*" {
		t.Errorf("Expected [*] resource, got %v", *stmt.Resource)
	}

	// Test non-existent target
	statements = orgPolicies.GetDirectScpStatementsForTarget("456")
	if statements != nil {
		t.Error("Expected nil statements for non-existent target")
	}
}

func TestGetParentScpStatementsForTarget(t *testing.T) {
	jsonData := `{
		"scps": [
			{
				"policySummary": {
					"Arn": "arn:aws:organizations::123456789012:policy/parent-scp",
					"Id": "p-parent123",
					"Name": "parent-scp"
				},
				"policyContent": {
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Deny",
							"Action": ["iam:*"],
							"Resource": ["*"]
						}
					]
				}
			}
		],
		"rcps": [],
		"targets": [
			{
				"id": "foo",
				"name": "test-target",
				"type": "ACCOUNT",
				"account": {
					"id": "123",
					"name": "Test Account",
					"email": "test@example.com",
					"status": "ACTIVE"
				},
				"scps": {
					"direct": [],
					"parents": [
						{
							"name": "parent-ou",
							"id": "ou-1234",
							"policies": ["arn:aws:organizations::123456789012:policy/parent-scp"]
						}
					]
				},
				"rcps": {
					"direct": [],
					"parents": []
				}
			}
		]
	}`

	var orgPolicies OrgPolicies
	err := json.Unmarshal([]byte(jsonData), &orgPolicies)
	if err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	// Test successful case
	statements := orgPolicies.GetParentScpStatementsForTarget("123")
	if statements == nil {
		t.Fatal("Expected statements but got nil")
	}

	if len(*statements) != 1 {
		t.Errorf("Expected 1 statement, got %d", len(*statements))
	}

	stmt := (*statements)[0]
	if stmt.Effect != "Deny" {
		t.Errorf("Expected Deny effect, got %s", stmt.Effect)
	}

	if len(*stmt.Action) != 1 || (*stmt.Action)[0] != "iam:*" {
		t.Errorf("Expected [iam:*] action, got %v", *stmt.Action)
	}

	if len(*stmt.Resource) != 1 || (*stmt.Resource)[0] != "*" {
		t.Errorf("Expected [*] resource, got %v", *stmt.Resource)
	}

	// Test non-existent target
	statements = orgPolicies.GetParentScpStatementsForTarget("456")
	if statements != nil {
		t.Error("Expected nil statements for non-existent target")
	}
}

func TestGetAllScpPoliciesForTarget(t *testing.T) {
	jsonData := `{
		"scps": [
			{
				"policySummary": {
					"Arn": "arn:aws:organizations::123456789012:policy/direct-scp",
					"Id": "p-direct123",
					"Name": "direct-scp"
				},
				"policyContent": {
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Allow",
							"Action": ["s3:*"],
							"Resource": ["*"]
						}
					]
				}
			},
			{
				"policySummary": {
					"Arn": "arn:aws:organizations::123456789012:policy/parent-scp",
					"Id": "p-parent123",
					"Name": "parent-scp"
				},
				"policyContent": {
					"Version": "2012-10-17",
					"Statement": [
						{
							"Effect": "Deny",
							"Action": ["iam:*"],
							"Resource": ["*"]
						}
					]
				}
			}
		],
		"rcps": [],
		"targets": [
			{
				"id": "abcd",
				"name": "test-target",
				"type": "ACCOUNT",
				"account": {
					"id": "123",
					"name": "Test Account",
					"email": "test@example.com",
					"status": "ACTIVE"
				},
				"scps": {
					"direct": ["arn:aws:organizations::123456789012:policy/direct-scp"],
					"parents": [
						{
							"name": "parent-ou",
							"id": "ou-1234",
							"policies": ["arn:aws:organizations::123456789012:policy/parent-scp"]
						}
					]
				},
				"rcps": {
					"direct": [],
					"parents": []
				}
			}
		]
	}`

	var orgPolicies OrgPolicies
	err := json.Unmarshal([]byte(jsonData), &orgPolicies)
	if err != nil {
		t.Fatalf("Failed to unmarshal test data: %v", err)
	}

	// Test successful case
	statements := orgPolicies.GetAllScpPoliciesForTarget("123")
	if statements == nil {
		t.Fatal("Expected statements but got nil")
	}

	if len(*statements) != 2 {
		t.Errorf("Expected 2 statements, got %d", len(*statements))
	}

	// Verify both direct and parent policies are included
	foundAllow := false
	foundDeny := false
	for _, stmt := range *statements {
		switch stmt.Effect {
		case "Allow":
			foundAllow = true
			if len(*stmt.Action) != 1 || (*stmt.Action)[0] != "s3:*" {
				t.Errorf("Expected [s3:*] action for Allow statement, got %v", *stmt.Action)
			}
		case "Deny":
			foundDeny = true
			if len(*stmt.Action) != 1 || (*stmt.Action)[0] != "iam:*" {
				t.Errorf("Expected [iam:*] action for Deny statement, got %v", *stmt.Action)
			}
		}
	}

	if !foundAllow {
		t.Error("Expected to find Allow statement but didn't")
	}
	if !foundDeny {
		t.Error("Expected to find Deny statement but didn't")
	}

	// Test non-existent target
	statements = orgPolicies.GetAllScpPoliciesForTarget("456")
	if statements != nil {
		t.Error("Expected nil statements for non-existent target")
	}
}
