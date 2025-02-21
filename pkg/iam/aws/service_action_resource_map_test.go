package aws

import (
	"regexp"
	"slices"
	"testing"
)

func TestIsValidActionForResource(t *testing.T) {
	testCases := []struct {
		name     string
		action   string
		resource string
		expected bool
	}{
		{
			name:     "Valid action and resource",
			action:   "iam:AddUserToGroup",
			resource: "arn:aws:iam::123456789012:group/test-group",
			expected: true,
		},
		{
			name:     "Invalid action",
			action:   "iam:InvalidAction",
			resource: "arn:aws:iam::123456789012:group/test-group",
			expected: false,
		},
		{
			name:     "Valid action but invalid resource",
			action:   "iam:AddUserToGroup",
			resource: "arn:aws:iam::123456789012:role/test-role",
			expected: false,
		},
		{
			name:     "Valid action and resource with different service",
			action:   "s3:PutObject",
			resource: "arn:aws:s3:::my-bucket/my-object",
			expected: true,
		},
		{
			name:     "Invalid resource pattern",
			action:   "iam:AddUserToGroup",
			resource: "arn:aws:iam::123456789012:invalid/test",
			expected: false,
		},
		{
			name:     "Valid action and resource with wildcard",
			action:   "iam:AttachUserPolicy",
			resource: "arn:aws:iam::123456789012:user/*",
			expected: true,
		},
		{
			name:     "Valid action and resource with specific user",
			action:   "iam:AttachUserPolicy",
			resource: "arn:aws:iam::123456789012:user/test-user",
			expected: true,
		},
		{
			name:     "Valid action and resource with policy",
			action:   "iam:CreatePolicy",
			resource: "arn:aws:iam::123456789012:policy/test-policy",
			expected: true,
		},
		{
			name:     "Valid action and resource with instance profile",
			action:   "iam:AddRoleToInstanceProfile",
			resource: "arn:aws:iam::123456789012:instance-profile/test-profile",
			expected: true,
		},
		{
			name:     "Valid action and resource with MFA device",
			action:   "iam:CreateVirtualMFADevice",
			resource: "arn:aws:iam::123456789012:mfa/test-mfa",
			expected: true,
		},
		{
			name:     "Valid action and resource with OIDC provider",
			action:   "iam:CreateOpenIDConnectProvider",
			resource: "arn:aws:iam::123456789012:oidc-provider/test-oidc",
			expected: true,
		},
		{
			name:     "Valid action and resource with SAML provider",
			action:   "iam:CreateSAMLProvider",
			resource: "arn:aws:iam::123456789012:saml-provider/test-saml",
			expected: true,
		},
		{
			name:     "Valid action and resource with server certificate",
			action:   "iam:UploadServerCertificate",
			resource: "arn:aws:iam::123456789012:server-certificate/test-cert",
			expected: true,
		},
		{
			name:     "Valid action and resource with SSH public key",
			action:   "iam:UploadSSHPublicKey",
			resource: "arn:aws:iam::123456789012:user/test-user",
			expected: true,
		},
		{
			name:     "Valid action and resource with signing certificate",
			action:   "iam:UploadSigningCertificate",
			resource: "arn:aws:iam::123456789012:user/test-user",
			expected: true,
		},
		{
			name:     "Invalid action format",
			action:   "invalid-action-format",
			resource: "arn:aws:iam::123456789012:user/test-user",
			expected: false,
		},
		{
			name:     "Non-existent service",
			action:   "nonexistent:Action",
			resource: "arn:aws:nonexistent::123456789012:resource/test",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidActionForResource(tc.action, tc.resource)
			if result != tc.expected {
				t.Errorf("Expected %v, but got %v for action %v and resource %v", tc.expected, result, tc.action, tc.resource)
			}
		})
	}
}
func TestGetResourcePatternsFromAction(t *testing.T) {
	testCases := []struct {
		name     string
		action   string
		expected []*regexp.Regexp
	}{
		{
			name:   "Put user policy",
			action: "iam:PutUserPolicy",
			expected: []*regexp.Regexp{
				regexp.MustCompile(`^arn:aws:iam::\d{12}:user/.*`),
			},
		},
		{
			name:     "Valid action with single resource pattern",
			action:   "iam:AddUserToGroup",
			expected: []*regexp.Regexp{regexp.MustCompile(`^arn:aws:iam::\d{12}:group/.*`)},
		},
		{
			name:   "Valid action with multiple resource patterns",
			action: "iam:GenerateServiceLastAccessedDetails",
			expected: []*regexp.Regexp{
				regexp.MustCompile(`^arn:aws:iam::\d{12}:group/.*`),
				regexp.MustCompile(`^arn:aws:iam::\d{12}:role/.*`),
				regexp.MustCompile(`^arn:aws:iam::\d{12}:user/.*`),
				regexp.MustCompile(`^arn:aws:iam::(\d{12}|aws):policy/.*`),
			},
		},
		{
			name:     "Invalid action",
			action:   "iam:InvalidAction",
			expected: []*regexp.Regexp{},
		},
		{
			name:     "Valid action with non-existent service",
			action:   "nonexistent:Action",
			expected: []*regexp.Regexp{regexp.MustCompile(`arn:aws:nonexistent:*:*:*`)},
		},
		{
			name:     "Valid action with EC2 service",
			action:   "ec2:RunInstances",
			expected: []*regexp.Regexp{regexp.MustCompile(`^arn:aws:ec2:[a-z-0-9]+:\d{12}:instance/.*`)},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := GetResourcePatternsFromAction(Action(tc.action))
			if !equalSlices(result, tc.expected) {
				t.Errorf("Expected %v, but got %v for action %v", tc.expected, result, tc.action)
			}
		})
	}
}

func equalSlices(a, b []*regexp.Regexp) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v.String() != b[i].String() {
			return false
		}
	}
	return true
}

func TestResourcePatterns(t *testing.T) {
	resources := []string{
		"arn:aws:iam::123456789012:role/test",
		"arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws:iam::123456789012:policy/test",
		"arn:aws:cloudformation:us-east-2:123456789012:stack/foo/bar",
	}

	testCases := []struct {
		name             string
		action           string
		matchedResources []string
	}{
		{
			name:   "Valid action and resource",
			action: "iam:PassRole",
			matchedResources: []string{
				resources[0],
			},
		},
		{
			name:   "Valid action and resource",
			action: "iam:SetDefaultPolicyVersion",
			matchedResources: []string{
				resources[1],
				resources[2],
			},
		},
		{
			name:   "Cloudformation",
			action: "cloudformation:CreateStack",
			matchedResources: []string{
				resources[3],
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			patterns := GetResourcePatternsFromAction(Action(tc.action))
			t.Logf("Patterns: %v", patterns)
			matched := []string{}
			for _, pattern := range patterns {
				for _, resource := range resources {
					if matchesRegexPattern(pattern, resource) {
						matched = append(matched, resource)
					}
				}
			}

			if !slices.Equal(matched, tc.matchedResources) {
				t.Errorf("Expected %v, but got %v for action %v", tc.matchedResources, matched, tc.action)
			}
		})
	}
}
