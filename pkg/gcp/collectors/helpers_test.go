package gcloudcollectors

import (
	"testing"
)

func TestExtractProjectIDFromEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
	}{
		{
			name:     "standard service account email",
			email:    "sa@my-project-123.iam.gserviceaccount.com",
			expected: "my-project-123",
		},
		{
			name:     "hyphenated project id",
			email:    "test-sa@prod-env-456.iam.gserviceaccount.com",
			expected: "prod-env-456",
		},
		{
			name:     "invalid email format",
			email:    "not-an-email",
			expected: "",
		},
		{
			name:     "empty email",
			email:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractProjectIDFromEmail(tt.email)
			if result != tt.expected {
				t.Errorf("ExtractProjectIDFromEmail(%q) = %q, want %q", tt.email, result, tt.expected)
			}
		})
	}
}

func TestExtractProjectNumber(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "full URI with project number",
			uri:      "//run.googleapis.com/projects/123456789/locations/us-central1/services/my-service",
			expected: "123456789",
		},
		{
			name:     "short URI with project number",
			uri:      "projects/987654321",
			expected: "987654321",
		},
		{
			name:     "URI with project ID not number",
			uri:      "//run.googleapis.com/projects/my-project/locations/us/services/test",
			expected: "",
		},
		{
			name:     "no project in URI",
			uri:      "//storage.googleapis.com/buckets/my-bucket",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractProjectNumber(tt.uri)
			if result != tt.expected {
				t.Errorf("ExtractProjectNumber(%q) = %q, want %q", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestExtractProjectIDFromURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "full URI with project ID",
			uri:      "//run.googleapis.com/projects/my-project-123/locations/us/services/test",
			expected: "my-project-123",
		},
		{
			name:     "short URI with project ID",
			uri:      "projects/prod-env",
			expected: "prod-env",
		},
		{
			name:     "URI with project number",
			uri:      "projects/123456789/serviceAccounts/email",
			expected: "123456789",
		},
		{
			name:     "no project in URI",
			uri:      "organizations/123",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractProjectIDFromURI(tt.uri)
			if result != tt.expected {
				t.Errorf("ExtractProjectIDFromURI(%q) = %q, want %q", tt.uri, result, tt.expected)
			}
		})
	}
}

func TestBuildFullResourceURI(t *testing.T) {
	projectIDToNumber := map[string]string{
		"my-project-123": "123456789",
		"prod-env":       "987654321",
	}

	tests := []struct {
		name     string
		service  string
		shortURI string
		expected string
	}{
		{
			name:     "cloud run service with project ID",
			service:  "run.googleapis.com",
			shortURI: "projects/my-project-123/locations/us-central1/services/my-service",
			expected: "//run.googleapis.com/projects/123456789/locations/us-central1/services/my-service",
		},
		{
			name:     "cloud function with project ID",
			service:  "cloudfunctions.googleapis.com",
			shortURI: "projects/prod-env/locations/us-east1/functions/test-fn",
			expected: "//cloudfunctions.googleapis.com/projects/987654321/locations/us-east1/functions/test-fn",
		},
		{
			name:     "unknown project ID",
			service:  "compute.googleapis.com",
			shortURI: "projects/unknown-project/zones/us-east1-a/instances/vm-1",
			expected: "//compute.googleapis.com/projects/unknown-project/zones/us-east1-a/instances/vm-1",
		},
		{
			name:     "no project in URI",
			service:  "storage.googleapis.com",
			shortURI: "buckets/my-bucket",
			expected: "//storage.googleapis.com/buckets/my-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildFullResourceURI(tt.service, tt.shortURI, projectIDToNumber)
			if result != tt.expected {
				t.Errorf("BuildFullResourceURI(%q, %q) = %q, want %q", tt.service, tt.shortURI, result, tt.expected)
			}
		})
	}
}

func TestBuildServiceAccountURI(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		projectNumber string
		expected      string
	}{
		{
			name:          "standard service account",
			email:         "sa@my-project.iam.gserviceaccount.com",
			projectNumber: "123456789",
			expected:      "//iam.googleapis.com/projects/123456789/serviceAccounts/sa@my-project.iam.gserviceaccount.com",
		},
		{
			name:          "default compute service account",
			email:         "123456789-compute@developer.gserviceaccount.com",
			projectNumber: "123456789",
			expected:      "//iam.googleapis.com/projects/123456789/serviceAccounts/123456789-compute@developer.gserviceaccount.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildServiceAccountURI(tt.email, tt.projectNumber)
			if result != tt.expected {
				t.Errorf("BuildServiceAccountURI(%q, %q) = %q, want %q", tt.email, tt.projectNumber, result, tt.expected)
			}
		})
	}
}

func TestBuildProjectParentURI(t *testing.T) {
	tests := []struct {
		name          string
		projectNumber string
		expected      string
	}{
		{
			name:          "standard project number",
			projectNumber: "123456789",
			expected:      "//cloudresourcemanager.googleapis.com/projects/123456789",
		},
		{
			name:          "long project number",
			projectNumber: "987654321012345",
			expected:      "//cloudresourcemanager.googleapis.com/projects/987654321012345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildProjectParentURI(tt.projectNumber)
			if result != tt.expected {
				t.Errorf("BuildProjectParentURI(%q) = %q, want %q", tt.projectNumber, result, tt.expected)
			}
		})
	}
}

func TestNormalizeToFullURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "already full URI",
			uri:      "//cloudresourcemanager.googleapis.com/projects/123",
			expected: "//cloudresourcemanager.googleapis.com/projects/123",
		},
		{
			name:     "short project URI",
			uri:      "projects/123",
			expected: "//cloudresourcemanager.googleapis.com/projects/123",
		},
		{
			name:     "short folder URI",
			uri:      "folders/456",
			expected: "//cloudresourcemanager.googleapis.com/folders/456",
		},
		{
			name:     "short organization URI",
			uri:      "organizations/789",
			expected: "//cloudresourcemanager.googleapis.com/organizations/789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeToFullURI(tt.uri)
			if result != tt.expected {
				t.Errorf("NormalizeToFullURI(%q) = %q, want %q", tt.uri, result, tt.expected)
			}
		})
	}
}
