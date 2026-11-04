package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPWhoamiModule_Metadata(t *testing.T) {
	m := &GCPWhoamiModule{}
	assert.Equal(t, "whoami", m.ID())
	assert.Equal(t, "GCP Covert Whoami", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "stealth", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}

func TestParseCredentialJSON_ServiceAccount(t *testing.T) {
	raw := []byte(`{
		"type": "service_account",
		"project_id": "my-project",
		"client_email": "my-sa@my-project.iam.gserviceaccount.com",
		"client_id": "123456789"
	}`)
	id := parseCredentialJSON(raw)
	assert.Equal(t, "service_account", id.CredType)
	assert.Equal(t, "my-sa@my-project.iam.gserviceaccount.com", id.Email)
	assert.Equal(t, "my-project", id.ProjectID)
	assert.Equal(t, "123456789", id.ClientID)
}

func TestParseCredentialJSON_AuthorizedUser(t *testing.T) {
	raw := []byte(`{
		"type": "authorized_user",
		"client_id": "abc.apps.googleusercontent.com",
		"client_secret": "secret"
	}`)
	id := parseCredentialJSON(raw)
	assert.Equal(t, "authorized_user", id.CredType)
	assert.Equal(t, "abc.apps.googleusercontent.com", id.ClientID)
	assert.Empty(t, id.Email)
}

func TestParseCredentialJSON_ExternalAccount(t *testing.T) {
	raw := []byte(`{
		"type": "external_account",
		"audience": "//iam.googleapis.com/projects/1044257231918/locations/global/workloadIdentityPools/pool/providers/provider",
		"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/my-sa@my-project.iam.gserviceaccount.com:generateAccessToken"
	}`)
	id := parseCredentialJSON(raw)
	assert.Equal(t, "external_account", id.CredType)
	assert.Equal(t, "my-sa@my-project.iam.gserviceaccount.com", id.Email)
	assert.Equal(t, "1044257231918", id.ProjectID)
}

func TestParseCredentialJSON_Empty(t *testing.T) {
	id := parseCredentialJSON(nil)
	assert.Equal(t, "application_default", id.CredType)
}

func TestSAEmailFromImpersonationURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{
			"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@proj.iam.gserviceaccount.com:generateAccessToken",
			"sa@proj.iam.gserviceaccount.com",
		},
		{"https://example.com/no-sa-here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, saEmailFromImpersonationURL(tc.url))
	}
}

func TestProjectIDFromAudience(t *testing.T) {
	tests := []struct {
		audience string
		expected string
	}{
		{
			"//iam.googleapis.com/projects/1044257231918/locations/global/workloadIdentityPools/pool/providers/prov",
			"1044257231918",
		},
		{"no-project-here", ""},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, projectIDFromAudience(tc.audience))
	}
}
