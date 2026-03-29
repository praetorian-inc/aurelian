package analyze

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPSAKeyAnalysisModule_Metadata(t *testing.T) {
	m := &GCPSAKeyAnalysisModule{}
	assert.Equal(t, "sa-key-analysis", m.ID())
	assert.Equal(t, "GCP Service Account Key Analysis", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryAnalyze, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}

func TestSANameFromEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"my-sa@my-project.iam.gserviceaccount.com", "my-sa"},
		{"compute@developer.gserviceaccount.com", "compute"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, saNameFromEmail(tc.email))
	}
}

func TestReadKeyFile_InvalidPath(t *testing.T) {
	_, err := readKeyFile("/nonexistent/path.json")
	assert.Error(t, err)
}
