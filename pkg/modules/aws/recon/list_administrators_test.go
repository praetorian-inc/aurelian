package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestListAdministratorsModuleMetadata(t *testing.T) {
	m := &AWSListAdministratorsModule{}
	assert.Equal(t, "list-administrators", m.ID())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Contains(t, m.SupportedResourceTypes(), "AWS::IAM::User")
	assert.Contains(t, m.SupportedResourceTypes(), "AWS::IAM::Role")
	assert.Contains(t, m.SupportedResourceTypes(), "AWS::IAM::Group")
}
