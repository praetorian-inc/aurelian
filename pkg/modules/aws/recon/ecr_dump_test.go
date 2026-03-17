package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestECRDumpModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "ecr-dump")
	require.True(t, ok, "ecr-dump module should be registered")
	require.NotNil(t, mod)
}

func TestECRDumpModuleMetadata(t *testing.T) {
	m := &AWSECRDumpModule{}
	assert.Equal(t, "ecr-dump", m.ID())
	assert.Equal(t, "AWS ECR Dump", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.Contains(t, m.Description(), "ECR")
	assert.Contains(t, m.Description(), "Titus")

	refs := m.References()
	require.Len(t, refs, 2)

	types := m.SupportedResourceTypes()
	assert.Contains(t, types, "AWS::ECR::Repository")
	assert.Contains(t, types, "AWS::ECR::PublicRepository")
}

func TestECRDumpModuleParameters(t *testing.T) {
	m := &AWSECRDumpModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["extract"], "should have extract param")
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-repo", "my-repo"},
		{"org/my-repo", "org_my-repo"},
		{"my.repo:latest", "my_repo_latest"},
		{"a/b/c.d:e", "a_b_c_d_e"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, sanitizeName(tt.input))
	}
}

func TestIsBinary(t *testing.T) {
	assert.False(t, isBinary([]byte("hello world")))
	assert.False(t, isBinary([]byte("#!/bin/bash\necho hi")))
	assert.True(t, isBinary([]byte{0x89, 0x50, 0x4e, 0x47, 0x00})) // PNG header with null
	assert.True(t, isBinary([]byte("ELF\x00binary")))
	assert.False(t, isBinary([]byte{}))
}
