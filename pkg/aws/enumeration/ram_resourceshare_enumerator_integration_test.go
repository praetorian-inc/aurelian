//go:build integration

package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRAMResourceShareEnumerator(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/ram-resource-share")
	fixture.Setup()

	opts := plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	}
	provider := NewAWSConfigProvider(opts)
	enum := NewRAMResourceShareEnumerator(opts, provider, NewSkipReport())

	out := pipeline.New[output.AWSResource]()
	go func() {
		require.NoError(t, enum.EnumerateAll(out))
		out.Close()
	}()

	var results []output.AWSResource
	for r := range out.Range() {
		results = append(results, r)
	}
	require.NoError(t, out.Wait())
	require.NotEmpty(t, results)

	externalArn := fixture.Output("external_share_arn")
	orgOnlyArn := fixture.Output("org_only_share_arn")
	externalPrincipal := fixture.Output("external_principal_id")

	byArn := make(map[string]output.AWSResource)
	for _, r := range results {
		assert.Equal(t, "AWS::RAM::ResourceShare", r.ResourceType)
		byArn[r.ARN] = r
	}

	ext, ok := byArn[externalArn]
	require.True(t, ok, "external share %s should be enumerated", externalArn)
	assert.Equal(t, true, ext.Properties["AllowExternalPrincipals"])
	assert.Contains(t, ext.Properties["Principals"], externalPrincipal)

	org, ok := byArn[orgOnlyArn]
	require.True(t, ok, "org-only share %s should be enumerated", orgOnlyArn)
	assert.Equal(t, false, org.Properties["AllowExternalPrincipals"])
}
