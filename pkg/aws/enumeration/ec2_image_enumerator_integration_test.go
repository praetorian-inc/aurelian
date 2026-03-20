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

func TestEC2ImageEnumerator(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/public-ami")
	fixture.Setup()

	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	})
	enum := NewEC2ImageEnumerator(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	}, provider)

	t.Run("EnumerateAll discovers owned AMIs", func(t *testing.T) {
		results, err := collectImageResults(func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateAll(out)
		})
		require.NoError(t, err)
		require.NotEmpty(t, results)

		publicInUseID := fixture.Output("public_in_use_ami_id")
		publicStaleID := fixture.Output("public_stale_ami_id")
		privateID := fixture.Output("private_ami_id")

		assert.True(t, containsImageID(results, publicInUseID), "should list public in-use AMI %s", publicInUseID)
		assert.True(t, containsImageID(results, publicStaleID), "should list public stale AMI %s", publicStaleID)
		assert.True(t, containsImageID(results, privateID), "should list private AMI %s", privateID)

		inUse := findImageByID(results, publicInUseID)
		require.NotNil(t, inUse)
		assert.Equal(t, "AWS::EC2::Image", inUse.ResourceType)
		assert.NotEmpty(t, inUse.ARN)
		assert.NotEmpty(t, inUse.AccountRef)
		assert.Equal(t, "us-east-1", inUse.Region)
		assert.Equal(t, publicInUseID, inUse.Properties["ImageId"])
		assert.True(t, inUse.Properties["IsPublic"].(bool), "in-use AMI should be public")

		instanceIDs, _ := inUse.Properties["InUseByInstances"].([]string)
		assert.Contains(t, instanceIDs, fixture.Output("instance_id"))

		stale := findImageByID(results, publicStaleID)
		require.NotNil(t, stale)
		assert.True(t, stale.Properties["IsPublic"].(bool))
		staleInstances, _ := stale.Properties["InUseByInstances"].([]string)
		assert.Empty(t, staleInstances)

		priv := findImageByID(results, privateID)
		require.NotNil(t, priv)
		assert.False(t, priv.Properties["IsPublic"].(bool))
	})

	t.Run("EnumerateByARN fetches single AMI", func(t *testing.T) {
		allResults, err := collectImageResults(func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateAll(out)
		})
		require.NoError(t, err)

		publicInUseID := fixture.Output("public_in_use_ami_id")
		inUse := findImageByID(allResults, publicInUseID)
		require.NotNil(t, inUse)
		require.NotEmpty(t, inUse.ARN)

		results, err := collectImageResults(func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(inUse.ARN, out)
		})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, publicInUseID, results[0].ResourceID)
	})

	t.Run("ResourceType", func(t *testing.T) {
		assert.Equal(t, "AWS::EC2::Image", enum.ResourceType())
	})
}

func collectImageResults(run func(out *pipeline.P[output.AWSResource]) error) ([]output.AWSResource, error) {
	out := pipeline.New[output.AWSResource]()
	resultCh := make(chan []output.AWSResource, 1)
	go func() {
		var results []output.AWSResource
		for r := range out.Range() {
			results = append(results, r)
		}
		resultCh <- results
	}()
	err := run(out)
	out.Close()
	return <-resultCh, err
}

func containsImageID(results []output.AWSResource, id string) bool {
	for _, r := range results {
		if r.ResourceID == id {
			return true
		}
	}
	return false
}

func findImageByID(results []output.AWSResource, id string) *output.AWSResource {
	for _, r := range results {
		if r.ResourceID == id {
			return &r
		}
	}
	return nil
}
