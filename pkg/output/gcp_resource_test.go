package output_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
)

func TestGCPResource_ImplementsAurelianModel(t *testing.T) {
	var _ model.AurelianModel = output.GCPResource{}
}

func TestNewGCPResource(t *testing.T) {
	r := output.NewGCPResource("my-project", "compute.googleapis.com/Instance", "projects/my-project/zones/us-central1-a/instances/vm-1")
	assert.Equal(t, "my-project", r.ProjectID)
	assert.Equal(t, "compute.googleapis.com/Instance", r.ResourceType)
	assert.Equal(t, "projects/my-project/zones/us-central1-a/instances/vm-1", r.ResourceID)
}
