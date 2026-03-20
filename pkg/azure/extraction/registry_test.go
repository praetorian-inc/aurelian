package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
)

func TestMustRegister_And_GetExtractors(t *testing.T) {
	saved := extractorsByType
	extractorsByType = map[string][]registeredExtractor{}
	defer func() { extractorsByType = saved }()

	fn := func(_ extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
		return nil
	}
	mustRegister("microsoft.compute/virtualmachines", "vm-userdata", fn)

	result := getExtractors("microsoft.compute/virtualmachines")
	assert.Len(t, result, 1)
	assert.Equal(t, "vm-userdata", result[0].Name)

	assert.Empty(t, getExtractors("nonexistent"))
}

func TestMustRegister_PanicOnDuplicate(t *testing.T) {
	saved := extractorsByType
	extractorsByType = map[string][]registeredExtractor{}
	defer func() { extractorsByType = saved }()

	fn := func(_ extractContext, _ output.AzureResource, _ *pipeline.P[output.ScanInput]) error {
		return nil
	}
	mustRegister("microsoft.compute/virtualmachines", "vm-userdata", fn)

	assert.Panics(t, func() {
		mustRegister("microsoft.compute/virtualmachines", "vm-userdata", fn)
	})
}
