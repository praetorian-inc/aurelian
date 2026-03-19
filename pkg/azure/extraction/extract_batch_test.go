package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractBatch_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.batch/batchaccounts")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.batch/batchaccounts")

	names := make([]string, len(extractors))
	for i, e := range extractors {
		names[i] = e.Name
	}
	assert.Contains(t, names, "batch-pool-starttasks")
}
