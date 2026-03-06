package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractStorage_RegisteredTypes(t *testing.T) {
	extractors := getExtractors("microsoft.storage/storageaccounts")
	assert.NotEmpty(t, extractors, "expected extractors registered for microsoft.storage/storageaccounts")
	assert.Equal(t, "storage-blobs", extractors[0].Name)
}
