package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractors_LambdaCodeRegistered(t *testing.T) {
	extractors := getExtractors("AWS::Lambda::Function")
	require.NotEmpty(t, extractors, "expected extractors registered for AWS::Lambda::Function")

	var found bool
	for _, e := range extractors {
		if e.Name == "lambda-code" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected lambda-code extractor registered for AWS::Lambda::Function")
}
