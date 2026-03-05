package resourcegraph

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestQueryInput_HasRequiredFields(t *testing.T) {
	input := QueryInput{
		Template: &templates.ARGQueryTemplate{
			ID:       "test",
			Name:     "Test",
			Query:    "resources | limit 1",
			Severity: "Low",
		},
	}
	assert.Equal(t, "test", input.Template.ID)
}

func TestQuery_MethodSignature(t *testing.T) {
	var lister *ResourceGraphLister
	var _ func(QueryInput, *pipeline.P[templates.ARGQueryResult]) error = lister.Query
}
