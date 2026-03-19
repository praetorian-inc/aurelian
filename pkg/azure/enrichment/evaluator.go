package enrichment

import (
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

// Evaluate is a pipeline-compatible function that checks enriched properties
// against registered evaluators. Templates without evaluators pass through.
func Evaluate(result templates.ARGQueryResult, out *pipeline.P[templates.ARGQueryResult]) error {
	eval, ok := plugin.GetAzureEvaluator(result.TemplateID)
	if !ok {
		out.Send(result)
		return nil
	}

	if eval(result) {
		out.Send(result)
	}
	return nil
}
