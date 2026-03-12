package extraction

import (
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// extractTags scans resource tags for secrets. Called by the dispatcher for any
// resource with non-empty tags. Zero extra API cost (tags come from ARG).
func extractTags(_ extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	if len(r.Tags) == 0 {
		return nil
	}
	tagsJSON, err := json.Marshal(r.Tags)
	if err != nil {
		return nil
	}
	out.Send(output.ScanInputFromAzureResource(r, "Tags", tagsJSON))
	return nil
}
