package extraction

import (
	"fmt"

	computeapi "google.golang.org/api/compute/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("compute.googleapis.com/Instance", "metadata", extractInstanceMetadata)
}

// extractInstanceMetadata fetches instance metadata items (including startup scripts).
func extractInstanceMetadata(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := computeapi.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	inst, err := svc.Instances.Get(r.ProjectID, r.Location, r.DisplayName).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("getting instance %s: %w", r.DisplayName, err)
	}

	if inst.Metadata == nil {
		return nil
	}

	for _, item := range inst.Metadata.Items {
		if item.Value == nil || *item.Value == "" {
			continue
		}
		out.Send(output.ScanInputFromGCPResource(r, fmt.Sprintf("metadata/%s", item.Key), []byte(*item.Value)))
	}
	return nil
}
