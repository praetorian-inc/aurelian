package extraction

import (
	"fmt"

	runapi "google.golang.org/api/run/v2"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("run.googleapis.com/Service", "env-vars", extractCloudRunEnvVars)
}

// extractCloudRunEnvVars extracts environment variables from the latest Cloud Run revision.
func extractCloudRunEnvVars(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := runapi.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloud run client: %w", err)
	}

	service, err := svc.Projects.Locations.Services.Get(r.ResourceID).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("getting cloud run service %s: %w", r.ResourceID, err)
	}

	if service.Template == nil || len(service.Template.Containers) == 0 {
		return nil
	}

	var envContent []byte
	for _, container := range service.Template.Containers {
		for _, env := range container.Env {
			if env.Value == "" {
				continue
			}
			envContent = append(envContent, []byte(env.Name+"="+env.Value+"\n")...)
		}
	}
	if len(envContent) > 0 {
		out.Send(output.ScanInputFromGCPResource(r, "env-vars", envContent))
	}
	return nil
}
