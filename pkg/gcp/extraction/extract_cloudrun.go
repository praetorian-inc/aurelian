package extraction

import (
	"fmt"
	"strings"

	"google.golang.org/api/cloudfunctions/v1"
	runapi "google.golang.org/api/run/v2"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("run.googleapis.com/Service", "env-vars", extractCloudRunEnvVars)
	mustRegister("run.googleapis.com/Service", "gen2-function-source", extractGen2FunctionSource)
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

// extractGen2FunctionSource downloads source code for Gen 2 Cloud Functions
// that appear as Cloud Run services. Skips non-Gen2 services.
func extractGen2FunctionSource(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	if r.Properties["isGen2CloudFunction"] != true {
		return nil
	}

	svc, err := cloudfunctions.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloudfunctions client: %w", err)
	}

	// Gen 2 functions use the v1 API. The Cloud Run service name follows:
	// projects/PROJECT/locations/REGION/services/SERVICE_NAME
	// For Gen 2, service name == function name, so swap "services" for "functions".
	functionName := strings.Replace(r.ResourceID, "/services/", "/functions/", 1)

	resp, err := svc.Projects.Locations.Functions.GenerateDownloadUrl(functionName, &cloudfunctions.GenerateDownloadUrlRequest{}).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("generating download URL for gen2 function %s: %w", functionName, err)
	}

	if resp.DownloadUrl == "" {
		return nil
	}

	return downloadAndExtractZip(r, resp.DownloadUrl, out)
}
