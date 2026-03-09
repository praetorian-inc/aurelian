package extraction

import (
	"fmt"

	"google.golang.org/api/appengine/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("appengine.googleapis.com/Version", "env-vars", extractAppEngineEnvVars)
}

// extractAppEngineEnvVars extracts environment variables from an App Engine version.
func extractAppEngineEnvVars(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := appengine.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating appengine client: %w", err)
	}

	serviceID, _ := r.Properties["service"].(string)
	if serviceID == "" {
		return fmt.Errorf("app engine version %s missing service property", r.ResourceID)
	}

	version, err := svc.Apps.Services.Versions.Get(r.ProjectID, serviceID, r.ResourceID).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("getting app engine version %s/%s: %w", serviceID, r.ResourceID, err)
	}

	var envContent []byte
	for k, v := range version.EnvVariables {
		envContent = append(envContent, []byte(k+"="+v+"\n")...)
	}
	if len(envContent) > 0 {
		out.Send(output.ScanInputFromGCPResource(r, "env-vars", envContent))
	}
	return nil
}
