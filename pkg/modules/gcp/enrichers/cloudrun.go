package enrichers

import (
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	run "google.golang.org/api/run/v2"
)

func init() {
	plugin.RegisterGCPEnricher("run.googleapis.com/Service", enrichCloudRunIAMWrapper)
}

func enrichCloudRunIAMWrapper(cfg plugin.GCPEnricherConfig, r *output.GCPResource) error {
	svc, err := run.NewService(cfg.Context, cfg.ClientOptions...)
	if err != nil {
		return err
	}

	policy, err := svc.Projects.Locations.Services.GetIamPolicy(r.ResourceID).Context(cfg.Context).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping cloud run IAM", "resource", r.ResourceID, "error", err)
			return nil
		}
		return err
	}

	var bindings []iamBinding
	for _, b := range policy.Bindings {
		bindings = append(bindings, iamBinding{Role: b.Role, Members: b.Members})
	}
	enrichIAMBindings(r, bindings)
	return nil
}
