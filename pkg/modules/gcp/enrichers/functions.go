package enrichers

import (
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
)

func init() {
	plugin.RegisterGCPEnricher("cloudfunctions.googleapis.com/Function", enrichFunctionIAMWrapper)
}

func enrichFunctionIAMWrapper(cfg plugin.GCPEnricherConfig, r *output.GCPResource) error {
	svc, err := cloudfunctions.NewService(cfg.Context, cfg.ClientOptions...)
	if err != nil {
		return err
	}

	policy, err := svc.Projects.Locations.Functions.GetIamPolicy(r.ResourceID).Context(cfg.Context).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping function IAM", "resource", r.ResourceID, "error", err)
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
