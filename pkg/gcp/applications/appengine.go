package applications

import (
	"fmt"
	"log/slog"

	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// AppEngineLister enumerates App Engine services and versions in a GCP project.
type AppEngineLister struct {
	clientOptions []option.ClientOption
}

// NewAppEngineLister creates an AppEngineLister with the given client options.
func NewAppEngineLister(clientOptions []option.ClientOption) *AppEngineLister {
	return &AppEngineLister{clientOptions: clientOptions}
}

// List enumerates all App Engine services and their versions for the given project.
func (l *AppEngineLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := appengine.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating appengine client: %w", err)
	}

	// Get app info to check if App Engine is enabled.
	app, err := svc.Apps.Get(projectID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping app engine", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("getting app engine app: %w", err)
	}

	// List services.
	err = svc.Apps.Services.List(projectID).Pages(nil, func(resp *appengine.ListServicesResponse) error {
		for _, service := range resp.Services {
			r := output.NewGCPResource(projectID, "appengine.googleapis.com/Service", service.Id)
			r.DisplayName = service.Id

			if app.DefaultHostname != "" {
				r.URLs = []string{"https://" + app.DefaultHostname}
			}

			r.Properties = map[string]any{
				"servingStatus": app.ServingStatus,
			}
			out.Send(r)

			// List versions for each service.
			err := svc.Apps.Services.Versions.List(projectID, service.Id).Pages(nil, func(vResp *appengine.ListVersionsResponse) error {
				for _, version := range vResp.Versions {
					vr := output.NewGCPResource(projectID, "appengine.googleapis.com/Version", version.Id)
					vr.DisplayName = version.Id
					vr.Properties = map[string]any{
						"servingStatus": version.ServingStatus,
						"runtime":       version.Runtime,
						"env":           version.Env,
						"service":       service.Id,
					}

					if version.VersionUrl != "" {
						vr.URLs = []string{version.VersionUrl}
					}

					out.Send(vr)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping app engine versions", "project", projectID, "service", service.Id, "reason", err)
					continue
				}
				return fmt.Errorf("listing app engine versions for service %s: %w", service.Id, err)
			}
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping app engine services", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing app engine services: %w", err)
	}
	return nil
}
