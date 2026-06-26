package enumeration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

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
	svc, err := appengine.NewService(context.Background(), l.clientOptions...)
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
	err = svc.Apps.Services.List(projectID).Pages(context.Background(), func(resp *appengine.ListServicesResponse) error {
		for _, service := range resp.Services {
			sendAppEngineService(projectID, app, service, out)

			// List versions for each service.
			err := svc.Apps.Services.Versions.List(projectID, service.Id).Pages(context.Background(), func(vResp *appengine.ListVersionsResponse) error {
				for _, version := range vResp.Versions {
					sendAppEngineVersion(projectID, service.Id, version, out)
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

func (l *AppEngineLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := appengine.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating appengine client: %w", err)
	}
	app, err := svc.Apps.Get(input.ProjectID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping app engine", "project", input.ProjectID, "reason", err)
			return nil
		}
		return fmt.Errorf("getting app engine app: %w", err)
	}

	if input.ResourceType == "appengine.googleapis.com/Version" {
		serviceID, versionID, err := parseAppEngineVersionResourceID(input.ProjectID, input.ResourceID)
		if err != nil {
			return err
		}
		version, err := svc.Apps.Services.Versions.Get(input.ProjectID, serviceID, versionID).Do()
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				slog.Debug("skipping app engine version", "project", input.ProjectID, "service", serviceID, "version", versionID, "reason", err)
				return nil
			}
			return fmt.Errorf("getting app engine version %s/%s: %w", serviceID, versionID, err)
		}
		sendAppEngineVersion(input.ProjectID, serviceID, version, out)
		return nil
	}

	serviceID := parseAppEngineServiceResourceID(input.ResourceID)
	service, err := svc.Apps.Services.Get(input.ProjectID, serviceID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping app engine service", "project", input.ProjectID, "service", serviceID, "reason", err)
			return nil
		}
		return fmt.Errorf("getting app engine service %s: %w", serviceID, err)
	}
	sendAppEngineService(input.ProjectID, app, service, out)
	return nil
}

func (l *AppEngineLister) ResourceTypes() []string {
	return []string{"appengine.googleapis.com/Service", "appengine.googleapis.com/Version"}
}

func sendAppEngineService(projectID string, app *appengine.Application, service *appengine.Service, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "appengine.googleapis.com/Service", service.Id)
	r.DisplayName = service.Id

	if app.DefaultHostname != "" {
		r.URLs = []string{"https://" + app.DefaultHostname}
	}

	r.Properties = map[string]any{
		"servingStatus": app.ServingStatus,
	}
	out.Send(r)
}

func sendAppEngineVersion(projectID, serviceID string, version *appengine.Version, out *pipeline.P[output.GCPResource]) {
	vr := output.NewGCPResource(projectID, "appengine.googleapis.com/Version", version.Id)
	vr.DisplayName = version.Id
	vr.Properties = map[string]any{
		"servingStatus": version.ServingStatus,
		"runtime":       version.Runtime,
		"env":           version.Env,
		"service":       serviceID,
	}

	if version.VersionUrl != "" {
		vr.URLs = []string{version.VersionUrl}
	}

	out.Send(vr)
}

func parseAppEngineServiceResourceID(resourceID string) string {
	if serviceID, ok := pathSegment(resourceID, "services"); ok {
		return serviceID
	}
	return lastPathPart(resourceID)
}

func parseAppEngineVersionResourceID(projectID, resourceID string) (string, string, error) {
	if serviceID, ok := pathSegment(resourceID, "services"); ok {
		if versionID, ok := pathSegment(resourceID, "versions"); ok {
			return serviceID, versionID, nil
		}
	}
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return "", "", newResourceIDError("appengine.googleapis.com/Version", resourceID, fmt.Sprintf("service/version or a full path like projects/%s/services/{service}/versions/{version}", projectID))
}
