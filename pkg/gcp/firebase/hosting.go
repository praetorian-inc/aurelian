package firebase

import (
	"fmt"
	"log/slog"

	"google.golang.org/api/firebasehosting/v1beta1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// HostingLister enumerates Firebase Hosting sites in a GCP project.
type HostingLister struct {
	clientOptions []option.ClientOption
}

// NewHostingLister creates a HostingLister with the given client options.
func NewHostingLister(clientOptions []option.ClientOption) *HostingLister {
	return &HostingLister{clientOptions: clientOptions}
}

// List enumerates all Firebase Hosting sites for the given project.
func (l *HostingLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := firebasehosting.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating firebase hosting client: %w", err)
	}

	resp, err := svc.Projects.Sites.List("projects/" + projectID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping firebase hosting", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing firebase hosting sites: %w", err)
	}

	for _, site := range resp.Sites {
		r := output.NewGCPResource(projectID, "firebasehosting.googleapis.com/Site", site.Name)
		r.DisplayName = site.Name

		if site.DefaultUrl != "" {
			r.URLs = []string{site.DefaultUrl}
		}

		r.Properties = map[string]any{
			"type":  site.Type,
			"appId": site.AppId,
		}
		out.Send(r)
	}
	return nil
}
