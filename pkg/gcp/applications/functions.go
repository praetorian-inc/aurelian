package applications

import (
	"fmt"
	"log/slog"

	"google.golang.org/api/cloudfunctions/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// FunctionLister enumerates Cloud Functions in a GCP project.
type FunctionLister struct {
	clientOptions []option.ClientOption
}

// NewFunctionLister creates a FunctionLister with the given client options.
func NewFunctionLister(clientOptions []option.ClientOption) *FunctionLister {
	return &FunctionLister{clientOptions: clientOptions}
}

// List enumerates all Cloud Functions across all locations for the given project.
func (l *FunctionLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := cloudfunctions.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloudfunctions client: %w", err)
	}

	parent := "projects/" + projectID + "/locations/-"
	err = svc.Projects.Locations.Functions.List(parent).Pages(nil, func(resp *cloudfunctions.ListFunctionsResponse) error {
		for _, fn := range resp.Functions {
			r := output.NewGCPResource(projectID, "cloudfunctions.googleapis.com/Function", fn.Name)
			r.DisplayName = fn.Name
			r.Labels = fn.Labels

			if fn.HttpsTrigger != nil && fn.HttpsTrigger.Url != "" {
				r.URLs = []string{fn.HttpsTrigger.Url}
			}

			r.Properties = map[string]any{
				"runtime":           fn.Runtime,
				"status":            fn.Status,
				"entryPoint":        fn.EntryPoint,
				"availableMemoryMb": fn.AvailableMemoryMb,
			}
			out.Send(r)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping cloud functions", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing cloud functions: %w", err)
	}
	return nil
}
