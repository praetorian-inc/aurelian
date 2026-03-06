package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	crmv2 "google.golang.org/api/cloudresourcemanager/v2"
	"google.golang.org/api/option"
)

// Resolver discovers GCP projects under org/folder scopes.
type Resolver struct {
	clientOptions      []option.ClientOption
	includeSysProjects bool
	concurrency        int
}

// NewResolver creates a hierarchy resolver from GCP common recon options.
func NewResolver(opts plugin.GCPCommonRecon) *Resolver {
	return &Resolver{
		clientOptions:      opts.ClientOptions,
		includeSysProjects: opts.IncludeSysProjects,
		concurrency:        opts.Concurrency,
	}
}

// ResolveProjects resolves all scope inputs (org IDs, folder IDs, project IDs) into
// a flat list of project IDs, emitting hierarchy resources along the way.
func (r *Resolver) ResolveProjects(
	ctx context.Context,
	orgIDs, folderIDs, projectIDs []string,
	out *pipeline.P[output.GCPResource],
) ([]string, error) {
	var allProjects []string

	for _, orgID := range orgIDs {
		projects, err := r.resolveOrg(ctx, orgID, out)
		if err != nil {
			return nil, fmt.Errorf("resolve org %s: %w", orgID, err)
		}
		allProjects = append(allProjects, projects...)
	}

	for _, folderID := range folderIDs {
		projects, err := r.resolveFolder(ctx, folderID, out)
		if err != nil {
			return nil, fmt.Errorf("resolve folder %s: %w", folderID, err)
		}
		allProjects = append(allProjects, projects...)
	}

	allProjects = append(allProjects, projectIDs...)
	return allProjects, nil
}

// ResolveAndEmit resolves projects from org/folder/project scopes, emitting
// hierarchy resources into out as they're discovered. Returns the resolved
// project IDs.
func (r *Resolver) ResolveAndEmit(
	orgIDs, folderIDs, projectIDs []string,
	out *pipeline.P[model.AurelianModel],
) ([]string, error) {
	hierarchyOut := pipeline.New[output.GCPResource]()

	var projects []string
	var resolveErr error
	go func() {
		defer hierarchyOut.Close()
		projects, resolveErr = r.ResolveProjects(
			context.Background(),
			orgIDs, folderIDs, projectIDs,
			hierarchyOut,
		)
	}()

	for res := range hierarchyOut.Range() {
		out.Send(res)
	}
	return projects, resolveErr
}

func (r *Resolver) resolveOrg(ctx context.Context, orgID string, out *pipeline.P[output.GCPResource]) ([]string, error) {
	svc, err := crmv1.NewService(ctx, r.clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create CRM service: %w", err)
	}

	org, err := svc.Organizations.Get("organizations/" + orgID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get organization: %w", err)
	}
	out.Send(output.GCPResource{
		ResourceType: "organizations",
		ResourceID:   "organizations/" + orgID,
		DisplayName:  org.DisplayName,
		Properties:   map[string]any{"lifecycleState": org.LifecycleState},
	})

	folderSvc, err := crmv2.NewService(ctx, r.clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create CRM v2 service: %w", err)
	}
	_, err = r.listFoldersRecursive(ctx, folderSvc, "organizations/"+orgID, out)
	if err != nil {
		slog.Warn("failed to list folders", "org", orgID, "error", err)
	}

	return r.listProjectsUnderParent(ctx, svc, "organizations/"+orgID, out)
}

func (r *Resolver) resolveFolder(ctx context.Context, folderID string, out *pipeline.P[output.GCPResource]) ([]string, error) {
	svc, err := crmv1.NewService(ctx, r.clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create CRM service: %w", err)
	}

	folderSvc, err := crmv2.NewService(ctx, r.clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("create CRM v2 service: %w", err)
	}

	parent := "folders/" + folderID
	folder, err := folderSvc.Folders.Get(parent).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("get folder: %w", err)
	}
	out.Send(output.GCPResource{
		ResourceType: "folders",
		ResourceID:   parent,
		DisplayName:  folder.DisplayName,
		Properties:   map[string]any{"lifecycleState": folder.LifecycleState},
	})

	_, err = r.listFoldersRecursive(ctx, folderSvc, parent, out)
	if err != nil {
		slog.Warn("failed to list subfolders", "folder", folderID, "error", err)
	}

	return r.listProjectsUnderParent(ctx, svc, parent, out)
}

func (r *Resolver) listFoldersRecursive(ctx context.Context, svc *crmv2.Service, parent string, out *pipeline.P[output.GCPResource]) ([]string, error) {
	var folderIDs []string
	err := svc.Folders.List().Parent(parent).Context(ctx).Pages(ctx, func(resp *crmv2.ListFoldersResponse) error {
		for _, f := range resp.Folders {
			out.Send(output.GCPResource{
				ResourceType: "folders",
				ResourceID:   f.Name,
				DisplayName:  f.DisplayName,
				Properties:   map[string]any{"lifecycleState": f.LifecycleState, "parent": f.Parent},
			})
			folderIDs = append(folderIDs, f.Name)
			subFolders, err := r.listFoldersRecursive(ctx, svc, f.Name, out)
			if err != nil {
				slog.Warn("failed to list subfolders", "folder", f.Name, "error", err)
			}
			folderIDs = append(folderIDs, subFolders...)
		}
		return nil
	})
	return folderIDs, err
}

func (r *Resolver) listProjectsUnderParent(ctx context.Context, svc *crmv1.Service, parent string, out *pipeline.P[output.GCPResource]) ([]string, error) {
	var projectIDs []string

	var filter string
	if strings.HasPrefix(parent, "organizations/") {
		filter = fmt.Sprintf("parent.type:organization parent.id:%s", extractID(parent))
	} else {
		filter = fmt.Sprintf("parent.type:folder parent.id:%s", extractID(parent))
	}

	err := svc.Projects.List().Filter(filter).Context(ctx).Pages(ctx, func(resp *crmv1.ListProjectsResponse) error {
		for _, p := range resp.Projects {
			if p.LifecycleState != "ACTIVE" {
				continue
			}
			if !r.includeSysProjects && plugin.IsSystemProject(p.ProjectId) {
				slog.Debug("skipping system project", "project", p.ProjectId)
				continue
			}
			out.Send(output.GCPResource{
				ResourceType: "projects",
				ResourceID:   "projects/" + p.ProjectId,
				ProjectID:    p.ProjectId,
				DisplayName:  p.Name,
				Properties:   map[string]any{"projectNumber": p.ProjectNumber},
			})
			projectIDs = append(projectIDs, p.ProjectId)
		}
		return nil
	})
	return projectIDs, err
}

func extractID(resourceName string) string {
	if _, after, ok := strings.Cut(resourceName, "/"); ok {
		return after
	}
	return resourceName
}
