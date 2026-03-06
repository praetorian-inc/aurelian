package hierarchy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
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

// HierarchyResolverInput specifies the GCP scopes to resolve.
type HierarchyResolverInput struct {
	OrgIDs     []string
	FolderIDs  []string
	ProjectIDs []string
}

// Resolve discovers all orgs, folders, and projects from the given input,
// emitting each as a GCPResource into the pipeline.
func (r *Resolver) Resolve(input HierarchyResolverInput, out *pipeline.P[output.GCPResource]) error {
	for _, orgID := range input.OrgIDs {
		if err := r.resolveOrg(orgID, out); err != nil {
			return fmt.Errorf("resolve org %s: %w", orgID, err)
		}
	}

	for _, folderID := range input.FolderIDs {
		if err := r.resolveFolder(folderID, out); err != nil {
			return fmt.Errorf("resolve folder %s: %w", folderID, err)
		}
	}

	for _, projectID := range input.ProjectIDs {
		if err := r.resolveProject(projectID, out); err != nil {
			return fmt.Errorf("resolve project %s: %w", projectID, err)
		}
	}

	return nil
}

func (r *Resolver) resolveOrg(orgID string, out *pipeline.P[output.GCPResource]) error {
	ctx := context.Background()
	svc, err := crmv1.NewService(ctx, r.clientOptions...)
	if err != nil {
		return fmt.Errorf("create CRM service: %w", err)
	}

	org, err := svc.Organizations.Get("organizations/" + orgID).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get organization: %w", err)
	}
	out.Send(output.GCPResource{
		ResourceType: "organizations",
		ResourceID:   "organizations/" + orgID,
		DisplayName:  org.DisplayName,
		Properties:   map[string]any{"lifecycleState": org.LifecycleState},
	})

	folderSvc, err := crmv2.NewService(ctx, r.clientOptions...)
	if err != nil {
		return fmt.Errorf("create CRM v2 service: %w", err)
	}
	if err := r.listFoldersRecursive(folderSvc, "organizations/"+orgID, out); err != nil {
		slog.Warn("failed to list folders", "org", orgID, "error", err)
	}

	return r.listProjectsUnderParent(svc, "organizations/"+orgID, out)
}

func (r *Resolver) resolveFolder(folderID string, out *pipeline.P[output.GCPResource]) error {
	ctx := context.Background()
	svc, err := crmv1.NewService(ctx, r.clientOptions...)
	if err != nil {
		return fmt.Errorf("create CRM service: %w", err)
	}

	folderSvc, err := crmv2.NewService(ctx, r.clientOptions...)
	if err != nil {
		return fmt.Errorf("create CRM v2 service: %w", err)
	}

	parent := "folders/" + folderID
	folder, err := folderSvc.Folders.Get(parent).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get folder: %w", err)
	}
	out.Send(output.GCPResource{
		ResourceType: "folders",
		ResourceID:   parent,
		DisplayName:  folder.DisplayName,
		Properties:   map[string]any{"lifecycleState": folder.LifecycleState},
	})

	if err := r.listFoldersRecursive(folderSvc, parent, out); err != nil {
		slog.Warn("failed to list subfolders", "folder", folderID, "error", err)
	}

	return r.listProjectsUnderParent(svc, parent, out)
}

// resolveProject hydrates a bare project ID via the CRM API, emitting it as a
// GCPResource. On API failure, warns and emits a minimal resource with just the ID.
func (r *Resolver) resolveProject(projectID string, out *pipeline.P[output.GCPResource]) error {
	ctx := context.Background()

	svc, err := crmv1.NewService(ctx, r.clientOptions...)
	if err != nil {
		return fmt.Errorf("create CRM service: %w", err)
	}

	p, err := svc.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		slog.Warn("failed to hydrate project metadata, emitting minimal resource", "project", projectID, "error", err)
		out.Send(output.GCPResource{
			ResourceType: "projects",
			ResourceID:   "projects/" + projectID,
			ProjectID:    projectID,
		})
		return nil
	}

	out.Send(output.GCPResource{
		ResourceType: "projects",
		ResourceID:   "projects/" + p.ProjectId,
		ProjectID:    p.ProjectId,
		DisplayName:  p.Name,
		Properties:   map[string]any{"projectNumber": p.ProjectNumber},
	})
	return nil
}

func (r *Resolver) listFoldersRecursive(svc *crmv2.Service, parent string, out *pipeline.P[output.GCPResource]) error {
	ctx := context.Background()
	paginator := ratelimit.NewGCPPaginator()
	var pageToken string

	return paginator.Paginate(func() (bool, error) {
		resp, err := svc.Folders.List().Parent(parent).PageToken(pageToken).Context(ctx).Do()
		if err != nil {
			return false, err
		}
		for _, f := range resp.Folders {
			out.Send(output.GCPResource{
				ResourceType: "folders",
				ResourceID:   f.Name,
				DisplayName:  f.DisplayName,
				Properties:   map[string]any{"lifecycleState": f.LifecycleState, "parent": f.Parent},
			})
			if err := r.listFoldersRecursive(svc, f.Name, out); err != nil {
				slog.Warn("failed to list subfolders", "folder", f.Name, "error", err)
			}
		}
		pageToken = resp.NextPageToken
		return pageToken != "", nil
	})
}

func (r *Resolver) listProjectsUnderParent(svc *crmv1.Service, parent string, out *pipeline.P[output.GCPResource]) error {
	ctx := context.Background()
	paginator := ratelimit.NewGCPPaginator()

	var filter string
	if strings.HasPrefix(parent, "organizations/") {
		filter = fmt.Sprintf("parent.type:organization parent.id:%s", extractID(parent))
	} else {
		filter = fmt.Sprintf("parent.type:folder parent.id:%s", extractID(parent))
	}

	var pageToken string
	return paginator.Paginate(func() (bool, error) {
		resp, err := svc.Projects.List().Filter(filter).PageToken(pageToken).Context(ctx).Do()
		if err != nil {
			return false, err
		}
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
		}
		pageToken = resp.NextPageToken
		return pageToken != "", nil
	})
}

func extractID(resourceName string) string {
	if _, after, ok := strings.Cut(resourceName, "/"); ok {
		return after
	}
	return resourceName
}
