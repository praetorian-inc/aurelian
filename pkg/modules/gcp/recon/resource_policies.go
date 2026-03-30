package recon

import (
	"context"
	"fmt"
	"log/slog"

	asset "cloud.google.com/go/asset/apiv1"
	assetpb "cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPResourcePoliciesModule{})
}

type GCPResourcePoliciesConfig struct {
	plugin.GCPCommonRecon
}

type GCPResourcePoliciesModule struct {
	GCPResourcePoliciesConfig
}

func (m *GCPResourcePoliciesModule) ID() string                { return "resource-policies" }
func (m *GCPResourcePoliciesModule) Name() string              { return "GCP Resource IAM Policies" }
func (m *GCPResourcePoliciesModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPResourcePoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPResourcePoliciesModule) OpsecLevel() string        { return "moderate" }
func (m *GCPResourcePoliciesModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPResourcePoliciesModule) Description() string {
	return "Enumerate all IAM policy bindings across GCP resources using Cloud Asset Inventory SearchAllIamPolicies."
}
func (m *GCPResourcePoliciesModule) References() []string {
	return []string{"https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies"}
}
func (m *GCPResourcePoliciesModule) SupportedResourceTypes() []string { return nil }
func (m *GCPResourcePoliciesModule) Parameters() any                  { return &m.GCPResourcePoliciesConfig }

func (m *GCPResourcePoliciesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPResourcePoliciesConfig

	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs: c.OrgID, FolderIDs: c.FolderID, ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	// Collect scopes (projects, orgs, folders) for IAM policy search
	scopes := pipeline.New[string]()
	pipeline.Pipe(resolved, func(res output.GCPResource, p *pipeline.P[string]) error {
		switch res.ResourceType {
		case "projects":
			p.Send("projects/" + res.ProjectID)
		case "organizations":
			p.Send("organizations/" + res.ResourceID)
		case "folders":
			p.Send("folders/" + res.ResourceID)
		}
		return nil
	}, scopes)

	pipeline.Pipe(scopes, func(scope string, p *pipeline.P[model.AurelianModel]) error {
		return m.searchPolicies(cfg, scope, p)
	}, out)

	return out.Wait()
}

func (m *GCPResourcePoliciesModule) searchPolicies(cfg plugin.Config, scope string, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	client, err := asset.NewClient(ctx, m.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating asset client: %w", err)
	}
	defer client.Close()

	cfg.Info("searching IAM policies in scope %s", scope)

	it := client.SearchAllIamPolicies(ctx, &assetpb.SearchAllIamPoliciesRequest{
		Scope: scope,
	})

	count := 0
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				slog.Debug("skipping IAM policy search", "scope", scope, "reason", err)
				cfg.Warn("skipping %s: %v", scope, err)
				return nil
			}
			return fmt.Errorf("iterating IAM policies in %s: %w", scope, err)
		}

		if result.Policy == nil {
			continue
		}

		for _, binding := range result.Policy.Bindings {
			res := output.NewGCPResource("", "iam.googleapis.com/Policy", result.Resource)
			res.Properties = map[string]any{
				"resource":  result.Resource,
				"assetType": result.AssetType,
				"role":      binding.Role,
				"members":   binding.Members,
			}
			if result.Project != "" {
				res.ProjectID = result.Project
			}
			out.Send(res)
			count++
		}
	}

	cfg.Success("found %d IAM bindings in %s", count, scope)
	return nil
}
