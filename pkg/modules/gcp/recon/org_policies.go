package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	orgpolicy "cloud.google.com/go/orgpolicy/apiv2"
	orgpolicypb "cloud.google.com/go/orgpolicy/apiv2/orgpolicypb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPOrgPoliciesModule{})
}

// GCPOrgPoliciesConfig holds parameters for the GCP org-policies module.
type GCPOrgPoliciesConfig struct {
	plugin.GCPCommonRecon
}

// GCPOrgPoliciesModule enumerates organization policy constraints and their
// effective policies across GCP organizations, folders, and projects.
type GCPOrgPoliciesModule struct {
	GCPOrgPoliciesConfig
}

func (m *GCPOrgPoliciesModule) ID() string                { return "org-policies" }
func (m *GCPOrgPoliciesModule) Name() string              { return "GCP Organization Policies" }
func (m *GCPOrgPoliciesModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPOrgPoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPOrgPoliciesModule) OpsecLevel() string        { return "moderate" }
func (m *GCPOrgPoliciesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPOrgPoliciesModule) Description() string {
	return "Enumerate organization policy constraints and their effective policies " +
		"across GCP organizations, folders, and projects."
}

func (m *GCPOrgPoliciesModule) References() []string {
	return []string{"https://cloud.google.com/resource-manager/docs/organization-policy/overview"}
}

func (m *GCPOrgPoliciesModule) SupportedResourceTypes() []string {
	return []string{"orgpolicy.googleapis.com/Policy"}
}

func (m *GCPOrgPoliciesModule) Parameters() any {
	return &m.GCPOrgPoliciesConfig
}

func (m *GCPOrgPoliciesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPOrgPoliciesConfig

	// Resolve hierarchy to discover projects.
	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs:     c.OrgID,
		FolderIDs:  c.FolderID,
		ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	// Collect all scopes to query: orgs, folders, and projects.
	scopes := pipeline.New[string]()
	pipeline.Pipe(resolved, m.extractScopes(c), scopes)

	// For each scope, list constraints and get effective policies.
	pipeline.Pipe(scopes, m.enumeratePolicies(c.ClientOptions), out)

	return out.Wait()
}

// extractScopes returns a pipeline function that extracts scope strings
// (e.g. "projects/my-project", "organizations/123", "folders/456") from
// hierarchy resources. It also adds org and folder scopes from the config.
func (m *GCPOrgPoliciesModule) extractScopes(c GCPOrgPoliciesConfig) func(output.GCPResource, *pipeline.P[string]) error {
	emittedOrgs := make(map[string]bool)
	emittedFolders := make(map[string]bool)

	// Pre-mark config-level orgs and folders so they are emitted once
	// from hierarchy resources rather than duplicated.
	for _, orgID := range c.OrgID {
		emittedOrgs[orgID] = false
	}
	for _, folderID := range c.FolderID {
		emittedFolders[folderID] = false
	}

	return func(res output.GCPResource, p *pipeline.P[string]) error {
		switch res.ResourceType {
		case "organizations":
			orgID := extractResourceID(res.ResourceID)
			if !emittedOrgs[orgID] {
				emittedOrgs[orgID] = true
				p.Send("organizations/" + orgID)
			}
		case "folders":
			folderID := extractResourceID(res.ResourceID)
			if !emittedFolders[folderID] {
				emittedFolders[folderID] = true
				p.Send("folders/" + folderID)
			}
		case "projects":
			if res.ProjectID != "" {
				p.Send("projects/" + res.ProjectID)
			}
		}
		return nil
	}
}

// enumeratePolicies returns a pipeline function that, for each scope, lists
// all constraints and retrieves their effective policies.
func (m *GCPOrgPoliciesModule) enumeratePolicies(clientOpts []option.ClientOption) func(string, *pipeline.P[model.AurelianModel]) error {
	return func(scope string, out *pipeline.P[model.AurelianModel]) error {
		ctx := context.Background()
		client, err := orgpolicy.NewClient(ctx, clientOpts...)
		if err != nil {
			return fmt.Errorf("create orgpolicy client: %w", err)
		}
		defer client.Close()

		// List all constraints for this scope.
		iter := client.ListConstraints(ctx, &orgpolicypb.ListConstraintsRequest{
			Parent: scope,
		})

		for {
			constraint, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if gcperrors.IsDisabledAPI(err) {
					slog.Warn("Organization Policy API not enabled — enable orgpolicy.googleapis.com or use --quota-project", "scope", scope)
				} else if gcperrors.IsPermissionDenied(err) {
					slog.Warn("permission denied listing org policy constraints — ensure roles/orgpolicy.policyViewer is granted", "scope", scope)
				} else {
					slog.Warn("failed to list constraints", "scope", scope, "error", err)
				}
				break
			}

			constraintName := constraint.GetName()
			properties := map[string]any{
				"constraint_name": constraintName,
				"constraint_type": constraint.GetConstraintDefault().String(),
				"description":     constraint.GetDescription(),
				"display_name":    constraint.GetDisplayName(),
				"supports_under":  constraint.GetSupportsDryRun(),
				"scope":           scope,
			}

			// Get the effective (inherited+merged) policy for this constraint.
			policyName := scope + "/policies/" + extractConstraintShortName(constraintName)
			effectivePolicy, err := client.GetEffectivePolicy(ctx, &orgpolicypb.GetEffectivePolicyRequest{
				Name: policyName,
			})
			if err != nil {
				slog.Debug("failed to get effective policy", "policy", policyName, "error", err)
				properties["effective_policy_error"] = err.Error()
			} else {
				properties["effective_policy"] = effectivePolicyToMap(effectivePolicy)
			}

			scopeID := extractResourceID(scope)

			out.Send(output.GCPResource{
				ResourceType: "orgpolicy.googleapis.com/Policy",
				ResourceID:   constraintName,
				ProjectID:    scopeID,
				Properties:   properties,
			})
		}

		return nil
	}
}

// extractResourceID extracts the ID portion from a resource name like
// "organizations/123" -> "123" or "projects/my-proj" -> "my-proj".
func extractResourceID(resourceName string) string {
	if _, after, ok := strings.Cut(resourceName, "/"); ok {
		return after
	}
	return resourceName
}

// extractConstraintShortName extracts the short constraint name from its full
// resource name. e.g. "constraints/compute.disableSerialPortAccess" ->
// "compute.disableSerialPortAccess".
func extractConstraintShortName(constraintName string) string {
	if _, after, ok := strings.Cut(constraintName, "/"); ok {
		return after
	}
	return constraintName
}

// effectivePolicyToMap converts an OrgPolicy proto message into a plain map
// for storage in GCPResource.Properties.
func effectivePolicyToMap(policy *orgpolicypb.Policy) map[string]any {
	m := map[string]any{
		"name": policy.GetName(),
	}

	if spec := policy.GetSpec(); spec != nil {
		specMap := map[string]any{
			"etag":                spec.GetEtag(),
			"update_time":        spec.GetUpdateTime().AsTime().String(),
			"inherit_from_parent": spec.GetInheritFromParent(),
			"reset":              spec.GetReset_(),
		}

		var rules []map[string]any
		for _, rule := range spec.GetRules() {
			ruleMap := map[string]any{}
			if v := rule.GetValues(); v != nil {
				ruleMap["allowed_values"] = v.GetAllowedValues()
				ruleMap["denied_values"] = v.GetDeniedValues()
			}
			if rule.GetAllowAll() {
				ruleMap["allow_all"] = true
			}
			if rule.GetDenyAll() {
				ruleMap["deny_all"] = true
			}
			if rule.GetEnforce() {
				ruleMap["enforce"] = true
			}
			if cond := rule.GetCondition(); cond != nil {
				ruleMap["condition"] = map[string]any{
					"expression":  cond.GetExpression(),
					"title":       cond.GetTitle(),
					"description": cond.GetDescription(),
				}
			}
			rules = append(rules, ruleMap)
		}
		specMap["rules"] = rules
		m["spec"] = specMap
	}

	return m
}
