package recon

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/gcp/iam"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPPrivescDetectionModule{})
}

// GCPPrivescDetectionConfig holds parameters for the privilege escalation
// detection module.
type GCPPrivescDetectionConfig struct {
	plugin.GCPCommonRecon
}

// GCPPrivescDetectionModule detects GCP privilege escalation paths using the
// testIamPermissions API.
type GCPPrivescDetectionModule struct {
	GCPPrivescDetectionConfig
}

func (m *GCPPrivescDetectionModule) ID() string                { return "privesc-detection" }
func (m *GCPPrivescDetectionModule) Name() string              { return "GCP Privilege Escalation Detection" }
func (m *GCPPrivescDetectionModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPPrivescDetectionModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPPrivescDetectionModule) OpsecLevel() string        { return "stealth" }
func (m *GCPPrivescDetectionModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPPrivescDetectionModule) Parameters() any           { return &m.GCPPrivescDetectionConfig }

func (m *GCPPrivescDetectionModule) Description() string {
	return "Detect GCP privilege escalation paths by testing IAM permissions on projects. " +
		"Uses testIamPermissions API which does not generate audit logs."
}

func (m *GCPPrivescDetectionModule) References() []string {
	return []string{
		"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/",
		"https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-2/",
	}
}

func (m *GCPPrivescDetectionModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPPrivescDetectionModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPPrivescDetectionConfig

	checker, err := iam.NewPermissionChecker(c.ClientOptions)
	if err != nil {
		return fmt.Errorf("creating permission checker: %w", err)
	}

	cfg.Info("scanning projects for privilege escalation paths")

	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs:     c.OrgID,
		FolderIDs:  c.FolderID,
		ProjectIDs: c.ProjectID,
	}

	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	projects := pipeline.New[string]()
	pipeline.Pipe(resolved, filterProjects, projects)

	allPerms := iam.AllPrivescPermissions()

	checkProject := func(projectID string, results *pipeline.P[model.AurelianModel]) error {
		granted, err := checker.TestPermissions(projectID, allPerms)
		if err != nil {
			slog.Warn("failed to test permissions", "project", projectID, "error", err)
			return nil
		}

		matched := iam.MatchPaths(granted)
		for _, path := range matched {
			ctx, err := json.Marshal(map[string]any{
				"project_id":          projectID,
				"path_name":           path.Name,
				"description":         path.Description,
				"granted_permissions": path.Permissions,
				"remediation":         path.Remediation,
				"references":          path.References,
			})
			if err != nil {
				return fmt.Errorf("marshaling context: %w", err)
			}

			results.Send(output.AurelianRisk{
				Name:               path.Name,
				Severity:           path.Severity,
				ImpactedResourceID: fmt.Sprintf("projects/%s", projectID),
				DeduplicationID:    fmt.Sprintf("privesc:%s:%s", projectID, path.Name),
				Context:            ctx,
			})
		}
		return nil
	}

	pipeline.Pipe(projects, checkProject, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking privilege escalation paths"),
		Concurrency: c.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("privilege escalation scan complete")
	return nil
}
