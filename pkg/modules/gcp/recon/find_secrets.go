package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/gcp/extraction"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
)

func init() {
	plugin.Register(&GCPFindSecretsModule{})
}

// GCPFindSecretsConfig holds the typed parameters for the GCP find-secrets module.
type GCPFindSecretsConfig struct {
	plugin.GCPCommonRecon
	secrets.ScannerConfig
	OutputDir string `param:"output-dir" desc:"Base output directory" default:"aurelian-output"`
}

// GCPFindSecretsModule scans GCP resources for hardcoded secrets using Titus.
type GCPFindSecretsModule struct {
	GCPFindSecretsConfig
}

func (m *GCPFindSecretsModule) ID() string                { return "find-secrets" }
func (m *GCPFindSecretsModule) Name() string              { return "GCP Find Secrets" }
func (m *GCPFindSecretsModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPFindSecretsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPFindSecretsModule) OpsecLevel() string        { return "moderate" }
func (m *GCPFindSecretsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPFindSecretsModule) Description() string {
	return "Enumerates GCP resources via project hierarchy, extracts content likely to contain " +
		"hardcoded secrets (Compute metadata/startup scripts, Cloud Functions source, " +
		"Cloud Run environment variables, App Engine environment variables), and scans with Titus."
}

func (m *GCPFindSecretsModule) References() []string {
	return []string{
		"https://cloud.google.com/apis/docs/overview",
	}
}

func (m *GCPFindSecretsModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPFindSecretsModule) Parameters() any {
	return &m.GCPFindSecretsConfig
}

// secretsResourceTypes are the GCP resource types that contain extractable secret content.
var secretsResourceTypes = []string{
	"compute.googleapis.com/Instance",
	"cloudfunctions.googleapis.com/Function",
	"run.googleapis.com/Service",
	"appengine.googleapis.com/Version",
	"storage.googleapis.com/Bucket",
}

func (m *GCPFindSecretsModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPFindSecretsConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	// Resolve hierarchy: org/folder/project → project IDs.
	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs:     c.OrgID,
		FolderIDs:  c.FolderID,
		ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	// Split: forward project IDs for enumeration.
	projects := pipeline.New[string]()
	pipeline.Pipe(resolved, splitHierarchyResources, projects)

	// Enumerate secrets-relevant resource types per project.
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes(secretsResourceTypes)
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, enumerator.ListForProject, listed)

	// Extract content from resources.
	extractor := extraction.NewGCPExtractor(c.GCPCommonRecon)
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted)

	// Scan for secrets.
	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)

	return out.Wait()
}

func splitHierarchyResources(res output.GCPResource, p *pipeline.P[string]) error {
	if res.ResourceType == "projects" {
		p.Send(res.ProjectID)
	}
	return nil
}

