package recon

import (
	"fmt"
	"log/slog"
	"slices"

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
	return append(slices.Clone(supportedInputTypes), secretsResourceTypes...)
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

	var listed *pipeline.P[output.GCPResource]
	var err error
	if len(c.ResourceID) > 0 {
		listed, err = m.listByResourceID(c)
		if err != nil {
			return err
		}
	} else {
		listed = m.listByHierarchy(c)
	}

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

func (m *GCPFindSecretsModule) listByHierarchy(c GCPFindSecretsConfig) *pipeline.P[output.GCPResource] {
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
	return listed
}

func (m *GCPFindSecretsModule) listByResourceID(c GCPFindSecretsConfig) (*pipeline.P[output.GCPResource], error) {
	if len(c.ProjectID) != 1 {
		return nil, fmt.Errorf("direct GCP resource scanning requires exactly one --project-id")
	}
	if len(c.ResourceType) != 1 || c.ResourceType[0] == "all" {
		return nil, fmt.Errorf("direct GCP resource scanning requires exactly one --resource-type")
	}
	resourceType := c.ResourceType[0]
	if resolved, err := resolveAlias(resourceType); err == nil {
		resourceType = resolved
	}
	if !slices.Contains(secretsResourceTypes, resourceType) {
		return nil, fmt.Errorf("resource type %q is not supported for direct GCP secret scanning", resourceType)
	}

	inputs := make([]enumeration.ResourceIDInput, 0, len(c.ResourceID))
	for _, resourceID := range c.ResourceID {
		inputs = append(inputs, enumeration.ResourceIDInput{
			ProjectID:    c.ProjectID[0],
			ResourceType: resourceType,
			ResourceID:   resourceID,
		})
	}

	inputStream := pipeline.From(inputs...)
	listed := pipeline.New[output.GCPResource]()
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon)
	pipeline.Pipe(inputStream, enumerator.ListByResourceID, listed, &pipeline.PipeOpts{Concurrency: c.Concurrency})
	return listed, nil
}

func splitHierarchyResources(res output.GCPResource, p *pipeline.P[string]) error {
	if res.ResourceType == "projects" {
		p.Send(res.ProjectID)
	}
	return nil
}
