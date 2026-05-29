package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	computeapi "google.golang.org/api/compute/v1"

	"github.com/praetorian-inc/aurelian/pkg/gcp/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
)

func init() {
	plugin.Register(&GCPSerialConsoleModule{})
}

// GCPSerialConsoleConfig holds the typed parameters for the GCP serial-console module.
type GCPSerialConsoleConfig struct {
	plugin.GCPCommonRecon
	secrets.ScannerConfig
	OutputDir string `param:"output-dir" desc:"Base output directory" default:"aurelian-output"`
}

// GCPSerialConsoleModule analyzes GCP Compute Engine serial console output for secrets
// and security-relevant instance metadata.
type GCPSerialConsoleModule struct {
	GCPSerialConsoleConfig
}

func (m *GCPSerialConsoleModule) ID() string                { return "serial-console" }
func (m *GCPSerialConsoleModule) Name() string              { return "GCP Serial Console Analysis" }
func (m *GCPSerialConsoleModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPSerialConsoleModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPSerialConsoleModule) OpsecLevel() string        { return "moderate" }
func (m *GCPSerialConsoleModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPSerialConsoleModule) Description() string {
	return "Fetches serial console output from GCP Compute Engine instances and scans for " +
		"hardcoded secrets using Titus. Also checks instance metadata for security-relevant settings " +
		"such as OS Login, serial port access, SSH keys, and overly permissive OAuth scopes."
}

func (m *GCPSerialConsoleModule) References() []string {
	return []string{
		"https://cloud.google.com/compute/docs/troubleshooting/viewing-serial-port-output",
	}
}

func (m *GCPSerialConsoleModule) SupportedResourceTypes() []string {
	return []string{"compute.googleapis.com/Instance"}
}

func (m *GCPSerialConsoleModule) Parameters() any {
	return &m.GCPSerialConsoleConfig
}

func (m *GCPSerialConsoleModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPSerialConsoleConfig
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

	// Resolve hierarchy: org/folder/project -> project IDs.
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

	// Enumerate compute instances per project.
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes([]string{"compute.googleapis.com/Instance"})
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, enumerator.ListForProject, listed)

	// Create compute service client once for all instances.
	ctx := context.Background()
	computeSvc, err := computeapi.NewService(ctx, c.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// Fetch serial port output and check instance metadata.
	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, func(r output.GCPResource, p *pipeline.P[output.ScanInput]) error {
		projectID := r.ProjectID
		zone := r.Location
		instanceName := r.DisplayName

		// Fetch serial port output for ports 1-4.
		for port := int64(1); port <= 4; port++ {
			resp, err := computeSvc.Instances.GetSerialPortOutput(projectID, zone, instanceName).Port(port).Context(ctx).Do()
			if err != nil {
				continue // skip errors, some ports may be empty
			}
			if resp.Contents == "" {
				continue
			}
			p.Send(output.ScanInputFromGCPResource(r, fmt.Sprintf("serial-port/%d", port), []byte(resp.Contents)))
		}

		// Check instance metadata for security-relevant settings.
		checkInstanceMetadata(ctx, computeSvc, r, out)

		return nil
	}, extracted)

	// Scan for secrets.
	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned)
	pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)

	return out.Wait()
}

// checkInstanceMetadata inspects instance metadata and OAuth scopes for security-relevant settings.
func checkInstanceMetadata(ctx context.Context, svc *computeapi.Service, r output.GCPResource, out *pipeline.P[model.AurelianModel]) {
	inst, err := svc.Instances.Get(r.ProjectID, r.Location, r.DisplayName).Context(ctx).Do()
	if err != nil {
		slog.Debug("failed to get instance for metadata check", "instance", r.DisplayName, "error", err)
		return
	}

	// Check metadata items for security-relevant keys.
	if inst.Metadata != nil {
		for _, item := range inst.Metadata.Items {
			switch item.Key {
			case "enable-oslogin", "serial-port-enable", "ssh-keys":
				value := ""
				if item.Value != nil {
					value = *item.Value
				}
				finding := output.NewGCPResource(r.ProjectID, "compute.googleapis.com/Instance", r.ResourceID)
				finding.DisplayName = r.DisplayName
				finding.Location = r.Location
				finding.Properties = map[string]any{
					"finding_type":   "metadata-security-setting",
					"metadata_key":   item.Key,
					"metadata_value": value,
				}
				out.Send(finding)
			}
		}
	}

	// Check OAuth scopes for overly permissive settings.
	for _, sa := range inst.ServiceAccounts {
		for _, scope := range sa.Scopes {
			if strings.Contains(scope, "cloud-platform") {
				finding := output.NewGCPResource(r.ProjectID, "compute.googleapis.com/Instance", r.ResourceID)
				finding.DisplayName = r.DisplayName
				finding.Location = r.Location
				finding.Properties = map[string]any{
					"finding_type":    "overly-permissive-scope",
					"service_account": sa.Email,
					"scope":           scope,
				}
				out.Send(finding)
			}
		}
	}
}
