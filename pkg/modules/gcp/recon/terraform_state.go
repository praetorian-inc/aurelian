package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	gcsapi "google.golang.org/api/storage/v1"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPTerraformStateModule{})
}

// GCPTerraformStateConfig holds parameters for the GCP Terraform state detection module.
type GCPTerraformStateConfig struct {
	plugin.GCPCommonRecon
}

// GCPTerraformStateModule detects GCS buckets containing Terraform state files
// and validates their security posture.
type GCPTerraformStateModule struct {
	GCPTerraformStateConfig
}

func (m *GCPTerraformStateModule) ID() string                { return "terraform-state" }
func (m *GCPTerraformStateModule) Name() string              { return "GCP Terraform State Detection" }
func (m *GCPTerraformStateModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPTerraformStateModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPTerraformStateModule) OpsecLevel() string        { return "moderate" }
func (m *GCPTerraformStateModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPTerraformStateModule) Parameters() any           { return &m.GCPTerraformStateConfig }

func (m *GCPTerraformStateModule) Description() string {
	return "Detect GCS buckets containing Terraform state files and validate their security posture. " +
		"Checks for public access, versioning, and encryption configuration."
}

func (m *GCPTerraformStateModule) References() []string {
	return []string{
		"https://developer.hashicorp.com/terraform/language/settings/backends/gcs",
		"https://cloud.google.com/storage/docs/access-control",
	}
}

func (m *GCPTerraformStateModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPTerraformStateModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPTerraformStateConfig

	storageSvc, err := gcsapi.NewService(context.Background(), c.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating storage client: %w", err)
	}

	cfg.Info("scanning for Terraform state buckets")

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

	scanner := &terraformStateScanner{svc: storageSvc}
	pipeline.Pipe(projects, scanner.scanProject, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("scanning terraform state buckets"),
		Concurrency: c.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("terraform state scan complete")
	return nil
}

type terraformStateScanner struct {
	svc *gcsapi.Service
}

func (s *terraformStateScanner) scanProject(projectID string, out *pipeline.P[model.AurelianModel]) error {
	resp, err := s.svc.Buckets.List(projectID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping terraform state scan", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing buckets for project %s: %w", projectID, err)
	}

	for _, bucket := range resp.Items {
		detectionMethod := detectTerraformStateBucket(bucket.Name)
		if detectionMethod == "" {
			// Name didn't match; check objects for .tfstate files.
			if s.hasTfstateObjects(bucket.Name) {
				detectionMethod = "object-based"
			} else {
				continue
			}
		}

		// Emit resource.
		r := output.NewGCPResource(projectID, "storage.googleapis.com/Bucket", bucket.Id)
		r.DisplayName = bucket.Name
		r.Location = bucket.Location
		r.Labels = bucket.Labels
		r.Properties = map[string]any{
			"is_terraform_state": true,
			"detection_method":   detectionMethod,
		}
		out.Send(r)

		resourceID := fmt.Sprintf("projects/%s/buckets/%s", projectID, bucket.Name)

		// Check public access.
		if s.checkPublicAccess(bucket.Name, projectID, resourceID, detectionMethod, out) {
			// logged inside
		}

		// Check versioning.
		if bucket.Versioning == nil || !bucket.Versioning.Enabled {
			emitRisk(out, "gcp-terraform-state-no-versioning", output.RiskSeverityMedium,
				resourceID, projectID, bucket.Name, detectionMethod,
				"Terraform state bucket does not have versioning enabled",
				"Enable object versioning to allow state recovery from accidental changes or deletions")
		}

		// Check encryption (CMEK).
		hasCMEK := bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != ""
		if !hasCMEK {
			emitRisk(out, "gcp-terraform-state-no-cmek", output.RiskSeverityInfo,
				resourceID, projectID, bucket.Name, detectionMethod,
				"Terraform state bucket uses Google-managed encryption instead of CMEK",
				"Configure a Cloud KMS key for bucket default encryption to gain control over key lifecycle")
		}
	}

	return nil
}

// detectTerraformStateBucket returns a detection method string if the bucket name
// matches known Terraform state bucket patterns, or empty string if no match.
func detectTerraformStateBucket(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "terraform") || strings.Contains(lower, "tfstate") {
		return "name-based"
	}
	if strings.Contains(lower, "-state-") {
		return "name-based"
	}
	return ""
}

// isTerraformStateBucket returns true if the bucket name matches heuristics
// for a Terraform state bucket.
func isTerraformStateBucket(name string) bool {
	return detectTerraformStateBucket(name) != ""
}

// hasPublicAccess checks if any IAM binding contains allUsers or allAuthenticatedUsers.
func hasPublicAccess(bindings []*gcsapi.PolicyBindings) bool {
	for _, b := range bindings {
		for _, member := range b.Members {
			if strings.EqualFold(member, "allUsers") || strings.EqualFold(member, "allAuthenticatedUsers") {
				return true
			}
		}
	}
	return false
}

func (s *terraformStateScanner) hasTfstateObjects(bucketName string) bool {
	// Check for common tfstate file paths with targeted prefix queries
	// rather than listing all objects.
	for _, prefix := range []string{"terraform.tfstate", "default.tfstate", "env:/", "terraform/"} {
		resp, err := s.svc.Objects.List(bucketName).Prefix(prefix).MaxResults(5).Do()
		if err != nil {
			slog.Debug("failed to list objects for tfstate check", "bucket", bucketName, "prefix", prefix, "error", err)
			continue
		}
		for _, obj := range resp.Items {
			if strings.HasSuffix(obj.Name, ".tfstate") || strings.HasSuffix(obj.Name, ".tfstate.backup") {
				return true
			}
		}
	}
	return false
}

func (s *terraformStateScanner) checkPublicAccess(bucketName, projectID, resourceID, detectionMethod string, out *pipeline.P[model.AurelianModel]) bool {
	policy, err := s.svc.Buckets.GetIamPolicy(bucketName).Do()
	if err != nil {
		slog.Warn("failed to get IAM policy for bucket", "bucket", bucketName, "error", err)
		return false
	}
	if hasPublicAccess(policy.Bindings) {
		emitRisk(out, "gcp-terraform-state-public-access", output.RiskSeverityHigh,
			resourceID, projectID, bucketName, detectionMethod,
			"Terraform state bucket is publicly accessible via IAM policy (allUsers or allAuthenticatedUsers)",
			"Remove allUsers and allAuthenticatedUsers bindings from the bucket IAM policy immediately")
		return true
	}
	return false
}

func emitRisk(out *pipeline.P[model.AurelianModel], riskName string, severity output.RiskSeverity,
	resourceID, projectID, bucketName, detectionMethod, description, remediation string) {

	ctx, _ := json.Marshal(map[string]string{
		"project_id":       projectID,
		"bucket_name":      bucketName,
		"description":      description,
		"remediation":      remediation,
		"detection_method": detectionMethod,
	})

	out.Send(output.AurelianRisk{
		Name:               riskName,
		Severity:           severity,
		ImpactedResourceID: resourceID,
		DeduplicationID:    fmt.Sprintf("%s:%s:%s", riskName, projectID, bucketName),
		Context:            json.RawMessage(ctx),
	})
}
