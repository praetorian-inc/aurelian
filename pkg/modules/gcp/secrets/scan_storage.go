package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GcpScanStorage{})
}

// GcpScanStorage scans GCP Storage buckets for secrets
type GcpScanStorage struct{}

// ID returns the unique identifier for this module
func (m *GcpScanStorage) ID() string {
	return "storage-secrets"
}

// Name returns the human-readable name
func (m *GcpScanStorage) Name() string {
	return "GCP Scan Storage Secrets"
}

// Description returns the module description
func (m *GcpScanStorage) Description() string {
	return "List all storage buckets and objects in a GCP project and scan them for secrets."
}

// Platform returns the cloud platform
func (m *GcpScanStorage) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

// Category returns the module category
func (m *GcpScanStorage) Category() plugin.Category {
	return plugin.CategorySecrets
}

// OpsecLevel returns the operational security level
func (m *GcpScanStorage) OpsecLevel() string {
	return "moderate"
}

// Authors returns the list of module authors
func (m *GcpScanStorage) Authors() []string {
	return []string{"Praetorian"}
}

// References returns external references
func (m *GcpScanStorage) References() []string {
	return []string{}
}

// Parameters defines the required and optional parameters
func (m *GcpScanStorage) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project-id",
			Description: "GCP project ID to scan",
			Type:        "string",
			Required:    true,
			Shortcode:   "p",
		},
		{
			Name:        "continue-piping",
			Description: "Continue processing pipeline on errors",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the module
func (m *GcpScanStorage) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Extract required parameters
	projectID, ok := cfg.Args["project-id"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project-id parameter is required")
	}

	continuePiping := true
	if val, exists := cfg.Args["continue-piping"]; exists {
		if b, ok := val.(bool); ok {
			continuePiping = b
		}
	}

	// Implementation note: This is a placeholder for the actual implementation
	// The original Janus-based implementation chained together:
	// 1. hierarchy.NewGcpProjectInfoLink - Get project info
	// 2. storage.NewGcpStorageBucketListLink - List buckets
	// 3. storage.NewGcpStorageObjectListLink - List objects in buckets
	// 4. storage.NewGcpStorageObjectSecretsLink - Download objects
	// 5. noseyparker.NewNoseyParkerScanner - Scan for secrets
	//
	// TODO: Port these link implementations to native plugin functions

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Temporary implementation that returns an error indicating porting is needed
	return nil, fmt.Errorf("module ported to native plugin architecture but link implementations need migration: project=%s, continue-piping=%v", projectID, continuePiping)
}

// Helper functions for future implementation

// getProjectInfo retrieves GCP project information
func getProjectInfo(ctx context.Context, projectID string) (map[string]any, error) {
	// TODO: Implement GCP project info retrieval
	return nil, fmt.Errorf("not implemented")
}

// listStorageBuckets lists all storage buckets in the project
func listStorageBuckets(ctx context.Context, projectID string) ([]string, error) {
	// TODO: Implement storage bucket listing
	return nil, fmt.Errorf("not implemented")
}

// listStorageObjects lists all objects in a bucket
func listStorageObjects(ctx context.Context, bucket string) ([]string, error) {
	// TODO: Implement object listing
	return nil, fmt.Errorf("not implemented")
}

// downloadObject downloads an object from storage
func downloadObject(ctx context.Context, bucket, object string) ([]byte, error) {
	// TODO: Implement object download
	return nil, fmt.Errorf("not implemented")
}

// scanForSecrets scans content for secrets using NoseyParker
func scanForSecrets(ctx context.Context, content []byte) ([]map[string]any, error) {
	// TODO: Implement NoseyParker integration
	return nil, fmt.Errorf("not implemented")
}

// formatResult formats scan results for output
func formatResult(findings []map[string]any) (plugin.Result, error) {
	data, err := json.Marshal(findings)
	if err != nil {
		return plugin.Result{}, err
	}

	return plugin.Result{
		Data: string(data),
		Metadata: map[string]any{
			"count": len(findings),
		},
	}, nil
}
