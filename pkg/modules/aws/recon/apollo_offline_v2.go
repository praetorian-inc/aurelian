package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	iam "github.com/praetorian-inc/aurelian/pkg/iam/aws"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ApolloOfflineV2 analyzes AWS IAM permissions from pre-collected JSON files.
// Replaces the Janus chain-based ApolloOffline module.
// This is the V2 implementation using plain Go patterns.
type ApolloOfflineV2 struct {
	// Required: Path to GAAD JSON file
	GaadFile string

	// Optional: Path to organization policies JSON file
	OrgPolicyFile string

	// Optional: Path to resource policies JSON file
	ResourcePoliciesFile string
}

// ApolloOfflineResult contains all IAM analysis results from offline analysis.
type ApolloOfflineResult = ApolloResult

// NewApolloOfflineV2 creates a new V2 Apollo offline analyzer.
// gaadFile is required - path to GAAD (GetAccountAuthorizationDetails) JSON.
func NewApolloOfflineV2(gaadFile string) *ApolloOfflineV2 {
	return &ApolloOfflineV2{
		GaadFile: gaadFile,
	}
}

// WithOrgPolicyFile sets the organization policies file path.
func (a *ApolloOfflineV2) WithOrgPolicyFile(path string) *ApolloOfflineV2 {
	a.OrgPolicyFile = path
	return a
}

// WithResourcePoliciesFile sets the resource policies file path.
func (a *ApolloOfflineV2) WithResourcePoliciesFile(path string) *ApolloOfflineV2 {
	a.ResourcePoliciesFile = path
	return a
}

// Run executes the Apollo offline IAM analysis workflow.
// Returns analyzed permissions as structured data.
func (a *ApolloOfflineV2) Run(ctx context.Context) (*ApolloOfflineResult, error) {
	// 1. Load organization policies
	orgPolicies, err := a.loadOrgPolicies()
	if err != nil {
		return nil, fmt.Errorf("failed to load org policies: %w", err)
	}

	// 2. Load GAAD data (required)
	gaad, err := a.loadGaad()
	if err != nil {
		return nil, fmt.Errorf("failed to load GAAD: %w", err)
	}

	// 3. Load resource policies
	resourcePolicies, err := a.loadResourcePolicies()
	if err != nil {
		return nil, fmt.Errorf("failed to load resource policies: %w", err)
	}

	// 4. Create PolicyData (no resources for offline mode)
	resources := make([]types.EnrichedResourceDescription, 0)
	pd := &iam.PolicyData{
		Gaad:             gaad,
		OrgPolicies:      orgPolicies,
		ResourcePolicies: resourcePolicies,
		Resources:        &resources,
	}

	// 5. Analyze permissions using existing analyzer
	analyzer := iam.NewGaadAnalyzer(pd)
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, fmt.Errorf("permission analysis failed: %w", err)
	}

	// 6. Transform results
	result := &ApolloOfflineResult{}
	for _, r := range summary.FullResults() {
		perm, err := awstransformers.TransformResultToPermission(r)
		if err != nil {
			slog.Debug("Failed to transform permission result", "error", err)
			continue
		}
		result.Permissions = append(result.Permissions, perm)
	}

	// 7. Add GitHub Actions permissions
	ghPerms, err := awstransformers.ExtractGitHubActionsPermissions(gaad)
	if err != nil {
		slog.Debug("Failed to extract GitHub Actions permissions", "error", err)
	}
	result.GitHubActionsPermissions = ghPerms

	slog.Info("Apollo offline analysis completed", "permissions", len(result.Permissions), "github_actions", len(result.GitHubActionsPermissions))

	return result, nil
}

// loadOrgPolicies loads organization policies from file or uses defaults.
func (a *ApolloOfflineV2) loadOrgPolicies() (*orgpolicies.OrgPolicies, error) {
	if a.OrgPolicyFile == "" {
		slog.Warn("No organization policies file provided, assuming p-FullAWSAccess.")
		return orgpolicies.NewDefaultOrgPolicies(), nil
	}

	fileBytes, err := os.ReadFile(a.OrgPolicyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read org policies file '%s': %w", a.OrgPolicyFile, err)
	}

	// Try to unmarshal as array first (matching online module output)
	var orgPoliciesArray []*orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &orgPoliciesArray); err == nil {
		if len(orgPoliciesArray) > 0 {
			return orgPoliciesArray[0], nil
		}
		slog.Warn("Empty organization policies array, assuming p-FullAWSAccess.")
		return orgpolicies.NewDefaultOrgPolicies(), nil
	}

	// Fallback to single object format
	var op *orgpolicies.OrgPolicies
	if err := json.Unmarshal(fileBytes, &op); err != nil {
		return nil, fmt.Errorf("failed to unmarshal org policies from '%s': %w", a.OrgPolicyFile, err)
	}

	return op, nil
}

// loadGaad loads GAAD data from file.
func (a *ApolloOfflineV2) loadGaad() (*types.Gaad, error) {
	if a.GaadFile == "" {
		return nil, fmt.Errorf("gaad-file is required for offline Apollo analysis")
	}

	fileBytes, err := os.ReadFile(a.GaadFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read GAAD file '%s': %w", a.GaadFile, err)
	}

	// Try to unmarshal as array first (matching account-auth-details module output)
	var gaadArray []types.Gaad
	if err := json.Unmarshal(fileBytes, &gaadArray); err == nil {
		if len(gaadArray) > 0 {
			return &gaadArray[0], nil
		}
		return nil, fmt.Errorf("GAAD file '%s' contains empty array", a.GaadFile)
	}

	// Fallback to single object format
	var gaad types.Gaad
	if err := json.Unmarshal(fileBytes, &gaad); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GAAD data from '%s': %w", a.GaadFile, err)
	}

	return &gaad, nil
}

// loadResourcePolicies loads resource policies from file.
func (a *ApolloOfflineV2) loadResourcePolicies() (map[string]*types.Policy, error) {
	if a.ResourcePoliciesFile == "" {
		slog.Warn("No resource policies file provided, proceeding without resource policies")
		return make(map[string]*types.Policy), nil
	}

	fileBytes, err := os.ReadFile(a.ResourcePoliciesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource policies file '%s': %w", a.ResourcePoliciesFile, err)
	}

	// Try to unmarshal as array first
	var resourcePoliciesArray []map[string]*types.Policy
	if err := json.Unmarshal(fileBytes, &resourcePoliciesArray); err == nil {
		if len(resourcePoliciesArray) > 0 {
			return resourcePoliciesArray[0], nil
		}
		slog.Warn("Empty resource policies array, proceeding without resource policies")
		return make(map[string]*types.Policy), nil
	}

	// Parse as map directly
	var resourcePolicies map[string]*types.Policy
	if err := json.Unmarshal(fileBytes, &resourcePolicies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource policies from '%s': %w", a.ResourcePoliciesFile, err)
	}

	if resourcePolicies == nil {
		resourcePolicies = make(map[string]*types.Policy)
	}

	return resourcePolicies, nil
}
