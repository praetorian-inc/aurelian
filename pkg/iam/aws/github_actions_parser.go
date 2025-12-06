package aws

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/types"
)

const (
	GitHubActionsOIDCProvider = "token.actions.githubusercontent.com"
	GitHubActionsSubjectKey   = "token.actions.githubusercontent.com:sub"
	GitHubActionsAudienceKey  = "token.actions.githubusercontent.com:aud"
)

// GitHubSubjectClaim represents a parsed GitHub Actions OIDC subject claim
type GitHubSubjectClaim struct {
	Original     string // Full original subject claim: "repo:owner/repo:ref:refs/heads/main"
	Org          string // Organization/owner name: "owner"
	Repo         string // Repository name: "repo"
	FullRepoName string // Full repo name: "owner/repo"
	Context      string // Context part: "ref:refs/heads/main"
	ContextType  string // Context type: "ref", "environment", "actor", etc.
	ContextValue string // Context value: "refs/heads/main", "production", "username", etc.
}

// ParseGitHubSubjectClaim parses a GitHub Actions OIDC subject claim string
func ParseGitHubSubjectClaim(subject string) (*GitHubSubjectClaim, error) {
	if subject == "" {
		return nil, fmt.Errorf("empty subject claim")
	}

	// GitHub Actions subject format: repo:owner/repo[:context]
	if !strings.HasPrefix(subject, "repo:") {
		return nil, fmt.Errorf("invalid GitHub Actions subject format: must start with 'repo:'")
	}

	// Remove "repo:" prefix
	remaining := strings.TrimPrefix(subject, "repo:")

	// Split on first colon after the repo part to separate repo from context
	parts := strings.SplitN(remaining, ":", 2)
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid subject format: missing repository part")
	}

	// Parse org/repo part
	repoPath := parts[0]
	if !strings.Contains(repoPath, "/") {
		return nil, fmt.Errorf("invalid repository format: must contain org/repo")
	}

	// Split org/repo - handle multi-level repo names like "org/sub-org/repo"
	repoParts := strings.Split(repoPath, "/")
	if len(repoParts) < 2 {
		return nil, fmt.Errorf("invalid repository format: must have at least org/repo")
	}

	org := repoParts[0]
	repo := strings.Join(repoParts[1:], "/") // Join remaining parts for multi-level repos

	claim := &GitHubSubjectClaim{
		Original:     subject,
		Org:          org,
		Repo:         repo,
		FullRepoName: org + "/" + repo,
	}

	// Parse context if present
	if len(parts) > 1 {
		context := parts[1]
		claim.Context = context

		// Parse context type and value
		contextParts := strings.SplitN(context, ":", 2)
		claim.ContextType = contextParts[0]

		if len(contextParts) > 1 {
			claim.ContextValue = contextParts[1]
		} else {
			// For simple contexts like "pull_request" or "*"
			claim.ContextValue = contextParts[0]
		}
	}

	return claim, nil
}

// ExtractRepositoriesFromConditions extracts all GitHub Actions repository patterns from IAM policy conditions
func ExtractRepositoriesFromConditions(conditions *types.Condition) (map[string][]string, error) {
	if conditions == nil {
		return map[string][]string{}, nil
	}

	repositories := make(map[string][]string)

	// Process each condition statement
	for _, conditionStatement := range *conditions {
		for conditionKey, conditionValues := range conditionStatement {
			// Look for GitHub Actions subject condition keys
			if conditionKey == GitHubActionsSubjectKey {
				// Extract repository patterns from condition values
				for _, value := range conditionValues {
					if strings.HasPrefix(value, "repo:") {
						claim, err := ParseGitHubSubjectClaim(value)
						if err != nil {
							// Log error but continue processing other claims
							continue
						}

						// Group subject patterns by repository
						repoKey := claim.FullRepoName
						if repositories[repoKey] == nil {
							repositories[repoKey] = make([]string, 0)
						}
						repositories[repoKey] = append(repositories[repoKey], value)
					}
				}
			}
		}
	}

	return repositories, nil
}

// GroupSubjectPatternsByRepository takes a list of subject patterns and groups them by repository
func GroupSubjectPatternsByRepository(patterns []string) map[string][]string {
	repositories := make(map[string][]string)

	for _, pattern := range patterns {
		claim, err := ParseGitHubSubjectClaim(pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		repoKey := claim.FullRepoName
		if repositories[repoKey] == nil {
			repositories[repoKey] = make([]string, 0)
		}
		repositories[repoKey] = append(repositories[repoKey], pattern)
	}

	return repositories
}

// IsGitHubActionsFederatedPrincipal checks if a principal represents GitHub Actions OIDC federation
func IsGitHubActionsFederatedPrincipal(principal *types.Principal) bool {
	if principal == nil || principal.Federated == nil {
		return false
	}

	for _, federated := range *principal.Federated {
		if strings.Contains(federated, GitHubActionsOIDCProvider) {
			return true
		}
	}
	return false
}

// ExtractGitHubActionsSubjectPatternsFromStatement extracts all GitHub Actions subject patterns from a policy statement
func ExtractGitHubActionsSubjectPatternsFromStatement(stmt *types.PolicyStatement) []string {
	patterns := make([]string, 0)

	if stmt.Condition == nil {
		return patterns
	}

	repositories, _ := ExtractRepositoriesFromConditions(stmt.Condition)

	// Flatten all patterns from all repositories
	for _, repoPatterns := range repositories {
		patterns = append(patterns, repoPatterns...)
	}

	return patterns
}

// ValidateGitHubSubjectClaim validates that a subject claim follows GitHub Actions format
func ValidateGitHubSubjectClaim(claim *GitHubSubjectClaim) error {
	if claim == nil {
		return fmt.Errorf("claim cannot be nil")
	}

	if claim.Org == "" {
		return fmt.Errorf("organization cannot be empty")
	}

	if claim.Repo == "" {
		return fmt.Errorf("repository name cannot be empty")
	}

	// Validate known context types
	validContextTypes := map[string]bool{
		"ref":         true,
		"environment": true,
		"pull_request": true,
		"actor":       true,
		"*":           true,
	}

	if claim.ContextType != "" && !validContextTypes[claim.ContextType] {
		// Allow unknown context types but log them
		// This ensures forward compatibility with new GitHub Actions context types
	}

	return nil
}

// GetRepositoryURL constructs a GitHub repository URL from org and repo
func GetRepositoryURL(org, repo string) string {
	return fmt.Sprintf("https://github.com/%s/%s", org, repo)
}

// ParseRepositoryFromURL extracts org and repo from a GitHub URL
func ParseRepositoryFromURL(url string) (org, repo string, err error) {
	if !strings.HasPrefix(url, "https://github.com/") {
		return "", "", fmt.Errorf("invalid GitHub URL format")
	}

	path := strings.TrimPrefix(url, "https://github.com/")
	path = strings.TrimSuffix(path, ".git") // Remove .git suffix if present

	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL: must contain org/repo")
	}

	org = parts[0]
	repo = strings.Join(parts[1:], "/") // Handle multi-level repos

	return org, repo, nil
}