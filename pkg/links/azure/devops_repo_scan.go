package azure

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureDevOpsRepoScanLink clones and scans Git repositories with NoseyParker
type AzureDevOpsRepoScanLink struct {
	*chain.Base
}

func NewAzureDevOpsRepoScanLink(configs ...cfg.Config) chain.Link {
	l := &AzureDevOpsRepoScanLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureDevOpsRepoScanLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureDevOpsPAT(),
		options.OutputDir(),
		options.NoseyParkerPath(),
		options.NoseyParkerOutput(),
		options.NoseyParkerArgs(),
	}
}

// makeDevOpsRequest helper function for authenticated API calls
func (l *AzureDevOpsRepoScanLink) makeDevOpsRequest(method, url string) (*http.Response, error) {
	pat, _ := cfg.As[string](l.Arg("devops-pat"))

	req, err := http.NewRequestWithContext(l.Context(), method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add PAT authentication
	auth := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("unauthorized access - please verify your PAT token has Code (Read) permissions")
	}

	return resp, nil
}

// prepareGitRepo clones a Git repository for scanning
func (l *AzureDevOpsRepoScanLink) prepareGitRepo(cloneUrl, repoPath string) error {
	if err := os.MkdirAll(filepath.Dir(repoPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	l.Logger.Debug("Cloning repository", "url", cloneUrl, "path", repoPath)

	// Clone with full history using --mirror
	cmd := exec.CommandContext(l.Context(), "git", "clone", "--mirror", cloneUrl, repoPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to clone repository: %w\nOutput: %s", err, output)
	}

	return nil
}

// scanGitRepo scans a Git repository with NoseyParker
func (l *AzureDevOpsRepoScanLink) scanGitRepo(repoPath string) error {
	outputDir, _ := cfg.As[string](l.Arg("output"))
	npOutput, _ := cfg.As[string](l.Arg("nosey-parker-output"))
	npPath, _ := cfg.As[string](l.Arg("nosey-parker-path"))
	customArgs, _ := cfg.As[string](l.Arg("nosey-parker-args"))

	// Prepare NoseyParker command
	datastorePath := filepath.Join(outputDir, npOutput)

	npArgs := []string{
		"scan",
		"-d", datastorePath,
		"--git-history", "full",
		repoPath,
	}

	// Add any custom args
	if customArgs != "" {
		npArgs = append(npArgs, strings.Split(customArgs, " ")...)
	}

	l.Logger.Debug("Running NoseyParker scan", "command", npPath, "args", npArgs, "repo", repoPath)

	cmd := exec.CommandContext(l.Context(), npPath, npArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("NoseyParker scan failed: %w\nOutput: %s", err, output)
	}

	return nil
}

func (l *AzureDevOpsRepoScanLink) Process(config types.DevOpsScanConfig) error {
	pat, _ := cfg.As[string](l.Arg("devops-pat"))

	// List repositories in the project
	reposUrl := fmt.Sprintf("https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.1-preview.1",
		config.Organization, config.Project)

	reposResp, err := l.makeDevOpsRequest(http.MethodGet, reposUrl)
	if err != nil {
		return fmt.Errorf("failed to get repositories: %w", err)
	}
	defer reposResp.Body.Close()

	body, err := io.ReadAll(reposResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var reposResult struct {
		Count int `json:"count"`
		Value []struct {
			Id            string `json:"id"`
			Name          string `json:"name"`
			DefaultBranch string `json:"defaultBranch"`
			WebUrl        string `json:"webUrl"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &reposResult); err != nil {
		return fmt.Errorf("failed to parse repos response: %w", err)
	}

	if reposResult.Count == 0 {
		l.Logger.Info("No repositories found in project", "project", config.Project)
		return nil
	}

	message.Info("Found %d repositories to scan in project %s", reposResult.Count, config.Project)

	// Process repositories concurrently with rate limiting
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Max 5 concurrent operations

	baseDir := filepath.Join(os.TempDir(), fmt.Sprintf("azdo-repos-%s-%s", config.Organization, config.Project))
	defer os.RemoveAll(baseDir)

	for _, repo := range reposResult.Value {
		wg.Add(1)
		go func(repo types.DevOpsRepo) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			repoDir := filepath.Join(baseDir, repo.Name)
			cloneUrl := fmt.Sprintf("https://%s@dev.azure.com/%s/%s/_git/%s",
				pat,
				url.PathEscape(config.Organization),
				url.PathEscape(config.Project),
				url.PathEscape(repo.Name))

			// Clone and prepare repository
			if err := l.prepareGitRepo(cloneUrl, repoDir); err != nil {
				l.Logger.Error("Failed to prepare repository", "repo", repo.Name, "error", err.Error())
				return
			}

			// Scan with NoseyParker
			if err := l.scanGitRepo(repoDir); err != nil {
				l.Logger.Error("Failed to scan repository", "repo", repo.Name, "error", err.Error())
			} else {
				l.Logger.Info("Successfully scanned repository", "repo", repo.Name)
			}
		}(types.DevOpsRepo{
			Id:            repo.Id,
			Name:          repo.Name,
			DefaultBranch: repo.DefaultBranch,
			WebUrl:        repo.WebUrl,
		})
	}

	wg.Wait()
	return nil
}
