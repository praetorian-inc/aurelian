package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AmplifyEnumModule{})
}

// defaultBranchNames are probed for every distribution ID.
var defaultBranchNames = []string{
	"main", "master",
	"develop", "dev", "development",
	"staging", "stage", "stg",
	"prod", "production", "prd",
	"preview",
	"test", "testing",
	"qa", "uat",
	"release",
	"beta", "alpha",
	"demo", "sandbox",
	"www", "app", "web",
}

type AmplifyEnumParams struct {
	Distributions     []string `param:"distributions" desc:"CloudFront distribution IDs or domains to probe" shortcode:"d"`
	DistributionsFile string   `param:"distributions-file" desc:"File with one distribution ID per line"`
	Branches          []string `param:"branches" desc:"Additional branch names to try (merged with defaults)" shortcode:"b"`
	Concurrency       int      `param:"concurrency" desc:"Max concurrent HTTP requests" default:"10" shortcode:"c"`
}

type AmplifyEnumModule struct {
	AmplifyEnumParams
}

func (m *AmplifyEnumModule) ID() string                       { return "amplify-discover" }
func (m *AmplifyEnumModule) Name() string                     { return "AWS Amplify Branch Discovery" }
func (m *AmplifyEnumModule) Platform() plugin.Platform        { return plugin.PlatformAWS }
func (m *AmplifyEnumModule) Category() plugin.Category        { return plugin.CategoryRecon }
func (m *AmplifyEnumModule) OpsecLevel() string               { return "safe" }
func (m *AmplifyEnumModule) Authors() []string                { return []string{"Praetorian"} }
func (m *AmplifyEnumModule) SupportedResourceTypes() []string { return nil }
func (m *AmplifyEnumModule) Parameters() any                  { return &m.AmplifyEnumParams }

func (m *AmplifyEnumModule) Description() string {
	return "Discovers Amplify app branches by probing CloudFront distribution IDs against " +
		"the <branch>.<distribution-id>.amplifyapp.com URL pattern. Amplify apps and their " +
		"backing CloudFront distributions share the same distribution ID."
}

func (m *AmplifyEnumModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/amplify/latest/userguide/custom-domains.html",
	}
}

type amplifyEnumResult struct {
	DistributionID string             `json:"distribution_id"`
	Branches       []discoveredBranch `json:"branches"`
}

type discoveredBranch struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

func (m *AmplifyEnumModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	distributions, err := m.loadDistributions()
	if err != nil {
		return err
	}
	if len(distributions) == 0 {
		return fmt.Errorf("no distribution IDs provided; use --distributions or --distributions-file")
	}

	branches := buildBranchList(m.Branches)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, raw := range distributions {
		distID := normalizeDistributionID(raw)
		if distID == "" {
			cfg.Warn("skipping empty distribution ID from input %q", raw)
			continue
		}

		cfg.Info("probing %d branch names against %s.amplifyapp.com", len(branches), distID)

		found := probeDistribution(cfg.Context, client, distID, branches, m.Concurrency)

		for _, b := range found {
			cfg.Success("found %s (HTTP %d)", b.URL, b.StatusCode)
		}

		if len(found) == 0 {
			cfg.Info("no branches found for %s", distID)
			continue
		}

		result := amplifyEnumResult{
			DistributionID: distID,
			Branches:       found,
		}

		resultsJSON, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshaling results: %w", err)
		}

		out.Send(output.AnalyzeResult{
			Module:  m.ID(),
			Input:   distID,
			Results: json.RawMessage(resultsJSON),
		})
	}

	return nil
}

// loadDistributions merges --distributions and --distributions-file inputs,
// deduplicating entries.
func (m *AmplifyEnumParams) loadDistributions() ([]string, error) {
	var all []string
	all = append(all, m.Distributions...)

	if m.DistributionsFile != "" {
		f, err := os.Open(m.DistributionsFile)
		if err != nil {
			return nil, fmt.Errorf("opening distributions file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				all = append(all, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading distributions file: %w", err)
		}
	}

	// Deduplicate after normalization.
	seen := make(map[string]struct{}, len(all))
	deduped := make([]string, 0, len(all))
	for _, raw := range all {
		id := normalizeDistributionID(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			deduped = append(deduped, raw)
		}
	}
	return deduped, nil
}

func probeDistribution(ctx context.Context, client *http.Client, distID string, branches []string, concurrency int) []discoveredBranch {
	var (
		mu    sync.Mutex
		found []discoveredBranch
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for _, name := range branches {
		g.Go(func() error {
			target := fmt.Sprintf("https://%s.%s.amplifyapp.com", name, distID)
			status := probeAmplifyURL(ctx, client, target)
			if status > 0 && status != http.StatusBadRequest && status != http.StatusNotFound {
				mu.Lock()
				found = append(found, discoveredBranch{
					Name:       name,
					URL:        target,
					StatusCode: status,
				})
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()

	slices.SortFunc(found, func(a, b discoveredBranch) int {
		return strings.Compare(a.Name, b.Name)
	})
	return found
}

func probeAmplifyURL(ctx context.Context, client *http.Client, target string) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// normalizeDistributionID extracts the bare distribution ID from various input
// formats: bare ID, CloudFront domain, Amplify domain, or full URL.
func normalizeDistributionID(input string) string {
	input = strings.TrimSpace(input)
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input, _, _ = strings.Cut(input, "/")
	input, _, _ = strings.Cut(input, ".cloudfront.net")
	input, _, _ = strings.Cut(input, ".amplifyapp.com")
	return strings.ToLower(input)
}

// buildBranchList merges default branch names with user-provided ones, deduped.
func buildBranchList(userBranches []string) []string {
	branches := slices.Clone(defaultBranchNames)
	for _, b := range userBranches {
		b = strings.TrimSpace(b)
		if b != "" && !slices.Contains(branches, b) {
			branches = append(branches, b)
		}
	}
	return branches
}
