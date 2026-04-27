package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSScanAMIsModule{})
}

// ScanAMIsConfig holds the parameters for the AMI vulnerability scanner.
type ScanAMIsConfig struct {
	plugin.AWSReconBase
	AMIIDs      []string `param:"ami-ids"      desc:"Specific AMI IDs to scan (default: all owned AMIs)" shortcode:"i"`
	Regions     []string `param:"regions"      desc:"AWS regions to scan" default:"us-east-1" shortcode:"r"`
	KEVOnly     bool     `param:"kev-only"     desc:"Only report KEV-flagged vulnerabilities" default:"false"`
	CaligulaCmd string   `param:"caligula-cmd" desc:"Path to caligula binary" default:"caligula"`
}

// AWSScanAMIsModule scans Amazon Linux AMIs for OS-level vulnerabilities
// using Caligula's EBS peeler and ALAS advisory matching pipeline.
type AWSScanAMIsModule struct {
	ScanAMIsConfig
}

func (m *AWSScanAMIsModule) ID() string                { return "scan-amis" }
func (m *AWSScanAMIsModule) Name() string              { return "AWS AMI Vulnerability Scanner (Caligula)" }
func (m *AWSScanAMIsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSScanAMIsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSScanAMIsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSScanAMIsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSScanAMIsModule) Description() string {
	return "Scans Amazon Linux AMIs for OS-level vulnerabilities by invoking Caligula's " +
		"--mod ami pipeline. Caligula peels the AMI's EBS snapshot, extracts the RPM database, " +
		"and matches against Amazon Linux Advisory (ALAS) feeds with EPSS and CISA KEV enrichment. " +
		"No instance launch required — reads the AMI's EBS snapshot directly via the EBS Direct API."
}

func (m *AWSScanAMIsModule) References() []string {
	return []string{
		"https://github.com/praetorian-inc/caligula",
		"https://alas.aws.amazon.com/",
		"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
}

func (m *AWSScanAMIsModule) SupportedResourceTypes() []string {
	return []string{"AWS::EC2::Image"}
}

func (m *AWSScanAMIsModule) Parameters() any {
	return &m.ScanAMIsConfig
}

func (m *AWSScanAMIsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ScanAMIsConfig
	ctx := cfg.Context

	region := "us-east-1"
	if len(c.Regions) > 0 {
		region = c.Regions[0]
	}

	// If no AMI IDs specified, discover owned AMIs.
	amiIDs := c.AMIIDs
	if len(amiIDs) == 0 {
		cfg.Log.Info("no AMI IDs specified — discovering owned AMIs in %s", region)
		awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
			Region:     region,
			Profile:    c.Profile,
			ProfileDir: c.ProfileDir,
		})
		if err != nil {
			return fmt.Errorf("scan-amis: load AWS config: %w", err)
		}
		discovered, err := discoverOwnedAMIs(ctx, awsCfg)
		if err != nil {
			return fmt.Errorf("scan-amis: discover AMIs: %w", err)
		}
		amiIDs = discovered
		cfg.Log.Info("discovered %d owned AMIs", len(amiIDs))
	}

	if len(amiIDs) == 0 {
		cfg.Log.Warn("no AMIs to scan")
		return nil
	}

	// Invoke caligula binary for each AMI.
	for _, amiID := range amiIDs {
		cfg.Log.Info("scanning AMI %s via caligula", amiID)
		findings, err := runCaligula(ctx, c.CaligulaCmd, amiID, region)
		if err != nil {
			cfg.Log.Warn("AMI %s: caligula failed: %v", amiID, err)
			out.Send(&output.AurelianRisk{
				Name:               "ami-scan-error",
				Severity:           output.RiskSeverityInfo,
				ImpactedResourceID: amiID,
				DeduplicationID:    fmt.Sprintf("caligula:error:%s", amiID),
				Context:            mustJSON(map[string]string{"ami_id": amiID, "error": err.Error()}),
			})
			continue
		}

		for _, f := range findings.Vulnerabilities {
			if c.KEVOnly && !f.InKEV {
				continue
			}

			severity := output.NormalizeSeverity(output.RiskSeverity(strings.ToLower(f.Severity)))
			kevLabel := ""
			if f.InKEV {
				kevLabel = " [KEV]"
			}

			out.Send(&output.AurelianRisk{
				Name:               fmt.Sprintf("ami-vulnerability: %s %s@%s%s", f.VulnID, f.Package, f.Version, kevLabel),
				Severity:           severity,
				ImpactedResourceID: amiID,
				DeduplicationID:    fmt.Sprintf("caligula:vuln:%s:%s:%s", amiID, f.Package, f.VulnID),
				Context: mustJSON(map[string]any{
					"ami_id":          amiID,
					"package":         f.Package,
					"version":         f.Version,
					"vuln_id":         f.VulnID,
					"cves":            f.CVEs,
					"severity":        f.Severity,
					"epss_score":      f.EPSSScore,
					"epss_percentile": f.EPSSPercentile,
					"in_kev":          f.InKEV,
					"fixed_version":   f.FixedVersion,
					"summary":         f.Summary,
				}),
			})
		}

		cfg.Log.Info("AMI %s: %d packages, %d vulnerabilities",
			amiID, len(findings.Packages), len(findings.Vulnerabilities))
	}

	cfg.Log.Success("AMI scan complete: %d AMIs processed", len(amiIDs))
	return nil
}

// discoverOwnedAMIs lists all AMIs owned by the caller's account.
func discoverOwnedAMIs(ctx context.Context, cfg awssdk.Config) ([]string, error) {
	client := ec2.NewFromConfig(cfg)
	out, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, img := range out.Images {
		if img.ImageId != nil {
			ids = append(ids, *img.ImageId)
		}
	}
	return ids, nil
}

// caligulaOutput is the JSON schema caligula --mod ami --formats json produces.
type caligulaOutput struct {
	Packages        []caligulaPackage `json:"packages"`
	Vulnerabilities []caligulaVuln    `json:"vulnerabilities"`
}

type caligulaPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type caligulaVuln struct {
	Package        string   `json:"package"`
	Version        string   `json:"version"`
	VulnID         string   `json:"vuln_id"`
	CVEs           []string `json:"cves"`
	Severity       string   `json:"severity"`
	EPSSScore      float64  `json:"epss_score"`
	EPSSPercentile float64  `json:"epss_percentile"`
	InKEV          bool     `json:"in_kev"`
	FixedVersion   string   `json:"fixed_version"`
	Summary        string   `json:"summary"`
}

// runCaligula invokes the caligula binary with --mod ami and parses the JSON output.
func runCaligula(ctx context.Context, caligulaCmd, amiID, region string) (*caligulaOutput, error) {
	outDir, err := os.MkdirTemp("", "aurelian-caligula-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	args := []string{
		"--mod", "ami",
		"--ami-id", amiID,
		"--aws-region", region,
		"--formats", "json",
		"--no-policy",
		".", // dummy dir argument (required by CLI but unused by ami module)
	}

	cmd := exec.CommandContext(ctx, caligulaCmd, args...)
	cmd.Dir = outDir
	stderr, err := cmd.CombinedOutput()
	// Exit code 1 means findings were detected — that's success for us.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// Findings detected — this is expected.
		} else {
			return nil, fmt.Errorf("caligula exited with error: %w\nstderr: %s", err, stderr)
		}
	}

	jsonPath := filepath.Join(outDir, "output", "ami.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read caligula output: %w\nstderr: %s", err, stderr)
	}

	var result caligulaOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse caligula output: %w", err)
	}
	return &result, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
