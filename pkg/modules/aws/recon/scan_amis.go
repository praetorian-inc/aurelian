package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/praetorian-inc/caligula/pkg/alas"
	"github.com/praetorian-inc/caligula/pkg/ami"
	amiaws "github.com/praetorian-inc/caligula/pkg/ami/aws"
	"github.com/praetorian-inc/caligula/pkg/ami/ebs"
	"github.com/praetorian-inc/caligula/pkg/ami/imagebuilder"
	"github.com/praetorian-inc/caligula/pkg/epss"
	"github.com/praetorian-inc/caligula/pkg/kev"
	"github.com/praetorian-inc/caligula/pkg/parser"
	"github.com/praetorian-inc/caligula/pkg/scanner"

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
	AMIIDs       []string `param:"ami-ids"        desc:"Specific AMI IDs to scan (default: all owned AMIs)" shortcode:"i"`
	Regions      []string `param:"regions"        desc:"AWS regions to scan" default:"us-east-1" shortcode:"r"`
	KEVOnly      bool     `param:"kev-only"       desc:"Only report KEV-flagged vulnerabilities" default:"false"`
	MaxAMISizeGB int      `param:"max-ami-size-gb" desc:"Skip AMIs whose root volume exceeds this many GB" default:"256"`
}

// AWSScanAMIsModule scans Amazon Linux AMIs for OS-level vulnerabilities by
// invoking Caligula's EBS peeler + ALAS advisory matching pipeline directly
// as a Go library (no subprocess, no caligula binary required on the host).
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
	return "Scans Amazon Linux AMIs for OS-level vulnerabilities by peeling each AMI's " +
		"EBS snapshot, extracting the RPM database, and matching against Amazon Linux " +
		"Advisory (ALAS) feeds with EPSS and CISA KEV enrichment. No instance launch " +
		"required — reads the AMI's EBS snapshot directly via the EBS Direct API. " +
		"Implemented via direct Go imports of github.com/praetorian-inc/caligula/pkg/..."
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

	// Resolve AWS config via Aurelian's standard helper. Caligula's AMI
	// runner is constructed from this same config below, so profile/SSO/
	// role-assumption all flow through to the underlying EBS Direct API
	// calls without a second pass through the SDK credential chain.
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     region,
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("scan-amis: load AWS config: %w", err)
	}

	amiIDs := c.AMIIDs
	if len(amiIDs) == 0 {
		cfg.Log.Info("no AMI IDs specified — discovering owned AMIs in %s", region)
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

	maxSize := int32(c.MaxAMISizeGB)
	if maxSize <= 0 {
		maxSize = 256
	}

	// Build the AMI runner backed by Aurelian's resolved aws.Config. The
	// pipeline uses caligula's real EBS peeler — peel each AMI's snapshot
	// in-process, extract the RPM database, return parser.Package list.
	clients := amiaws.NewClients(awsCfg)
	peeler := ebs.NewRealPeeler(amiaws.EBSClientFactoryFromConfig(awsCfg), region)
	pipe := &amiPipeline{clients: clients, peeler: peeler, maxAMISizeGB: maxSize}
	runner := ami.NewRunner(pipe)

	cfg.Log.Info("peeling %d AMI(s)", len(amiIDs))
	result, err := runner.Run(ctx, ami.Options{AMIIDs: amiIDs})
	if err != nil {
		return fmt.Errorf("scan-amis: caligula runner failed: %w", err)
	}

	// Surface peel-time findings (encrypted snapshots, oversized roots,
	// classification failures) as info-severity Aurelian risks so the
	// operator can see why an AMI was skipped.
	for _, f := range result.Findings {
		out.Send(&output.AurelianRisk{
			Name:               fmt.Sprintf("ami-peel-%s", f.Type),
			Severity:           output.RiskSeverityInfo,
			ImpactedResourceID: f.AMIID,
			DeduplicationID:    fmt.Sprintf("caligula:peel:%s:%s", f.AMIID, f.Type),
			Context: mustJSON(map[string]any{
				"ami_id":   f.AMIID,
				"region":   f.Region,
				"type":     f.Type,
				"severity": f.Severity,
				"detail":   f.Detail,
			}),
		})
	}

	if len(result.Packages) == 0 {
		cfg.Log.Warn("no packages extracted from any AMI — nothing to match against ALAS")
		return nil
	}

	// ALAS → EPSS → KEV enrichment, mirroring caligula's CLI pipeline.
	cfg.Log.Info("matching %d packages against ALAS advisories", len(result.Packages))
	vulnFindings := matchAMIPackages(ctx, result.Packages, cfg.Log)

	emittedByAMI := map[string]int{}
	for _, f := range vulnFindings {
		if c.KEVOnly && !f.InKEV {
			continue
		}

		amiID := amiIDForPackage(result, f.Package)
		emittedByAMI[amiID]++

		severity := deriveSeverity(f)
		kevLabel := ""
		if f.InKEV {
			kevLabel = " [KEV]"
		}

		out.Send(&output.AurelianRisk{
			Name: fmt.Sprintf("ami-vulnerability: %s %s@%s%s",
				f.Vulnerability.ID, f.Package.Name, f.Package.Version, kevLabel),
			Severity:           severity,
			ImpactedResourceID: amiID,
			DeduplicationID: fmt.Sprintf("caligula:vuln:%s:%s:%s",
				amiID, f.Package.Name, f.Vulnerability.ID),
			Context: mustJSON(map[string]any{
				"ami_id":          amiID,
				"package":         f.Package.Name,
				"version":         f.Package.Version,
				"vuln_id":         f.Vulnerability.ID,
				"cves":            f.Vulnerability.CVEAliases(),
				"severity":        string(severity),
				"epss_score":      f.EPSSScore,
				"epss_percentile": f.EPSSPercentile,
				"in_kev":          f.InKEV,
				"fixed_version":   f.FixedVersion,
				"summary":         f.Vulnerability.Summary,
			}),
		})
	}

	for amiID, n := range emittedByAMI {
		cfg.Log.Info("AMI %s: %d vulnerabilities emitted", amiID, n)
	}
	cfg.Log.Success("AMI scan complete: %d AMIs processed, %d total vulnerabilities",
		len(amiIDs), len(vulnFindings))
	return nil
}

// discoverOwnedAMIs lists all AMIs owned by the caller's account in the
// region encoded in cfg.
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

// amiPipeline implements caligula's ami.Pipeline interface. ImageBuilder
// expansion is wired up but rarely useful for Aurelian's recon flow; we
// keep it functional rather than stubbing it out, since the dependency
// is already pulled in by the runner.
type amiPipeline struct {
	clients      *amiaws.Clients
	peeler       ami.Peeler
	maxAMISizeGB int32
}

func (p *amiPipeline) ExpandImageBuilderBuildARN(ctx context.Context, arn string) ([]ami.AMIInfo, error) {
	return imagebuilder.ExtractAMIs(ctx, p.clients.ImageBuilder, arn)
}

func (p *amiPipeline) ClassifyAMI(ctx context.Context, id, region string) (ami.AMIInfo, *ami.Finding, error) {
	clients := p.clients
	if region != "" && region != p.clients.Region {
		switched, err := p.clients.WithRegion(ctx, region)
		if err != nil {
			return ami.AMIInfo{ID: id, Region: region}, nil, fmt.Errorf("switch region to %s: %w", region, err)
		}
		clients = switched
	}
	c := ebs.New(clients.EC2, clients.Region, p.maxAMISizeGB)
	return c.Classify(ctx, id)
}

func (p *amiPipeline) Peel(ctx context.Context, info ami.AMIInfo) ([]parser.Package, *ami.Finding, error) {
	return p.peeler.Peel(ctx, info)
}

// matchAMIPackages runs the ALAS → EPSS → KEV pipeline on extracted
// packages, mirroring caligula's cmd/ami.go. Logs warnings via the
// Aurelian logger rather than stderr.
func matchAMIPackages(ctx context.Context, packages []parser.Package, log *plugin.Logger) []scanner.Finding {
	alasClient := alas.NewClient()

	byDistro := map[alas.Distro][]parser.Package{}
	for _, pkg := range packages {
		distro, ok := scanner.ALASDistroForPackage(pkg)
		if !ok {
			continue
		}
		byDistro[distro] = append(byDistro[distro], pkg)
	}

	var findings []scanner.Finding
	for distro, pkgs := range byDistro {
		fr, err := alasClient.FetchAdvisories(ctx, distro)
		if err != nil {
			log.Warn("ALAS fetch for %s failed: %v", distro, err)
			continue
		}
		if fr.Skipped > 0 {
			log.Warn("ALAS %s: %d advisories skipped during parse", distro, fr.Skipped)
		}
		for _, pkg := range pkgs {
			for _, adv := range alas.MatchPackage(pkg, fr.Advisories) {
				findings = append(findings, scanner.ALASFinding(pkg, adv))
			}
		}
	}

	uniqueCVEs := map[string]struct{}{}
	for _, f := range findings {
		for _, cve := range f.Vulnerability.CVEAliases() {
			uniqueCVEs[cve] = struct{}{}
		}
	}
	if len(uniqueCVEs) > 0 {
		cveList := make([]string, 0, len(uniqueCVEs))
		for cve := range uniqueCVEs {
			cveList = append(cveList, cve)
		}
		epssClient := epss.NewClient()
		if scores, err := epssClient.GetScores(ctx, cveList); err != nil {
			log.Warn("EPSS enrichment failed: %v", err)
		} else {
			for i := range findings {
				for _, cve := range findings[i].Vulnerability.CVEAliases() {
					if sc, ok := scores[cve]; ok && sc.Score > findings[i].EPSSScore {
						findings[i].EPSSScore = sc.Score
						findings[i].EPSSPercentile = sc.Percentile
					}
				}
			}
		}
	}

	kevClient := kev.NewClient()
	if catalog, err := kevClient.FetchCatalog(ctx); err != nil {
		log.Warn("CISA KEV fetch failed: %v", err)
	} else {
		for i := range findings {
			for _, cve := range findings[i].Vulnerability.CVEAliases() {
				if _, ok := catalog[cve]; ok {
					findings[i].InKEV = true
					break
				}
			}
		}
	}

	return findings
}

// amiIDForPackage extracts the AMI ID from a package's SourceFile. Caligula
// stamps "ami://<region>/<ami-id>" on every package extracted by the AMI
// peeler (see ami.SourceFileFor), so this is a deterministic lookup rather
// than a fuzzy (name, version) match.
func amiIDForPackage(_ *ami.Result, pkg parser.Package) string {
	const prefix = "ami://"
	src := pkg.SourceFile
	if !strings.HasPrefix(src, prefix) {
		return ""
	}
	rest := src[len(prefix):]
	slash := strings.Index(rest, "/")
	if slash == -1 {
		return ""
	}
	return rest[slash+1:]
}

// deriveSeverity maps a scanner.Finding's CVSS rating to an Aurelian
// RiskSeverity. KEV findings are bumped one level up to reflect the
// known-exploited-in-the-wild status.
func deriveSeverity(f scanner.Finding) output.RiskSeverity {
	rating, _ := f.Vulnerability.SeverityRating()
	sev := output.NormalizeSeverity(output.RiskSeverity(strings.ToLower(string(rating))))
	if f.InKEV {
		switch sev {
		case output.RiskSeverityLow:
			sev = output.RiskSeverityMedium
		case output.RiskSeverityMedium:
			sev = output.RiskSeverityHigh
		case output.RiskSeverityHigh, output.RiskSeverityCritical:
			sev = output.RiskSeverityCritical
		}
	}
	return sev
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
