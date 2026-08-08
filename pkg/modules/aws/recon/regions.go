package recon

import (
	"context"
	"fmt"
	"slices"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSRegionsModule{})
}

// RegionsConfig embeds AWSReconBase and nothing else.
//
// It deliberately does not embed AWSCommonRecon: that would add a regions
// parameter, making the module that answers "which regions are enabled" take
// the answer as input, and its PostBind resolves "all" eagerly on the bind path
// through the very helper this module exists to call.
type RegionsConfig struct {
	plugin.AWSReconBase
}

type AWSRegionsModule struct {
	RegionsConfig

	// enabledRegions resolves the account's enabled regions and the provenance
	// of that answer. It exists purely as a test seam: helpers'
	// AccountRegionLister/EC2RegionLister and its default config loader are
	// unexported inside package helpers, so a test in this package cannot
	// otherwise drive Run without live AWS credentials.
	//
	// A nil value means "use the real helper", which is how the instance
	// registered in init() always runs — nothing outside a test sets it.
	enabledRegions func(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error)
}

func (m *AWSRegionsModule) ID() string                { return "regions" }
func (m *AWSRegionsModule) Name() string              { return "AWS Enabled Regions" }
func (m *AWSRegionsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSRegionsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSRegionsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSRegionsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSRegionsModule) Description() string {
	return "Lists the AWS regions enabled for the account, reporting whether the list came from the Account API, the EC2 API, or the compiled-in fallback list."
}

func (m *AWSRegionsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/accounts/latest/reference/API_ListRegions.html",
		"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeRegions.html",
	}
}

// SupportedResourceTypes declares the Guard DISPATCH KEY for this module. It is
// not an enumeration claim: the module enumerates no resource types at all, it
// answers a question ABOUT the account.
//
// The value is required for dispatch, not for listing. Guard's
// agora.MatchesSupportedResourceType (backend/pkg/aurelian/agora/helpers.go)
// short-circuits `return false` when len(supported) == 0, and
// backend/pkg/aurelian/aws/aws_factory.go uses that as its dispatch gate.
// Returning nil would therefore make the region coordinator undispatchable for
// EVERY target, not merely absent from listings.
//
// Declaring it is provably inert inside Aurelian, for three independent reasons:
//
//  1. The loop over every registered module's SupportedResourceTypes() in
//     pkg/aws/resourcetypes/union.go is the sole registry-level consumer of this
//     method, so nothing else observes the declaration.
//  2. Four sibling modules in this package already declare the same type —
//     cdk_bucket_takeover.go, iam_quick_analyze.go, graph.go, and
//     list_all_resources.go — and ensureComputed accumulates into a SET, so this
//     adds no new member.
//  3. pkg/aws/resourcetypes/exclusions.go lists the type, and ensureComputed
//     deletes every exclusion from its accumulator BEFORE it builds allCache
//     from what remains — that ordering is what makes the exclusion effective.
//     The type can never reach GetAll(), and therefore never
//     GetGlobal()/GetRegional(), which filter allCache.
//
// Pinned by TestRegionsModule_DeclarationDoesNotLeakIntoUnion in
// pkg/aws/resourcetypes/coverage_test.go.
func (m *AWSRegionsModule) SupportedResourceTypes() []string {
	return []string{"AWS::Organizations::Account"}
}

func (m *AWSRegionsModule) Parameters() any {
	return &m.RegionsConfig
}

// resolver returns the function Run uses to resolve enabled regions: the
// enabledRegions seam when a test has set one, otherwise the real helper.
//
// This is split out of Run so the default binding can be asserted without being
// invoked. Reaching the default through Run means making a live AWS call, which
// on a credentialed machine can succeed — turning the assertion into one that
// passes for the wrong reason.
func (m *AWSRegionsModule) resolver() func(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error) {
	if m.enabledRegions == nil {
		return helpers.EnabledRegionsWithSource
	}
	return m.enabledRegions
}

func (m *AWSRegionsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.RegionsConfig

	regions, source, err := m.resolver()(cfg.Context, c.Profile, c.ProfileDir)
	if err != nil {
		return fmt.Errorf("regions: resolve enabled regions: %w", err)
	}

	// Clone before sorting. At tier 3 the ladder's result originates from the
	// package-level helpers.Regions variable, which AWSCommonRecon.PostBind
	// reads on list-all's live bind path; sorting in place would permanently
	// reorder a process-global. The helper clones today, but this module does
	// not depend on that staying true.
	sorted := slices.Clone(regions)
	slices.Sort(sorted)

	result := output.NewAWSEnabledRegions(sorted, source)

	cfg.Info("resolved %d enabled regions (source: %s)", result.Count, result.Source)
	out.Send(&result)
	return nil
}
