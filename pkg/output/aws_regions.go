package output

import (
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/model"
)

// RegionSource identifies which tier of the region-resolution ladder produced a
// region list.
//
// It is declared here, exported, rather than in internal/helpers/aws because
// Guard is a separate Go module and cannot import internal/ packages. These
// string values are a wire contract: Guard matches on them, so renaming one is
// a breaking change.
type RegionSource string

const (
	// SourceAccountAPI means the list came from Account.ListRegions (tier 1),
	// the authoritative per-account answer.
	SourceAccountAPI RegionSource = "account-api"

	// SourceEC2API means Account.ListRegions was unavailable and the list came
	// from EC2.DescribeRegions (tier 2).
	SourceEC2API RegionSource = "ec2-api"

	// SourceStaticFallback means both APIs were unavailable and the list is the
	// compiled-in region list (tier 3). Consumers should treat a result carrying
	// this source as potentially stale: the static list cannot know about
	// regions added after the binary was built, nor which regions this
	// particular account has actually enabled.
	SourceStaticFallback RegionSource = "static-fallback"
)

// AWSEnabledRegions is the set of AWS regions enabled for an account, together
// with the provenance of how that set was determined.
//
// The type carries no identity material by design. Determining the region list
// requires credentials, but the answer is a de-escalation of what those
// credentials could reveal: no ARN, no account ID, no profile name, and no
// filesystem path ever reaches the wire. Compare CallerIdentity in this package,
// which deliberately does emit an ARN and account ID.
type AWSEnabledRegions struct {
	model.BaseAurelianModel

	// Regions is the enabled region list. The slice is owned by this struct;
	// NewAWSEnabledRegions copies its input so callers cannot alias it.
	Regions []string `json:"regions"`

	// Count is always len(Regions), maintained by NewAWSEnabledRegions.
	Count int `json:"count"`

	Source RegionSource `json:"source"`
}

// Compile-time proof that AWSEnabledRegions satisfies the sealed marker interface.
var _ model.AurelianModel = (*AWSEnabledRegions)(nil)

// NewAWSEnabledRegions builds an AWSEnabledRegions, keeping Count consistent
// with Regions by construction so the two cannot drift.
//
// The input slice is cloned because tier 3 of the resolution ladder returns a
// package-level variable: storing the caller's slice would let a later in-place
// sort permanently reorder a process-global that other code reads on a live path.
func NewAWSEnabledRegions(regions []string, source RegionSource) AWSEnabledRegions {
	stored := slices.Clone(regions)
	return AWSEnabledRegions{
		Regions: stored,
		Count:   len(stored),
		Source:  source,
	}
}
