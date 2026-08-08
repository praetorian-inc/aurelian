package resourcetypes

import "strings"

// globalServices is the region-scope ledger: AWS services whose control plane
// is a single global endpoint, so their resources must be enumerated exactly
// once rather than fanned out across every enabled region. Keys are the
// <Service> segment of an AWS::<Service>::<Resource> type; values are the
// justification for that classification.
//
// # Why this is keyed on the service, not the resource type
//
// Globalness is a property of the SERVICE, not of an individual resource type:
// every type under a global endpoint is global, and no type under a regional
// endpoint is. Keying on the service makes that structural fact explicit
// instead of restating it once per type. It also keeps the ledger reviewable —
// the current union is 49 resource types but only 37 distinct services, and the
// four entries below cover all seven global types. A reviewer can audit a
// 4-entry ledger against AWS documentation; a 49-entry type map is a wall of
// text where a single wrong line silently loses inventory.
//
// The corollary is that a new resource type under an already-classified service
// is inherited automatically and correctly (a fifth IAM type is global without
// any edit here), while a type under a brand-new service is caught by
// TestScope_ReviewedServiceLedger rather than defaulting to regional in
// silence.
//
// This comment is the architecture decision record for that choice. The repo
// has no ADR directory, and docs/ is CI-owned, so the rationale lives with the
// data it explains.
//
// Adding an entry: key on the service segment and supply a one-sentence
// justification naming the endpoint behavior. The justification is asserted
// non-empty by TestScope_AllEntriesJustified, and the service is asserted live
// by TestScope_NoDeadLedgerEntries.
//
// # Deliberate non-entries
//
// Two services look global and are deliberately absent. Do not "fix" either;
// both are pinned by tests in coverage_test.go.
//
//   - GlobalAccelerator — global by nature, but its control plane pins
//     us-west-2 while all four services below resolve to us-east-1. Classifying
//     it global would route it to a us-east-1 global shard where it answers
//     nowhere, silently dropping every accelerator from inventory — a total
//     loss no partition or count test can detect. Pinned by
//     TestGetRegional_KeepsGlobalAccelerator.
//   - S3 — listBucketsInRegion in pkg/aws/enumeration already filters
//     server-side on the BucketRegion it sets on s3.ListBucketsInput, and the
//     S3Enumerator doc comment records that it exists specifically to avoid the
//     duplicate enumeration CloudControl causes. Pinned by
//     TestGetRegional_KeepsS3Bucket.
var globalServices = map[string]string{
	"IAM":           "Single global endpoint iam.amazonaws.com, signed against us-east-1; covers Role, Policy, User, and Group.",
	"Route53":       "Single global control-plane endpoint; hosted zones are not region-scoped.",
	"CloudFront":    "Global CDN whose ARNs carry no region, as encoded in pkg/types/enriched_resource_description.go.",
	"Organizations": "Single global endpoint; the organization is a global singleton per account tree.",
}

// IsGlobal, GetGlobal, and GetRegional are exported solely for Phase B (Guard)
// consumption. Nothing inside Aurelian calls them outside tests: the
// global-vs-regional shard split they exist to drive lives in Guard, which is a
// separate Go module and can only reach this ledger through an exported surface.
// Compare the RegionSource type in pkg/output, exported for the same reason. An
// "unused export" sweep of this repo alone will flag all three; they are not
// dead code.

// IsGlobal reports whether a resource type belongs to a global-endpoint
// service, by looking up the <Service> segment of AWS::<Service>::<Resource> in
// the scope ledger. Input is a resource type only if it is exactly three
// "::"-separated segments whose first is the literal "AWS" and whose <Resource>
// segment is non-empty; anything else reports false. An empty <Service> segment
// reports false as well, via the ledger lookup rather than a segment check —
// no ledger key is empty.
//
// IsGlobal is PURE: it reads only the package-level ledger literal and never
// touches the plugin registry or the union cache. That is deliberate — it makes
// the predicate safe to call from an init() function and from tests that run
// before the module loader has populated the registry, neither of which would
// be true if it called ensureComputed. Keep it that way.
func IsGlobal(rt string) bool {
	parts := strings.Split(rt, "::")
	if len(parts) != 3 || parts[0] != "AWS" || parts[2] == "" {
		return false
	}
	_, ok := globalServices[parts[1]]
	return ok
}

// GetGlobal returns the resource types in GetAll() that belong to a
// global-endpoint service. The result is a fresh slice that never aliases the
// union cache, and it preserves GetAll()'s sort order because ensureComputed
// leaves allCache sorted and filtering is order-preserving.
func GetGlobal() []string {
	ensureComputed()
	out := make([]string, 0, len(allCache))
	for _, rt := range allCache {
		if IsGlobal(rt) {
			out = append(out, rt)
		}
	}
	return out
}

// GetRegional returns the resource types in GetAll() that must be enumerated
// per-region. It is the exact complement of GetGlobal over GetAll(): together
// the two reconstruct GetAll() with no overlap. Same aliasing and ordering
// guarantees as GetGlobal.
func GetRegional() []string {
	ensureComputed()
	out := make([]string, 0, len(allCache))
	for _, rt := range allCache {
		if !IsGlobal(rt) {
			out = append(out, rt)
		}
	}
	return out
}
