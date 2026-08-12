package resourcetypes

import "strings"

// globalServices is the region-scope ledger: AWS services whose control plane is
// a single global endpoint, so their resources must be enumerated exactly once
// rather than fanned out across every enabled region. Keys are the <Service>
// segment of an AWS::<Service>::<Resource> type.
//
// It is keyed on the service, not the resource type, because globalness is a
// property of the service — every type under a global endpoint is global, and no
// type under a regional one is. A four-entry ledger is also auditable against AWS
// documentation, where a per-type map would be a wall of text in which a single
// wrong line silently loses inventory.
//
// Two services look global and are deliberately absent. Do NOT "fix" either:
//
//   - GlobalAccelerator — its control plane pins us-west-2 while the four
//     services below resolve to us-east-1, so classifying it global would route
//     it to a us-east-1 global shard where it answers nowhere, silently dropping
//     every accelerator from inventory.
//   - S3 — the regional enumerator already filters buckets server-side per
//     region, specifically to avoid the duplicate enumeration CloudControl
//     causes; classifying it global would discard that.
var globalServices = map[string]string{
	"IAM":           "Single global endpoint iam.amazonaws.com, signed against us-east-1; covers Role, Policy, User, and Group.",
	"Route53":       "Single global control-plane endpoint; hosted zones are not region-scoped.",
	"CloudFront":    "Global CDN whose ARNs carry no region, as encoded in pkg/types/enriched_resource_description.go.",
	"Organizations": "Single global endpoint; the organization is a global singleton per account tree.",
}

// IsGlobal reports whether a resource type belongs to a global-endpoint service.
//
// It is PURE: it reads only the package-level ledger, never the plugin registry
// or the union cache. That is what makes it safe to call from an init() function
// and from tests that run before the module loader has populated the registry.
// Keep it that way.
func IsGlobal(rt string) bool {
	parts := strings.Split(rt, "::")
	if len(parts) != 3 || parts[0] != "AWS" || parts[2] == "" {
		return false
	}
	_, ok := globalServices[parts[1]]
	return ok
}

// GetGlobal returns the resource types in GetAll() that belong to a
// global-endpoint service, in GetAll()'s order and in a fresh slice that never
// aliases the union cache.
//
// It filters the runtime union, so a consumer in another Go module must
// blank-import github.com/praetorian-inc/aurelian/pkg/modules/loader before its
// first call; without it the result is built from the baseline list alone and
// silently under-reports.
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
// the two reconstruct GetAll() with no overlap. Same loader requirement,
// aliasing, and ordering guarantees as GetGlobal.
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
