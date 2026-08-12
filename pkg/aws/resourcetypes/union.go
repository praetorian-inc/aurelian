package resourcetypes

import (
	"log/slog"
	"regexp"
	"sort"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// typeFormat matches the AWS::Service::Resource shape (e.g., AWS::S3::Bucket).
var typeFormat = regexp.MustCompile(`^AWS::[A-Z][A-Za-z0-9]*::[A-Z][A-Za-z0-9]*$`)

var (
	allOnce  sync.Once
	allCache []string
	allSet   map[string]bool
)

// ensureComputed runs the union build at most once per process. After it
// returns, allCache and allSet are populated and safe to read.
//
// The cache has process-lifetime: it is NOT invalidated when
// plugin.ResetRegistry() is called. Tests that need a fresh union must call
// ResetForTest.
//
// Important init-order constraint: do NOT call GetAll(), IsValid(), or
// Validate() from a package init() function. If invoked before all module
// init() functions have registered, the union will be permanently incomplete
// for the lifetime of the process.
//
// An empty registry is a legitimate reachable state here, not a bug; the build
// logs a Warn saying what a consumer must do about it.
func ensureComputed() {
	allOnce.Do(func() {
		seen := make(map[string]struct{})
		for _, rt := range baseline {
			seen[rt] = struct{}{}
		}
		modules := plugin.ByPlatform(plugin.PlatformAWS)
		if len(modules) == 0 {
			slog.Warn("no AWS modules are registered; the resource-type union was "+
				"built from the baseline list alone, so GetAll, IsValid, Validate, "+
				"GetGlobal, and GetRegional will under-report. A consumer outside "+
				"this Go module must blank-import "+
				"github.com/praetorian-inc/aurelian/pkg/modules/loader before its "+
				"first call",
				"baseline_count", len(baseline))
		}
		for _, m := range modules {
			for _, rt := range m.SupportedResourceTypes() {
				if !typeFormat.MatchString(rt) {
					slog.Warn("dropping malformed resource type from list-all union",
						"module", m.ID(), "type", rt)
					continue
				}
				seen[rt] = struct{}{}
			}
		}
		for rt := range exclusions {
			delete(seen, rt)
		}
		allCache = make([]string, 0, len(seen))
		for rt := range seen {
			allCache = append(allCache, rt)
		}
		sort.Strings(allCache)
		allSet = make(map[string]bool, len(allCache))
		for _, rt := range allCache {
			allSet[rt] = true
		}
	})
}
