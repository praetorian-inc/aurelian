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

// computeAll returns the cached union slice, computing it on first call.
// The returned slice is the internal cache — callers MUST NOT mutate it.
// Use GetAll() externally to obtain a defensive copy.
//
// Note: if no AWS modules are registered when this runs (e.g., a test
// imports resourcetypes directly without importing pkg/modules/loader),
// the union degrades to baseline minus exclusions. The full union requires
// the loader to be imported so the plugin registry is populated.
func computeAll() []string {
	allOnce.Do(func() {
		seen := make(map[string]struct{})

		for _, rt := range baseline {
			seen[rt] = struct{}{}
		}

		for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
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
	return allCache
}
