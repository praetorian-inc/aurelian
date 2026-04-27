// Package resourcetypes_test is an external test package that imports the
// module loader so the plugin registry is fully populated before tests run.
// Tests here observe the runtime resource-type union; static-data tests live
// in types_test.go (internal package).
package resourcetypes_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/plugin"

	// Blank-import the loader to register all modules before tests run.
	_ "github.com/praetorian-inc/aurelian/pkg/modules/loader"
)

// TestModuleConsumerCoverage is the headline drift test: every type a
// registered AWS module declares in SupportedResourceTypes() must be in
// GetAll() or in the exclusions list. Failing this test means a consumer
// module added a type that list-all won't enumerate — fix by either adding
// the type to baseline (if listing makes sense) or to exclusions (with
// justification).
func TestModuleConsumerCoverage(t *testing.T) {
	all := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		all[rt] = true
	}

	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		for _, rt := range m.SupportedResourceTypes() {
			if all[rt] || resourcetypes.IsExcluded(rt) {
				continue
			}
			t.Errorf("module %q declares %q which is not in GetAll() and not excluded",
				m.ID(), rt)
		}
	}
}
