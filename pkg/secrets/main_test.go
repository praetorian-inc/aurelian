package secrets

import (
	"os"
	"testing"

	"github.com/praetorian-inc/titus/pkg/types"
)

var testRules []*types.Rule

func TestMain(m *testing.M) {
	rules, err := loadRules("", nil)
	if err != nil {
		panic("failed to load test rules: " + err.Error())
	}
	testRules = rules
	os.Exit(m.Run())
}
