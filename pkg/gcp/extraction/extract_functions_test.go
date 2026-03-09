package extraction

import (
	"testing"
)

func TestExtractors_FunctionEnvVarsRegistered(t *testing.T) {
	extractors := getExtractors("cloudfunctions.googleapis.com/Function")
	var found bool
	for _, e := range extractors {
		if e.Name == "env-vars" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected env-vars extractor registered for cloudfunctions.googleapis.com/Function")
	}
}
