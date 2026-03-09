package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func TestGetExtractors_ReturnsRegistered(t *testing.T) {
	extractors := getExtractors("compute.googleapis.com/Instance")
	if len(extractors) == 0 {
		t.Fatal("expected at least one extractor for compute instances")
	}
	if extractors[0].Name != "metadata" {
		t.Errorf("Name = %q, want %q", extractors[0].Name, "metadata")
	}
}

func TestGetExtractors_UnknownType(t *testing.T) {
	extractors := getExtractors("nonexistent.googleapis.com/Thing")
	if len(extractors) != 0 {
		t.Errorf("expected 0 extractors for unknown type, got %d", len(extractors))
	}
}

func TestMustRegister_PanicOnDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	noop := func(_ extractContext, _ output.GCPResource, _ *pipeline.P[output.ScanInput]) error { return nil }
	mustRegister("compute.googleapis.com/Instance", "metadata", noop)
}
