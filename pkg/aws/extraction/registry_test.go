package extraction

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func noopExtractor(_ extractContext, _ output.AWSResource, _ *pipeline.P[output.ScanInput]) error {
	return nil
}

func TestRegister_DuplicatePanics(t *testing.T) {
	mustRegister("AWS::UnitTest::Duplicate", "duplicate", noopExtractor)

	require.Panics(t, func() {
		mustRegister("AWS::UnitTest::Duplicate", "duplicate", noopExtractor)
	})
}

func TestRegister_MaintainsOrder(t *testing.T) {
	mustRegister("AWS::UnitTest::Order", "first", noopExtractor)
	mustRegister("AWS::UnitTest::Order", "second", noopExtractor)

	extractors := getExtractors("AWS::UnitTest::Order")
	require.Len(t, extractors, 2)
	require.Equal(t, "first", extractors[0].Name)
	require.Equal(t, "second", extractors[1].Name)
}
