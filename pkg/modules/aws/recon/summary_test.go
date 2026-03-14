package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "summary")
	require.True(t, ok, "summary module should be registered")
	require.NotNil(t, mod)
}

func TestSummaryModuleMetadata(t *testing.T) {
	m := &AWSSummaryModule{}
	assert.Equal(t, "summary", m.ID())
	assert.Equal(t, "AWS Summary", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.Contains(t, m.Description(), "Cost Explorer")
}

func TestSummaryModuleParameters(t *testing.T) {
	m := &AWSSummaryModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["days"], "should have days param")
}

func TestCleanServiceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Amazon EC2", "EC2"},
		{"AWS Lambda", "Lambda"},
		{"Amazon Simple Storage Service", "Simple Storage Service"},
		{"CloudWatch", "CloudWatch"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, cleanServiceName(tt.input))
	}
}

func TestBuildCostTable(t *testing.T) {
	serviceRegions := map[string]map[string]float64{
		"EC2":    {"us-east-1": 43.22, "us-west-2": 12.50},
		"Lambda": {"us-east-1": 5.10},
		"S3":     {"us-east-1": 0.005}, // below threshold
	}
	regionSet := map[string]bool{
		"us-east-1": true,
		"us-west-2": true,
	}
	grandTotal := 60.825

	table := buildCostTable(serviceRegions, regionSet, grandTotal, 30)

	// Check heading.
	assert.Contains(t, table.TableHeading, "AWS Cost Summary")
	assert.Contains(t, table.TableHeading, "30 days")

	// Check headers: Service, us-east-1, us-west-2, Total Cost
	require.Len(t, table.Headers, 4)
	assert.Equal(t, "Service", table.Headers[0])
	assert.Equal(t, "us-east-1", table.Headers[1])
	assert.Equal(t, "us-west-2", table.Headers[2])
	assert.Equal(t, "Total Cost", table.Headers[3])

	// 3 services + 1 TOTAL row = 4 rows.
	require.Len(t, table.Rows, 4)

	// Services are sorted alphabetically: EC2, Lambda, S3
	assert.Equal(t, "EC2", table.Rows[0][0])
	assert.Equal(t, "$43.22", table.Rows[0][1])   // us-east-1
	assert.Equal(t, "$12.50", table.Rows[0][2])    // us-west-2
	assert.Equal(t, "$55.72", table.Rows[0][3])    // total

	assert.Equal(t, "Lambda", table.Rows[1][0])
	assert.Equal(t, "$5.10", table.Rows[1][1])     // us-east-1
	assert.Equal(t, "-", table.Rows[1][2])          // us-west-2 (no cost)
	assert.Equal(t, "$5.10", table.Rows[1][3])      // total

	assert.Equal(t, "S3", table.Rows[2][0])
	assert.Equal(t, "-", table.Rows[2][1])           // us-east-1 (below threshold)
	assert.Equal(t, "-", table.Rows[2][2])           // us-west-2 (no cost)
	assert.Equal(t, "$0.01", table.Rows[2][3])       // total (0.005 rounds)

	// TOTAL row with bold markdown.
	totalRow := table.Rows[3]
	assert.Equal(t, "**TOTAL**", totalRow[0])
	assert.Contains(t, totalRow[len(totalRow)-1], "**$")
}
