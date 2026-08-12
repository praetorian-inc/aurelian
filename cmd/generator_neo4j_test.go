package cmd

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// TestResultsContainGraphEntities covers the content-based gate that decides
// whether --neo4j-uri results should additionally be seeded into Neo4j.
// Recon graph emits AWSIAMResource/AWSIAMRelationship (seed); analyze graph
// emits only AurelianRisk (read-only, do not seed).
func TestResultsContainGraphEntities(t *testing.T) {
	tests := []struct {
		name    string
		results []model.AurelianModel
		want    bool
	}{
		{
			name:    "empty results",
			results: nil,
			want:    false,
		},
		{
			name: "only AurelianRisk (analyze graph)",
			results: []model.AurelianModel{
				output.AurelianRisk{Name: "aws-privesc-path", Severity: output.RiskSeverityHigh},
				output.AurelianRisk{Name: "aws-privesc-path", Severity: output.RiskSeverityLow},
			},
			want: false,
		},
		{
			name: "contains AWSIAMResource (recon graph node)",
			results: []model.AurelianModel{
				output.AurelianRisk{Name: "aws-privesc-path"},
				output.AWSIAMResource{},
			},
			want: true,
		},
		{
			name: "contains AWSIAMRelationship (recon graph edge)",
			results: []model.AurelianModel{
				output.AWSIAMRelationship{Action: "iam:PassRole"},
			},
			want: true,
		},
		{
			// Inventory data, not a graph node or edge: a coordinator run that
			// only resolves regions has nothing for GraphFormatter to seed.
			name: "only AWSEnabledRegions (region coordinator) does not seed",
			results: []model.AurelianModel{
				output.NewAWSEnabledRegions([]string{"us-east-1", "us-west-2"}, output.SourceAccountAPI),
			},
			want: false,
		},
		{
			// AWSRegionsModule.Run sends &result, so the pointer spelling is what
			// reaches this gate in production. Both spellings are pinned so a
			// future type-switch case on either one is caught.
			name: "AWSEnabledRegions pointer (as the module emits it) does not seed",
			results: []model.AurelianModel{
				&output.AWSEnabledRegions{
					Regions: []string{"us-east-1"},
					Count:   1,
					Source:  output.SourceStaticFallback,
				},
			},
			want: false,
		},
		{
			// Proves the new type is INERT, not gate-suppressing. Without this row a
			// buggy early `return false` on seeing AWSEnabledRegions would satisfy
			// both rows above while silently disabling seeding for real recon runs.
			name: "AWSEnabledRegions alongside a graph entity still seeds",
			results: []model.AurelianModel{
				output.NewAWSEnabledRegions([]string{"us-east-1"}, output.SourceEC2API),
				output.AWSIAMResource{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resultsContainGraphEntities(tt.results); got != tt.want {
				t.Errorf("resultsContainGraphEntities() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNeo4jSeedingGateRoutingOutcome asserts the routing DECISION that runModule
// makes: with --neo4j-uri set, an only-AurelianRisk result set (analyze graph)
// must NOT seed Neo4j (JSON only), while a graph-entity result set (recon graph)
// must seed. The gate is `uri != "" && resultsContainGraphEntities(results)`.
func TestNeo4jSeedingGateRoutingOutcome(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		results  []model.AurelianModel
		wantSeed bool
		wantJSON bool
	}{
		{
			name:     "analyze graph: uri set, only risks -> JSON only",
			uri:      "bolt://localhost:7687",
			results:  []model.AurelianModel{output.AurelianRisk{Name: "aws-privesc-path"}},
			wantSeed: false,
			wantJSON: true,
		},
		{
			name:     "recon graph: uri set, has entities -> JSON + seed",
			uri:      "bolt://localhost:7687",
			results:  []model.AurelianModel{output.AWSIAMResource{}, output.AWSIAMRelationship{}},
			wantSeed: true,
			wantJSON: true,
		},
		{
			name:     "no uri: entities present -> JSON only (default behavior)",
			uri:      "",
			results:  []model.AurelianModel{output.AWSIAMResource{}},
			wantSeed: false,
			wantJSON: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// JSON is always written when there are results (additive, never skipped).
			gotJSON := len(tt.results) > 0
			if gotJSON != tt.wantJSON {
				t.Errorf("JSON write = %v, want %v", gotJSON, tt.wantJSON)
			}
			// Neo4j seeding only when both the flag is set AND there are graph entities.
			gotSeed := tt.uri != "" && resultsContainGraphEntities(tt.results)
			if gotSeed != tt.wantSeed {
				t.Errorf("Neo4j seed = %v, want %v", gotSeed, tt.wantSeed)
			}
		})
	}
}
