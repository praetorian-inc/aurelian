//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSIAMQuickAnalyze(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "iam-quick-analyze")
	if !ok {
		t.Fatal("iam-quick-analyze module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"profiles":   []string{"default"},
			"output-dir": t.TempDir(),
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var findings []output.AWSResource
	for m := range p2.Range() {
		if r, ok := m.(output.AWSResource); ok {
			findings = append(findings, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, findings, "should produce at least some findings")

	// Separate findings by type.
	var privescs, trusts []output.AWSResource
	for _, f := range findings {
		switch f.Properties["finding_type"] {
		case "privesc":
			privescs = append(privescs, f)
		case "trust":
			trusts = append(trusts, f)
		}
	}

	t.Logf("Total findings: %d (privesc: %d, trust: %d)", len(findings), len(privescs), len(trusts))

	// -------------------------------------------------------------------------
	// Privesc findings
	// -------------------------------------------------------------------------
	t.Run("Privesc findings exist", func(t *testing.T) {
		require.NotEmpty(t, privescs, "should detect at least some privilege escalation paths")
	})

	t.Run("Fixture user 0 has privesc findings", func(t *testing.T) {
		userARNs := fixture.OutputList("user_arns")
		require.GreaterOrEqual(t, len(userARNs), 1, "fixture should have at least one user ARN")
		user0ARN := userARNs[0]

		// User 0 has: sts:AssumeRole, iam:CreateAccessKey, iam:CreateLoginProfile,
		// iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreatePolicyVersion.
		// Expected privesc combos: sts-assume, iam-create-login,
		// iam-update-user-put, iam-update-user-attach.
		user0Privescs := findingsForARN(privescs, user0ARN)
		require.NotEmpty(t, user0Privescs, "user 0 (%s) should have privesc findings", user0ARN)

		user0Types := privescTypes(user0Privescs)
		t.Logf("User 0 privesc types: %v", user0Types)

		assert.Contains(t, user0Types, "sts-assume",
			"user 0 should have sts-assume (has sts:AssumeRole)")
		assert.Contains(t, user0Types, "iam-create-login",
			"user 0 should have iam-create-login (has iam:CreateLoginProfile)")
		assert.Contains(t, user0Types, "iam-update-user-put",
			"user 0 should have iam-update-user-put (has iam:CreateAccessKey + iam:PutUserPolicy)")
		assert.Contains(t, user0Types, "iam-update-user-attach",
			"user 0 should have iam-update-user-attach (has iam:CreateAccessKey + iam:AttachUserPolicy)")
	})

	t.Run("Fixture user 1 has lambda-create privesc", func(t *testing.T) {
		userARNs := fixture.OutputList("user_arns")
		require.GreaterOrEqual(t, len(userARNs), 2, "fixture should have at least two user ARNs")
		user1ARN := userARNs[1]

		user1Privescs := findingsForARN(privescs, user1ARN)
		require.NotEmpty(t, user1Privescs, "user 1 (%s) should have privesc findings", user1ARN)

		user1Types := privescTypes(user1Privescs)
		t.Logf("User 1 privesc types: %v", user1Types)

		assert.Contains(t, user1Types, "lambda-create",
			"user 1 should have lambda-create (has lambda:CreateFunction + lambda:InvokeFunction + iam:PassRole)")
	})

	// -------------------------------------------------------------------------
	// Trust findings
	// -------------------------------------------------------------------------
	t.Run("Trust findings exist", func(t *testing.T) {
		require.NotEmpty(t, trusts, "should detect at least some trust relationships")
	})

	t.Run("Lambda role has service trust", func(t *testing.T) {
		lambdaRoleARN := fixture.Output("lambda_role_arn")
		roleTrusts := findingsForARN(trusts, lambdaRoleARN)
		require.NotEmpty(t, roleTrusts, "lambda role (%s) should have trust findings", lambdaRoleARN)

		trustTypes := trustTypesForFindings(roleTrusts)
		t.Logf("Lambda role trust types: %v", trustTypes)

		assert.Contains(t, trustTypes, "service-trust",
			"lambda role should have service-trust (trusts lambda.amazonaws.com)")
	})

	t.Run("Assumable role has principal trust", func(t *testing.T) {
		assumableRoleARN := fixture.Output("assumable_role_arn")
		roleTrusts := findingsForARN(trusts, assumableRoleARN)
		require.NotEmpty(t, roleTrusts, "assumable role (%s) should have trust findings", assumableRoleARN)

		trustTypes := trustTypesForFindings(roleTrusts)
		t.Logf("Assumable role trust types: %v", trustTypes)

		assert.Contains(t, trustTypes, "principal-trust:IAM User",
			"assumable role should have principal-trust:IAM User (trusts user 0)")
	})

	// -------------------------------------------------------------------------
	// Diagnostic summary
	// -------------------------------------------------------------------------
	t.Run("Diagnostic summary", func(t *testing.T) {
		t.Logf("=== IAM Quick Analyze Summary ===")
		t.Logf("Total findings: %d", len(findings))
		t.Logf("Privesc findings: %d", len(privescs))
		t.Logf("Trust findings: %d", len(trusts))

		// Count privesc types.
		privescCounts := make(map[string]int)
		for _, f := range privescs {
			if pt, ok := f.Properties["privesc_type"].(string); ok {
				privescCounts[pt]++
			}
		}
		t.Logf("Privesc type breakdown:")
		for pt, count := range privescCounts {
			t.Logf("  %s: %d", pt, count)
		}

		// Count trust types.
		trustCounts := make(map[string]int)
		for _, f := range trusts {
			if tt, ok := f.Properties["trust_type"].(string); ok {
				trustCounts[tt]++
			}
		}
		t.Logf("Trust type breakdown:")
		for tt, count := range trustCounts {
			t.Logf("  %s: %d", tt, count)
		}
	})
}

// findingsForARN returns all findings whose ARN matches the given ARN.
func findingsForARN(findings []output.AWSResource, arn string) []output.AWSResource {
	var out []output.AWSResource
	for _, f := range findings {
		if f.ARN == arn {
			out = append(out, f)
		}
	}
	return out
}

// privescTypes extracts unique privesc_type values from a slice of findings.
func privescTypes(findings []output.AWSResource) []string {
	seen := make(map[string]bool)
	var types []string
	for _, f := range findings {
		if pt, ok := f.Properties["privesc_type"].(string); ok && !seen[pt] {
			seen[pt] = true
			types = append(types, pt)
		}
	}
	return types
}

// trustTypesForFindings extracts unique trust_type values from a slice of findings.
func trustTypesForFindings(findings []output.AWSResource) []string {
	seen := make(map[string]bool)
	var types []string
	for _, f := range findings {
		if tt, ok := f.Properties["trust_type"].(string); ok && !seen[tt] {
			seen[tt] = true
			types = append(types, tt)
		}
	}
	return types
}
