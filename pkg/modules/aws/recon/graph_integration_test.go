//go:build integration

package recon

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// relKey is a (principal, resource, action) triple used for relationship lookups.
type relKey struct {
	principalARN string
	resourceARN  string
	action       string
}

// relIndex builds lookup structures from a slice of AWSIAMRelationships.
type relIndex struct {
	all  []output.AWSIAMRelationship
	set  map[relKey]bool
	byPT map[string][]output.AWSIAMRelationship // keyed by principal resource_type
}

func newRelIndex(rels []output.AWSIAMRelationship) *relIndex {
	idx := &relIndex{
		all:  rels,
		set:  make(map[relKey]bool, len(rels)),
		byPT: make(map[string][]output.AWSIAMRelationship),
	}
	for _, r := range rels {
		idx.set[relKey{r.Principal.ARN, r.Resource.ARN, r.Action}] = true
		idx.byPT[r.Principal.ResourceType] = append(idx.byPT[r.Principal.ResourceType], r)
	}
	return idx
}

func (idx *relIndex) contains(principalARN, resourceARN, action string) bool {
	return idx.set[relKey{principalARN, resourceARN, action}]
}

// countByPrincipalType returns the number of relationships where the principal
// has the given resource type.
func (idx *relIndex) countByPrincipalType(pt string) int {
	return len(idx.byPT[pt])
}

// countByPair returns the number of relationships matching the given
// (principal type, resource type) pair.
func (idx *relIndex) countByPair(principalType, resourceType string) int {
	count := 0
	for _, r := range idx.byPT[principalType] {
		if r.Resource.ResourceType == resourceType {
			count++
		}
	}
	return count
}

// countByAction returns the total number of relationships with the given action.
func (idx *relIndex) countByAction(action string) int {
	count := 0
	for _, r := range idx.all {
		if r.Action == action {
			count++
		}
	}
	return count
}

// fixtureARNSet is a set of ARNs belonging to the terraform fixture, plus
// wildcard service ARNs (e.g. arn:aws:lambda:*:*:*) which are synthetic.
type fixtureARNSet map[string]bool

// involves returns true if either the principal or resource ARN belongs to
// the fixture (or is a wildcard service ARN paired with a fixture ARN).
func (s fixtureARNSet) involves(r output.AWSIAMRelationship) bool {
	return s[r.Principal.ARN] || s[r.Resource.ARN] ||
		(isWildcardServiceARN(r.Resource.ARN) && s[r.Principal.ARN]) ||
		(isWildcardServiceARN(r.Principal.ARN) && s[r.Resource.ARN])
}

func isWildcardServiceARN(arn string) bool {
	return strings.HasSuffix(arn, ":*:*:*")
}

// filterRelationships returns only relationships where at least one side
// (principal or resource) is a fixture ARN.
func filterRelationships(rels []output.AWSIAMRelationship, arns fixtureARNSet) []output.AWSIAMRelationship {
	var out []output.AWSIAMRelationship
	for _, r := range rels {
		if arns.involves(r) {
			out = append(out, r)
		}
	}
	return out
}

func TestAWSGraph(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	if !ok {
		t.Fatal("graph module not registered in plugin system")
	}

	var entities []output.AWSIAMResource
	var resources []output.AWSResource
	var relationships []output.AWSIAMRelationship

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	for m := range p2.Range() {
		switch v := m.(type) {
		case output.AWSIAMResource:
			entities = append(entities, v)
		case output.AWSResource:
			resources = append(resources, v)
		case output.AWSIAMRelationship:
			relationships = append(relationships, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, entities, "should have at least some IAM entities")
	require.NotEmpty(t, relationships, "should have at least some IAM relationships")

	// Build fixture ARN set from terraform outputs.
	allFixtureARNs := fixture.OutputList("all_arns")
	fixtureARNs := make(fixtureARNSet, len(allFixtureARNs))
	for _, arn := range allFixtureARNs {
		fixtureARNs[arn] = true
	}
	t.Logf("Fixture ARNs (%d): %s", len(fixtureARNs), strings.Join(allFixtureARNs, ", "))

	// Build fixture-scoped indexes: only relationships involving fixture ARNs.
	fixtureRels := filterRelationships(relationships, fixtureARNs)
	t.Logf("Fixture relationships: %d (of %d total)", len(fixtureRels), len(relationships))

	idx := newRelIndex(relationships)  // full index (for spot-checks)
	fixIdx := newRelIndex(fixtureRels) // fixture-scoped index (for count assertions)

	// -------------------------------------------------------------------------
	// Result 1: Entities — verify IAM entities appear (from GAAD data)
	// -------------------------------------------------------------------------
	t.Run("GAAD contains created IAM entities", func(t *testing.T) {
		userNames := fixture.OutputList("user_names")
		groupName := fixture.Output("group_name")
		lambdaRoleName := fixture.Output("lambda_role_name")
		assumableRoleName := fixture.Output("assumable_role_name")
		customPolicyARN := fixture.Output("custom_policy_arn")

		foundUsers := make(map[string]bool)
		foundGroups := make(map[string]bool)
		foundRoles := make(map[string]bool)
		foundPolicyARNs := make(map[string]bool)

		for _, e := range entities {
			switch e.ResourceType {
			case "AWS::IAM::User":
				foundUsers[e.DisplayName] = true
			case "AWS::IAM::Group":
				foundGroups[e.DisplayName] = true
			case "AWS::IAM::Role":
				foundRoles[e.DisplayName] = true
			case "AWS::IAM::ManagedPolicy":
				foundPolicyARNs[e.ARN] = true
			}
		}

		for _, name := range userNames {
			assert.True(t, foundUsers[name], "entities should contain user %s", name)
		}
		assert.True(t, foundGroups[groupName], "entities should contain group %s", groupName)
		assert.True(t, foundRoles[lambdaRoleName], "entities should contain role %s", lambdaRoleName)
		assert.True(t, foundRoles[assumableRoleName], "entities should contain role %s", assumableRoleName)
		assert.True(t, foundPolicyARNs[customPolicyARN], "entities should contain policy %s", customPolicyARN)
	})

	// -------------------------------------------------------------------------
	// Result 2: Resources — verify discovered cloud resources
	// -------------------------------------------------------------------------
	t.Run("Cloud resources contain created resources", func(t *testing.T) {
		arnSet := make(map[string]bool)
		idSet := make(map[string]bool)
		for _, r := range resources {
			arnSet[r.ARN] = true
			idSet[r.ResourceID] = true
		}
		require.True(t, len(resources) > 0, "should have discovered at least some resources")

		bucketName := fixture.Output("s3_bucket_name")
		assert.True(t, idSet[bucketName] || arnSet[fixture.Output("s3_bucket_arn")],
			"resources should contain S3 bucket %s", bucketName)

		sqsARN := fixture.Output("sqs_queue_arn")
		assert.True(t, arnSet[sqsARN], "resources should contain SQS queue %s", sqsARN)

		snsARN := fixture.Output("sns_topic_arn")
		assert.True(t, arnSet[snsARN], "resources should contain SNS topic %s", snsARN)

		lambdaARN := fixture.Output("lambda_function_arn")
		assert.True(t, arnSet[lambdaARN], "resources should contain Lambda function %s", lambdaARN)
	})

	// =========================================================================
	// Relationship count regression gate (fixture-scoped)
	// =========================================================================
	t.Run("Relationship count regression gate", func(t *testing.T) {
		total := len(fixtureRels)
		t.Logf("Fixture relationships: %d", total)
		assert.GreaterOrEqual(t, total, 20,
			"fixture relationship count %d is below minimum expected 20 — likely a regression", total)
	})

	// =========================================================================
	// Relationship category counts (fixture-scoped)
	// =========================================================================
	t.Run("Relationship category counts", func(t *testing.T) {
		type categoryCheck struct {
			principalType string
			resourceType  string
			minCount      int
			description   string
		}

		checks := []categoryCheck{
			{"AWS::IAM::User", "AWS::IAM::Role", 1, "user policies grant sts:AssumeRole, iam:PassRole"},
			{"AWS::IAM::User", "AWS::IAM::User", 1, "user policies grant iam:CreateAccessKey, etc. on *"},
			{"AWS::IAM::User", "AWS::Lambda::Function", 1, "user1 has lambda:InvokeFunction on *"},
			{"AWS::IAM::User", "AWS::IAM::ManagedPolicy", 1, "user0 has iam:CreatePolicyVersion on *"},
			{"AWS::IAM::User", "AWS::IAM::Group", 1, "user0 is a member of the fixture group"},
			{"AWS::IAM::Role", "AWS::IAM::Role", 1, "assumable-role has iam:PassRole, iam:AttachRolePolicy on *"},
			{"AWS::IAM::Role", "AWS::IAM::User", 1, "assumable-role has iam:CreateAccessKey on *"},
			{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy", 1, "assumable-role has iam:CreatePolicyVersion on *"},
			{"AWS::IAM::Role", "AWS::Lambda::Function", 1, "assumable-role has lambda:InvokeFunction on *"},
			{"AWS::Service", "AWS::IAM::Role", 1, "lambda.amazonaws.com can AssumeRole the lambda role"},
			{"AWS::Service", "AWS::Lambda::Function", 1, "apigateway has lambda:InvokeFunction via resource policy"},
		}

		for _, c := range checks {
			count := fixIdx.countByPair(c.principalType, c.resourceType)
			t.Logf("  %s -> %s: %d (min: %d) — %s", c.principalType, c.resourceType, count, c.minCount, c.description)
			assert.GreaterOrEqual(t, count, c.minCount,
				"%s -> %s: got %d relationships, expected at least %d (%s)",
				c.principalType, c.resourceType, count, c.minCount, c.description)
		}
	})

	// =========================================================================
	// Action distribution (fixture-scoped)
	// =========================================================================
	t.Run("Action distribution", func(t *testing.T) {
		type actionCheck struct {
			action   string
			minCount int
			reason   string
		}

		checks := []actionCheck{
			{"sts:AssumeRole", 1, "user0 has sts:AssumeRole on * + lambda trust policy"},
			{"iam:CreateAccessKey", 1, "user0 has iam:CreateAccessKey on *"},
			{"iam:CreateLoginProfile", 1, "user0 has iam:CreateLoginProfile on *"},
			{"iam:AttachUserPolicy", 1, "user0 has iam:AttachUserPolicy on *"},
			{"iam:PutUserPolicy", 1, "user0 has iam:PutUserPolicy on *"},
			{"iam:PassRole", 1, "user1 has iam:PassRole on *"},
			{"lambda:CreateFunction", 1, "user1 has lambda:CreateFunction on *"},
			{"lambda:InvokeFunction", 1, "user1 has lambda:InvokeFunction on * + SNS resource policy"},
		}

		for _, c := range checks {
			count := fixIdx.countByAction(c.action)
			t.Logf("  %s: %d (min: %d) — %s", c.action, count, c.minCount, c.reason)
			assert.GreaterOrEqual(t, count, c.minCount,
				"action %s: got %d relationships, expected at least %d (%s)",
				c.action, count, c.minCount, c.reason)
		}
	})

	// =========================================================================
	// Specific fixture relationship spot-checks
	// =========================================================================
	t.Run("User to resource relationships", func(t *testing.T) {
		userARNs := fixture.OutputList("user_arns")
		assumableRoleARN := fixture.Output("assumable_role_arn")
		lambdaRoleARN := fixture.Output("lambda_role_arn")
		lambdaFunctionARN := fixture.Output("lambda_function_arn")

		foundAssumeRole := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, assumableRoleARN, "sts:AssumeRole") {
				t.Logf("Found: %s -> %s via sts:AssumeRole", userARN, assumableRoleARN)
				foundAssumeRole = true
				break
			}
		}
		assert.True(t, foundAssumeRole, "at least one fixture user should be able to AssumeRole the fixture assumable role")

		foundPassRole := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, lambdaRoleARN, "iam:PassRole") {
				t.Logf("Found: %s -> %s via iam:PassRole", userARN, lambdaRoleARN)
				foundPassRole = true
				break
			}
		}
		assert.True(t, foundPassRole, "at least one fixture user should be able to PassRole the fixture lambda role")

		foundInvoke := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, lambdaFunctionARN, "lambda:InvokeFunction") {
				t.Logf("Found: %s -> %s via lambda:InvokeFunction", userARN, lambdaFunctionARN)
				foundInvoke = true
				break
			}
		}
		assert.True(t, foundInvoke, "at least one fixture user should be able to InvokeFunction the fixture lambda")
	})

	t.Run("Service principal AssumeRole relationships", func(t *testing.T) {
		lambdaRoleARN := fixture.Output("lambda_role_arn")
		lambdaServiceARN := "arn:aws:lambda:*:*:*"

		assert.True(t, idx.contains(lambdaServiceARN, lambdaRoleARN, "sts:AssumeRole"),
			"%s should be able to AssumeRole the fixture lambda role %s", lambdaServiceARN, lambdaRoleARN)

		for _, r := range relationships {
			if r.Principal.ARN == lambdaServiceARN && r.Action == "sts:AssumeRole" {
				assert.Equal(t, "AWS::Service", r.Principal.ResourceType,
					"service principal should have resource_type AWS::Service")
				break
			}
		}
	})

	t.Run("Service principal resource policy relationships", func(t *testing.T) {
		lambdaFunctionARN := fixture.Output("lambda_function_arn")

		for _, r := range idx.byPT["AWS::Service"] {
			if r.Resource.ResourceType == "AWS::Lambda::Function" {
				t.Logf("  Service->Lambda: %s -> %s via %s (matches fixture: %v)",
					r.Principal.ARN, r.Resource.ARN, r.Action,
					strings.Contains(r.Resource.ARN, fixture.Output("prefix")))
			}
		}

		prefix := fixture.Output("prefix")
		foundSNSInvoke := false
		for _, r := range idx.byPT["AWS::Service"] {
			if r.Resource.ResourceType == "AWS::Lambda::Function" &&
				strings.Contains(r.Resource.ARN, prefix) &&
				r.Action == "lambda:InvokeFunction" {
				t.Logf("Found: %s -> %s via %s", r.Principal.ARN, r.Resource.ARN, r.Action)
				foundSNSInvoke = true
				break
			}
		}
		if !foundSNSInvoke {
			t.Logf("NOTE: no service principal -> fixture lambda %s InvokeFunction found (resource policy may not have propagated)",
				lambdaFunctionARN)
		}
	})

	t.Run("Synthetic service resource relationships", func(t *testing.T) {
		userARNs := fixture.OutputList("user_arns")

		foundCreateFunction := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, "arn:aws:lambda:*:*:*", "lambda:CreateFunction") {
				t.Logf("Found: %s -> arn:aws:lambda:*:*:* via lambda:CreateFunction", userARN)
				foundCreateFunction = true
				break
			}
		}
		assert.True(t, foundCreateFunction,
			"at least one fixture user should have lambda:CreateFunction on the lambda service resource")

		syntheticActions := []string{
			"lambda:CreateFunction",
			"ec2:RunInstances",
			"cloudformation:CreateStack",
		}
		for _, action := range syntheticActions {
			count := idx.countByAction(action)
			assert.Greater(t, count, 0,
				"synthetic action %s should have at least one relationship (account-wide)", action)
		}
	})

	t.Run("Wildcard principal relationships", func(t *testing.T) {
		wildcardCount := idx.countByPrincipalType("")
		t.Logf("Wildcard principal relationships (account-wide): %d", wildcardCount)
	})

	t.Run("Role to role relationships", func(t *testing.T) {
		fixtureRoleToRole := fixIdx.countByPair("AWS::IAM::Role", "AWS::IAM::Role")
		t.Logf("Fixture Role -> Role relationships: %d", fixtureRoleToRole)

		roleToRoleActions := make(map[string]int)
		for _, r := range idx.byPT["AWS::IAM::Role"] {
			if r.Resource.ResourceType == "AWS::IAM::Role" {
				roleToRoleActions[r.Action]++
			}
		}
		for _, expectedAction := range []string{"iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"} {
			assert.Greater(t, roleToRoleActions[expectedAction], 0,
				"Role -> Role relationships should include %s (account-wide)", expectedAction)
		}
	})

	// =========================================================================
	// Diagnostic logging
	// =========================================================================
	t.Run("Diagnostic summary", func(t *testing.T) {
		t.Logf("=== Full Account Summary ===")
		t.Logf("Total relationships: %d", len(relationships))
		t.Logf("Total entities: %d", len(entities))
		t.Logf("Total resources: %d", len(resources))

		t.Logf("=== Fixture-Scoped Summary ===")
		t.Logf("Fixture relationships: %d", len(fixtureRels))

		for _, pt := range []string{"AWS::IAM::User", "AWS::IAM::Role", "AWS::Service", ""} {
			label := pt
			if label == "" {
				label = "(wildcard/unknown)"
			}
			t.Logf("  Principal %s: %d", label, fixIdx.countByPrincipalType(pt))
		}

		actionCounts := make(map[string]int)
		for _, r := range fixtureRels {
			actionCounts[r.Action]++
		}
		type ac struct {
			action string
			count  int
		}
		var sorted []ac
		for a, c := range actionCounts {
			sorted = append(sorted, ac{a, c})
		}
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })
		t.Logf("  Top fixture actions:")
		for i, a := range sorted {
			if i >= 10 {
				break
			}
			t.Logf("    %s: %d", a.action, a.count)
		}

		uniquePrincipals := make(map[string]bool)
		for _, r := range fixtureRels {
			uniquePrincipals[r.Principal.ARN] = true
		}
		t.Logf("  Unique fixture principals: %d", len(uniquePrincipals))

		t.Logf("  AssumeRole breakdown:")
		assumeByPT := make(map[string]int)
		for _, r := range fixtureRels {
			if r.Action == "sts:AssumeRole" {
				pt := r.Principal.ResourceType
				if pt == "" {
					pt = "(wildcard/unknown)"
				}
				assumeByPT[pt]++
			}
		}
		for pt, count := range assumeByPT {
			t.Logf("    %s: %d", pt, count)
		}
	})
}
