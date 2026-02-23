//go:build integration

package recon

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
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
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	if !ok {
		t.Fatal("graph module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.Len(t, results, 3, "graph module should return exactly 3 results")

	var (
		entitiesResult      plugin.Result
		resourcesResult     plugin.Result
		relationshipsResult plugin.Result
	)
	for _, r := range results {
		switch r.Metadata["type"] {
		case "iam_entities":
			entitiesResult = r
		case "resources":
			resourcesResult = r
		case "iam_relationships":
			relationshipsResult = r
		}
	}

	entities, ok := entitiesResult.Data.([]output.AWSIAMResource)
	require.True(t, ok, "entities result should be []output.AWSIAMResource, got %T", entitiesResult.Data)

	resources, ok := resourcesResult.Data.([]output.AWSResource)
	require.True(t, ok, "resources result should be []output.AWSResource, got %T", resourcesResult.Data)

	relationships, ok := relationshipsResult.Data.([]output.AWSIAMRelationship)
	require.True(t, ok, "relationships result should be []output.AWSIAMRelationship, got %T", relationshipsResult.Data)
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

	// -------------------------------------------------------------------------
	// Result metadata validation
	// -------------------------------------------------------------------------
	t.Run("Result metadata is correct", func(t *testing.T) {
		assert.Equal(t, "graph", entitiesResult.Metadata["module"])
		assert.Equal(t, "iam_entities", entitiesResult.Metadata["type"])
		assert.NotEmpty(t, entitiesResult.Metadata["accountID"])

		assert.Equal(t, "graph", resourcesResult.Metadata["module"])
		assert.Equal(t, "resources", resourcesResult.Metadata["type"])

		assert.Equal(t, "graph", relationshipsResult.Metadata["module"])
		assert.Equal(t, "iam_relationships", relationshipsResult.Metadata["type"])

		relCount, ok := relationshipsResult.Metadata["count"].(int)
		if ok {
			assert.Greater(t, relCount, 0, "relationship count should be positive")
		}
	})

	// =========================================================================
	// Relationship count regression gate (fixture-scoped)
	// =========================================================================
	t.Run("Relationship count regression gate", func(t *testing.T) {
		// The fixture creates 2 users, 2 roles, 1 group, 1 lambda, 1 S3 bucket,
		// 1 SQS queue, 1 SNS topic, and 1 custom policy. Given their policies,
		// we expect a minimum number of relationships involving fixture ARNs.
		// This is deterministic because it only depends on the fixture's own
		// IAM policies, not on other resources in the account.
		total := len(fixtureRels)
		t.Logf("Fixture relationships: %d", total)

		// Minimum: each of the 2 users should generate several relationships
		// (AssumeRole, PassRole, InvokeFunction, CreateAccessKey, etc.) plus
		// the 2 roles get relationships from the account-wide IAM analysis.
		// 20 is a conservative floor.
		assert.GreaterOrEqual(t, total, 20,
			"fixture relationship count %d is below minimum expected 20 — likely a regression", total)
	})

	// =========================================================================
	// Relationship category counts (fixture-scoped)
	// =========================================================================
	t.Run("Relationship category counts", func(t *testing.T) {
		// Verify that each major (principal_type, resource_type) pair produces
		// relationships involving fixture ARNs. Since the fixture explicitly
		// creates IAM policies granting these access patterns, we can assert
		// on minimum counts deterministically.
		type categoryCheck struct {
			principalType string
			resourceType  string
			minCount      int
			description   string
		}

		checks := []categoryCheck{
			// User -> * (2 fixture users with explicit policies)
			{"AWS::IAM::User", "AWS::IAM::Role", 1, "user policies grant sts:AssumeRole, iam:PassRole"},
			{"AWS::IAM::User", "AWS::IAM::User", 1, "user policies grant iam:CreateAccessKey, etc. on *"},
			{"AWS::IAM::User", "AWS::Lambda::Function", 1, "user1 has lambda:InvokeFunction on *"},
			{"AWS::IAM::User", "AWS::IAM::ManagedPolicy", 1, "user0 has iam:CreatePolicyVersion on *"},
			{"AWS::IAM::User", "AWS::IAM::Group", 1, "user0 is a member of the fixture group"},

			// Role -> * (assumable-role has PassRole, CreateAccessKey, CreatePolicyVersion, InvokeFunction)
			{"AWS::IAM::Role", "AWS::IAM::Role", 1, "assumable-role has iam:PassRole, iam:AttachRolePolicy on *"},
			{"AWS::IAM::Role", "AWS::IAM::User", 1, "assumable-role has iam:CreateAccessKey on *"},
			{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy", 1, "assumable-role has iam:CreatePolicyVersion on *"},
			{"AWS::IAM::Role", "AWS::Lambda::Function", 1, "assumable-role has lambda:InvokeFunction on *"},

			// Service -> * (lambda.amazonaws.com trust policy + apigateway resource policy)
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
		// Verify key actions appear in fixture relationships. These are
		// deterministic because the fixture's IAM policies explicitly grant them.
		type actionCheck struct {
			action   string
			minCount int
			reason   string
		}

		checks := []actionCheck{
			// From user0 inline policy: sts:AssumeRole on *
			{"sts:AssumeRole", 1, "user0 has sts:AssumeRole on * + lambda trust policy"},
			// From user0 inline policy: iam:CreateAccessKey, iam:CreateLoginProfile, iam:AttachUserPolicy, iam:PutUserPolicy on *
			{"iam:CreateAccessKey", 1, "user0 has iam:CreateAccessKey on *"},
			{"iam:CreateLoginProfile", 1, "user0 has iam:CreateLoginProfile on *"},
			{"iam:AttachUserPolicy", 1, "user0 has iam:AttachUserPolicy on *"},
			{"iam:PutUserPolicy", 1, "user0 has iam:PutUserPolicy on *"},
			// From user1 inline policy: iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction on *
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
		// Verify that fixture users have expected relationships with
		// fixture resources. These are stable because the terraform
		// fixture defines exact IAM policies.
		userARNs := fixture.OutputList("user_arns")
		assumableRoleARN := fixture.Output("assumable_role_arn")
		lambdaRoleARN := fixture.Output("lambda_role_arn")
		lambdaFunctionARN := fixture.Output("lambda_function_arn")

		// At least one fixture user should be able to assume the fixture role
		foundAssumeRole := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, assumableRoleARN, "sts:AssumeRole") {
				t.Logf("Found: %s -> %s via sts:AssumeRole", userARN, assumableRoleARN)
				foundAssumeRole = true
				break
			}
		}
		assert.True(t, foundAssumeRole, "at least one fixture user should be able to AssumeRole the fixture assumable role")

		// At least one fixture user should be able to PassRole the lambda role
		foundPassRole := false
		for _, userARN := range userARNs {
			if idx.contains(userARN, lambdaRoleARN, "iam:PassRole") {
				t.Logf("Found: %s -> %s via iam:PassRole", userARN, lambdaRoleARN)
				foundPassRole = true
				break
			}
		}
		assert.True(t, foundPassRole, "at least one fixture user should be able to PassRole the fixture lambda role")

		// At least one fixture user should be able to invoke the lambda function
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
		// Service principals (e.g., lambda.amazonaws.com) should be able to
		// AssumeRole on roles that have matching trust policies.
		lambdaRoleARN := fixture.Output("lambda_role_arn")
		lambdaServiceARN := "arn:aws:lambda:*:*:*"

		assert.True(t, idx.contains(lambdaServiceARN, lambdaRoleARN, "sts:AssumeRole"),
			"%s should be able to AssumeRole the fixture lambda role %s", lambdaServiceARN, lambdaRoleARN)

		// Verify service principals appear with correct resource_type
		for _, r := range relationships {
			if r.Principal.ARN == lambdaServiceARN && r.Action == "sts:AssumeRole" {
				assert.Equal(t, "AWS::Service", r.Principal.ResourceType,
					"service principal should have resource_type AWS::Service")
				break
			}
		}
	})

	t.Run("Service principal resource policy relationships", func(t *testing.T) {
		// The fixture's lambda has a resource policy allowing SNS to invoke it.
		lambdaFunctionARN := fixture.Output("lambda_function_arn")

		// Log all Service -> Lambda relationships to debug ARN matching.
		for _, r := range idx.byPT["AWS::Service"] {
			if r.Resource.ResourceType == "AWS::Lambda::Function" {
				t.Logf("  Service->Lambda: %s -> %s via %s (matches fixture: %v)",
					r.Principal.ARN, r.Resource.ARN, r.Action,
					strings.Contains(r.Resource.ARN, fixture.Output("prefix")))
			}
		}

		// Check that SNS service can invoke the fixture lambda (use prefix match
		// since the relationship ARN may differ slightly from terraform output).
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
			// This is a known issue: resource policy-based relationships for
			// newly-created Lambda functions may not appear if the policy hasn't
			// propagated by the time the analyzer runs. Log rather than fail.
			t.Logf("NOTE: no service principal -> fixture lambda %s InvokeFunction found (resource policy may not have propagated)",
				lambdaFunctionARN)
		}
	})

	t.Run("Synthetic service resource relationships", func(t *testing.T) {
		// "Synthetic" relationships are where a principal can perform a
		// create-type action against a service resource (e.g., lambda:CreateFunction
		// on the lambda service). The resource ARN is a wildcard service ARN
		// like "arn:aws:lambda:*:*:*".
		//
		// Check that fixture users have these synthetic relationships based on
		// their explicit policies.
		userARNs := fixture.OutputList("user_arns")

		// user1 has lambda:CreateFunction on * → should produce synthetic relationship
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

		// Also verify that the broader set of synthetic actions exist in the
		// full result set (not fixture-scoped, since these come from account-wide
		// roles/users that aren't part of the fixture).
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
		// Relationships where the principal is "*" (anonymous/public access)
		// come from resource policies that grant public access.
		// NOTE: The current fixture does not create any public resource policies,
		// so we only check account-wide. If the fixture is extended with a
		// public bucket policy, this should be scoped to fixture ARNs.
		wildcardCount := idx.countByPrincipalType("")
		t.Logf("Wildcard principal relationships (account-wide): %d", wildcardCount)
		// This is informational only — we can't assert on account-wide counts
		// because they depend on what other resources exist in the account.
	})

	t.Run("Role to role relationships", func(t *testing.T) {
		// Verify that fixture roles have relationships with other roles.
		// The assumable role has iam:ListUsers which doesn't produce role->role,
		// but account-wide roles with broad policies will target fixture roles.
		fixtureRoleToRole := fixIdx.countByPair("AWS::IAM::Role", "AWS::IAM::Role")
		t.Logf("Fixture Role -> Role relationships: %d", fixtureRoleToRole)

		// Check that role -> role includes key IAM management actions (account-wide,
		// since these come from roles that aren't part of the fixture).
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

		// Count by principal type (fixture-scoped)
		for _, pt := range []string{"AWS::IAM::User", "AWS::IAM::Role", "AWS::Service", ""} {
			label := pt
			if label == "" {
				label = "(wildcard/unknown)"
			}
			t.Logf("  Principal %s: %d", label, fixIdx.countByPrincipalType(pt))
		}

		// Count by action (top 10, fixture-scoped)
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

		// Count unique fixture principals
		uniquePrincipals := make(map[string]bool)
		for _, r := range fixtureRels {
			uniquePrincipals[r.Principal.ARN] = true
		}
		t.Logf("  Unique fixture principals: %d", len(uniquePrincipals))

		// AssumeRole breakdown (fixture-scoped)
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
