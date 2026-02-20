//go:build integration

package recon

import (
	"context"
	"sort"
	"testing"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
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

func TestAWSGraphNew(t *testing.T) {
	t.Setenv("AWS_PROFILE", "aurelian")
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph-new")
	if !ok {
		t.Fatal("graph-new module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	require.Len(t, results, 2, "graph-new module should return exactly 2 results")

	var (
		entitiesResult      plugin.Result
		relationshipsResult plugin.Result
	)
	for _, r := range results {
		switch r.Metadata["type"] {
		case "entities":
			entitiesResult = r
		case "iam_relationships":
			relationshipsResult = r
		}
	}

	entities, ok := entitiesResult.Data.([]output.AWSIAMResource)
	require.True(t, ok, "entities result should be []output.AWSIAMResource, got %T", entitiesResult.Data)

	relationships, ok := relationshipsResult.Data.([]output.AWSIAMRelationship)
	require.True(t, ok, "relationships result should be []output.AWSIAMRelationship, got %T", relationshipsResult.Data)
	require.NotEmpty(t, relationships, "should have at least some IAM relationships")

	idx := newRelIndex(relationships)

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
	// Result 1 (cont): Entities — verify discovered cloud resources
	// -------------------------------------------------------------------------
	t.Run("Cloud resources contain created resources", func(t *testing.T) {
		arnSet := make(map[string]bool)
		idSet := make(map[string]bool)
		for _, e := range entities {
			arnSet[e.ARN] = true
			idSet[e.ResourceID] = true
		}
		require.True(t, len(entities) > 0, "should have discovered at least some resources")

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
		assert.Equal(t, "graph-new", entitiesResult.Metadata["module"])
		assert.Equal(t, "entities", entitiesResult.Metadata["type"])
		assert.NotEmpty(t, entitiesResult.Metadata["accountID"])

		assert.Equal(t, "graph-new", relationshipsResult.Metadata["module"])
		assert.Equal(t, "iam_relationships", relationshipsResult.Metadata["type"])

		relCount, ok := relationshipsResult.Metadata["count"].(int)
		if ok {
			assert.Greater(t, relCount, 0, "relationship count should be positive")
		}
	})

	// =========================================================================
	// Relationship count regression gate
	// =========================================================================
	t.Run("Relationship count regression gate", func(t *testing.T) {
		// The total relationship count must not drop. The baseline was captured
		// from a known-good run on 2026-02-19 against account 411435703965 with
		// regions=[us-east-2]. A small tolerance (5%) is applied to account for
		// minor infrastructure drift in the shared test account, but any large
		// drop indicates a regression in the IAM analysis pipeline.
		const (
			baselineTotal = 8900
			tolerance     = 0.05
		)
		minExpected := int(float64(baselineTotal) * (1 - tolerance))

		total := len(relationships)
		t.Logf("Total relationships: %d (baseline: %d, min: %d)", total, baselineTotal, minExpected)
		assert.GreaterOrEqual(t, total, minExpected,
			"total relationship count %d dropped below %.0f%% of baseline %d (min %d) — likely a regression",
			total, (1-tolerance)*100, baselineTotal, minExpected)
	})

	// =========================================================================
	// Relationship category counts
	// =========================================================================
	t.Run("Relationship category counts", func(t *testing.T) {
		// Verify that each major (principal_type, resource_type) pair produces
		// a non-trivial number of relationships. Baselines from 2026-02-19 run.
		// We use a generous floor (50% of baseline) to avoid flakiness while
		// still catching major regressions.
		type categoryCheck struct {
			principalType string
			resourceType  string
			minCount      int // 50% of observed baseline, rounded down
		}

		checks := []categoryCheck{
			// User -> *
			{"AWS::IAM::User", "AWS::IAM::Role", 320},       // baseline 640
			{"AWS::IAM::User", "AWS::IAM::User", 270},       // baseline 540
			{"AWS::IAM::User", "AWS::Lambda::Function", 140}, // baseline 287
			{"AWS::IAM::User", "AWS::IAM::ManagedPolicy", 40}, // baseline 82
			{"AWS::IAM::User", "AWS::Service", 25},           // baseline 50
			{"AWS::IAM::User", "AWS::IAM::Group", 12},        // baseline 24

			// Role -> *
			{"AWS::IAM::Role", "AWS::IAM::Role", 1700},       // baseline 3463
			{"AWS::IAM::Role", "AWS::IAM::User", 880},        // baseline 1770
			{"AWS::IAM::Role", "AWS::IAM::ManagedPolicy", 440}, // baseline 880
			{"AWS::IAM::Role", "AWS::Lambda::Function", 280}, // baseline 572
			{"AWS::IAM::Role", "AWS::IAM::Group", 140},       // baseline 288
			{"AWS::IAM::Role", "AWS::Service", 125},          // baseline 250

			// Service -> * (from trust policies and resource policies)
			{"AWS::Service", "AWS::IAM::Role", 15},           // baseline 31
			{"AWS::Service", "AWS::Lambda::Function", 2},     // baseline 4
		}

		for _, c := range checks {
			count := idx.countByPair(c.principalType, c.resourceType)
			t.Logf("  %s -> %s: %d (min: %d)", c.principalType, c.resourceType, count, c.minCount)
			assert.GreaterOrEqual(t, count, c.minCount,
				"%s -> %s: got %d relationships, expected at least %d",
				c.principalType, c.resourceType, count, c.minCount)
		}
	})

	// =========================================================================
	// Action distribution
	// =========================================================================
	t.Run("Action distribution", func(t *testing.T) {
		// Verify key actions appear in expected quantities. This catches
		// regressions where a specific action category silently disappears.
		type actionCheck struct {
			action   string
			minCount int // ~50% of baseline
		}

		checks := []actionCheck{
			{"iam:PassRole", 560},                      // baseline 1128
			{"iam:AttachRolePolicy", 450},              // baseline 910
			{"iam:PutRolePolicy", 450},                 // baseline 910
			{"iam:UpdateAssumeRolePolicy", 450},        // baseline 910
			{"iam:CreatePolicyVersion", 240},            // baseline 481
			{"iam:AttachUserPolicy", 240},               // baseline 480
			{"iam:CreateAccessKey", 240},                // baseline 480
			{"iam:CreateLoginProfile", 240},             // baseline 480
			{"iam:PutUserPolicy", 240},                  // baseline 480
			{"sts:AssumeRole", 140},                     // baseline 294
			{"lambda:InvokeFunction", 130},              // baseline 270
			{"lambda:UpdateFunctionCode", 100},          // baseline 209
			{"lambda:CreateFunction", 10},               // baseline 23
			{"ec2:RunInstances", 9},                     // baseline 19
			{"cloudformation:CreateStack", 8},           // baseline 17
			{"codebuild:CreateProject", 6},              // baseline 12
			{"glue:CreateDevEndpoint", 6},               // baseline 12
			{"sagemaker:CreateNotebookInstance", 6},     // baseline 12
			{"autoscaling:CreateAutoScalingGroup", 7},   // baseline 14
			{"ecs:RunTask", 7},                          // baseline 15
		}

		for _, c := range checks {
			count := idx.countByAction(c.action)
			t.Logf("  %s: %d (min: %d)", c.action, count, c.minCount)
			assert.GreaterOrEqual(t, count, c.minCount,
				"action %s: got %d relationships, expected at least %d",
				c.action, count, c.minCount)
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

		assert.True(t, idx.contains("lambda.amazonaws.com", lambdaRoleARN, "sts:AssumeRole"),
			"lambda.amazonaws.com should be able to AssumeRole the fixture lambda role %s", lambdaRoleARN)

		// Verify service principals appear with correct resource_type
		for _, r := range relationships {
			if r.Principal.ARN == "lambda.amazonaws.com" && r.Action == "sts:AssumeRole" {
				assert.Equal(t, "AWS::Service", r.Principal.ResourceType,
					"service principal should have resource_type AWS::Service")
				break
			}
		}
	})

	t.Run("Service principal resource policy relationships", func(t *testing.T) {
		// Service principals should appear as principals in resource-policy-based
		// relationships (e.g., apigateway.amazonaws.com invoking lambda functions
		// via resource policies).
		servicePrincipalLambdaCount := 0
		for _, r := range idx.byPT["AWS::Service"] {
			if r.Resource.ResourceType == "AWS::Lambda::Function" {
				servicePrincipalLambdaCount++
			}
		}
		assert.GreaterOrEqual(t, servicePrincipalLambdaCount, 2,
			"should have at least 2 service principal -> Lambda relationships (from resource policies)")
	})

	t.Run("Synthetic service resource relationships", func(t *testing.T) {
		// "Synthetic" relationships are where a principal can perform a
		// create-type action against a service resource (e.g., lambda:CreateFunction
		// on the lambda service). The resource ARN is a wildcard service ARN
		// like "arn:aws:lambda:*:*:*".
		syntheticActions := []string{
			"lambda:CreateFunction",
			"ec2:RunInstances",
			"cloudformation:CreateStack",
			"codebuild:CreateProject",
			"glue:CreateDevEndpoint",
			"ecs:RunTask",
			"ecs:RegisterTaskDefinition",
			"sagemaker:CreateNotebookInstance",
			"sagemaker:CreateTrainingJob",
			"autoscaling:CreateAutoScalingGroup",
			"autoscaling:CreateLaunchConfiguration",
		}

		for _, action := range syntheticActions {
			count := idx.countByAction(action)
			assert.Greater(t, count, 0,
				"synthetic action %s should have at least one relationship", action)
		}

		// Verify that fixture users have specific synthetic relationships
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
	})

	t.Run("Wildcard principal relationships", func(t *testing.T) {
		// Relationships where the principal is "*" (anonymous/public access)
		// come from resource policies that grant public access.
		wildcardCount := idx.countByPrincipalType("")
		t.Logf("Wildcard principal relationships: %d", wildcardCount)
		assert.GreaterOrEqual(t, wildcardCount, 1,
			"should have at least 1 relationship with a wildcard principal (from public resource policies)")
	})

	t.Run("Role to role relationships", func(t *testing.T) {
		// Roles should have relationships with other roles (e.g., PassRole,
		// AttachRolePolicy, UpdateAssumeRolePolicy).
		roleToRoleCount := idx.countByPair("AWS::IAM::Role", "AWS::IAM::Role")
		t.Logf("Role -> Role relationships: %d", roleToRoleCount)

		// Check that role -> role includes the key IAM management actions
		roleToRoleActions := make(map[string]int)
		for _, r := range idx.byPT["AWS::IAM::Role"] {
			if r.Resource.ResourceType == "AWS::IAM::Role" {
				roleToRoleActions[r.Action]++
			}
		}
		for _, expectedAction := range []string{"iam:PassRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"} {
			assert.Greater(t, roleToRoleActions[expectedAction], 0,
				"Role -> Role relationships should include %s", expectedAction)
		}
	})

	// =========================================================================
	// Diagnostic logging
	// =========================================================================
	t.Run("Diagnostic summary", func(t *testing.T) {
		t.Logf("=== Relationship Summary ===")
		t.Logf("Total relationships: %d", len(relationships))
		t.Logf("Total entities: %d", len(entities))

		// Count by principal type
		for _, pt := range []string{"AWS::IAM::User", "AWS::IAM::Role", "AWS::Service", ""} {
			label := pt
			if label == "" {
				label = "(wildcard/unknown)"
			}
			t.Logf("  Principal %s: %d", label, idx.countByPrincipalType(pt))
		}

		// Count by action (top 10)
		actionCounts := make(map[string]int)
		for _, r := range relationships {
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
		t.Logf("  Top actions:")
		for i, a := range sorted {
			if i >= 10 {
				break
			}
			t.Logf("    %s: %d", a.action, a.count)
		}

		// Count unique principals
		uniquePrincipals := make(map[string]bool)
		for _, r := range relationships {
			uniquePrincipals[r.Principal.ARN] = true
		}
		t.Logf("  Unique principals: %d", len(uniquePrincipals))

		// Count AssumeRole by principal type
		t.Logf("  AssumeRole breakdown:")
		assumeByPT := make(map[string]int)
		for _, r := range relationships {
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

// TestAWSGraphNewVsOld runs both the old and new graph modules against the same
// AWS account and verifies that the new module discovers everything the old one did.
func TestAWSGraphNewVsOld(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/graph")
	fixture.Setup()

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-2"},
		},
		Context: context.Background(),
	}

	// Run old module
	oldMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph")
	require.True(t, ok, "graph module not registered")
	oldResults, err := oldMod.Run(cfg)
	require.NoError(t, err)
	require.Len(t, oldResults, 2)

	// Run new module
	newMod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "graph-new")
	require.True(t, ok, "graph-new module not registered")
	newResults, err := newMod.Run(cfg)
	require.NoError(t, err)
	require.Len(t, newResults, 2)

	// -------------------------------------------------------------------------
	// Extract results by type
	// -------------------------------------------------------------------------
	getResult := func(results []plugin.Result, typ string) plugin.Result {
		for _, r := range results {
			if r.Metadata["type"] == typ {
				return r
			}
		}
		t.Fatalf("no result with type %q", typ)
		return plugin.Result{}
	}

	oldEntities := getResult(oldResults, "entities").Data.([]output.AWSIAMResource)
	newEntities := getResult(newResults, "entities").Data.([]output.AWSIAMResource)
	oldRels := getResult(oldResults, "iam_relationships").Data.([]iampkg.FullResult)
	newRels := getResult(newResults, "iam_relationships").Data.([]output.AWSIAMRelationship)

	// -------------------------------------------------------------------------
	// Entities: new module should have every ARN the old module found
	// -------------------------------------------------------------------------
	t.Run("Entity ARN coverage", func(t *testing.T) {
		oldARNs := make(map[string]bool, len(oldEntities))
		for _, e := range oldEntities {
			oldARNs[e.ARN] = true
		}
		newARNs := make(map[string]bool, len(newEntities))
		for _, e := range newEntities {
			newARNs[e.ARN] = true
		}

		var missing []string
		for arn := range oldARNs {
			if !newARNs[arn] {
				missing = append(missing, arn)
			}
		}
		sort.Strings(missing)
		assert.Empty(t, missing, "new module is missing %d entity ARNs that old module found", len(missing))

		t.Logf("Old entities: %d, New entities: %d", len(oldEntities), len(newEntities))
	})

	// -------------------------------------------------------------------------
	// Relationships: new module should cover every (principal, resource, action)
	// triple the old module found.
	// -------------------------------------------------------------------------
	t.Run("Relationship coverage", func(t *testing.T) {
		type triple struct {
			principalARN string
			resourceARN  string
			action       string
		}

		// Build set from old FullResults
		oldSet := make(map[triple]bool, len(oldRels))
		for _, fr := range oldRels {
			var principalARN string
			switch p := fr.Principal.(type) {
			case *types.UserDetail:
				principalARN = p.Arn
			case *types.RoleDetail:
				principalARN = p.Arn
			case *types.GroupDetail:
				principalARN = p.Arn
			case string:
				principalARN = p
			}
			resourceARN := ""
			if fr.Resource != nil {
				resourceARN = fr.Resource.Arn.String()
			}
			oldSet[triple{principalARN, resourceARN, fr.Action}] = true
		}

		// Build set from new AWSIAMRelationships
		newSet := make(map[triple]bool, len(newRels))
		for _, rel := range newRels {
			newSet[triple{rel.Principal.ARN, rel.Resource.ARN, rel.Action}] = true
		}

		var missing []triple
		for tri := range oldSet {
			if !newSet[tri] {
				missing = append(missing, tri)
			}
		}

		// Log some examples if there are missing triples
		if len(missing) > 0 {
			limit := 20
			if len(missing) < limit {
				limit = len(missing)
			}
			for _, m := range missing[:limit] {
				t.Logf("MISSING: principal=%s resource=%s action=%s", m.principalARN, m.resourceARN, m.action)
			}
		}

		assert.True(t, len(missing) == 0,
			"new module is missing %d relationship triples that old module found (out of %d old, %d new)",
			len(missing), len(oldSet), len(newSet))
	})
}
