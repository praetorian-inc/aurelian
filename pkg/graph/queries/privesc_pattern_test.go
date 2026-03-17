package queries

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modifiedMethods lists the 26 methods that had the Cartesian product fix applied.
// These must NOT contain the old "WITH attacker\nMATCH (victim:Principal)" pattern.
var modifiedMethods = []string{
	"aws/enrich/privesc/method_01",
	"aws/enrich/privesc/method_02",
	"aws/enrich/privesc/method_03",
	"aws/enrich/privesc/method_04",
	"aws/enrich/privesc/method_05",
	"aws/enrich/privesc/method_06",
	"aws/enrich/privesc/method_07",
	"aws/enrich/privesc/method_08",
	"aws/enrich/privesc/method_09",
	"aws/enrich/privesc/method_10",
	"aws/enrich/privesc/method_11",
	"aws/enrich/privesc/method_12",
	"aws/enrich/privesc/method_13",
	"aws/enrich/privesc/method_20",
	"aws/enrich/privesc/method_21",
	"aws/enrich/privesc/method_22",
	"aws/enrich/privesc/method_23",
	"aws/enrich/privesc/method_24",
	"aws/enrich/privesc/method_25",
	"aws/enrich/privesc/method_26",
	"aws/enrich/privesc/method_27",
	"aws/enrich/privesc/method_28",
	"aws/enrich/privesc/method_29",
	"aws/enrich/privesc/method_33",
	"aws/enrich/privesc/method_35",
	"aws/enrich/privesc/method_39",
}

// TestModifiedPrivescQueries_NoCartesianPattern ensures no modified query
// uses the old Cartesian product pattern that matches all victims.
func TestModifiedPrivescQueries_NoCartesianPattern(t *testing.T) {
	for _, id := range modifiedMethods {
		t.Run(id, func(t *testing.T) {
			query, exists := GetQuery(id)
			require.True(t, exists, "query %s must exist in registry", id)

			cypher := query.Cypher

			// The old broken pattern: "WITH attacker" followed by "MATCH (victim:Principal)"
			// This created O(n^2) edges. Must not appear in any modified query.
			assert.NotContains(t, cypher, "victim:Principal",
				"query %s still contains Cartesian 'victim:Principal' pattern", id)

			// Verify the fix is present: MERGE to target, not victim
			assert.Contains(t, cypher, "CAN_PRIVESC]->(target)",
				"query %s should MERGE CAN_PRIVESC to target, not victim", id)
		})
	}
}

// TestModifiedPrivescQueries_CoalesceGuard ensures all single-permission
// modified queries use coalesce() to handle both Arn and arn property names.
func TestModifiedPrivescQueries_CoalesceGuard(t *testing.T) {
	// Method 39 is dual-permission and does not need the coalesce guard
	// because it requires both permissions on the SAME target (self-filtering).
	singlePermissionMethods := make([]string, 0)
	for _, id := range modifiedMethods {
		if id != "aws/enrich/privesc/method_39" {
			singlePermissionMethods = append(singlePermissionMethods, id)
		}
	}

	for _, id := range singlePermissionMethods {
		t.Run(id, func(t *testing.T) {
			query, exists := GetQuery(id)
			require.True(t, exists)

			cypher := query.Cypher

			// Must contain coalesce to handle inconsistent Arn/arn casing
			assert.Contains(t, cypher, "coalesce(target.Arn, target.arn)",
				"query %s must use coalesce for target ARN", id)
			assert.Contains(t, cypher, "coalesce(attacker.Arn, attacker.arn)",
				"query %s must use coalesce for attacker ARN", id)
		})
	}
}

// TestMethod39_DualPermissionPattern verifies method 39 keeps target through
// WITH clause and requires both permissions on the same target.
func TestMethod39_DualPermissionPattern(t *testing.T) {
	query, exists := GetQuery("aws/enrich/privesc/method_39")
	require.True(t, exists)

	cypher := query.Cypher

	// Must carry target through WITH (not just "WITH attacker")
	assert.Contains(t, cypher, "WITH attacker, target",
		"method 39 must carry target through WITH clause")

	// Must NOT have the old victim pattern
	assert.NotContains(t, cypher, "victim:Principal")

	// Must MERGE to target
	assert.Contains(t, cypher, "CAN_PRIVESC]->(target)")
}

// TestUnmodifiedPassRoleMethods_StillTargetServiceResource verifies that
// PassRole methods (14-19) were not accidentally changed and still target
// service_resource (which was already correct).
func TestUnmodifiedPassRoleMethods_StillTargetServiceResource(t *testing.T) {
	passRoleMethods := []string{
		"aws/enrich/privesc/method_14",
		"aws/enrich/privesc/method_15",
		"aws/enrich/privesc/method_16",
		"aws/enrich/privesc/method_17",
		"aws/enrich/privesc/method_18",
		"aws/enrich/privesc/method_19",
	}

	for _, id := range passRoleMethods {
		t.Run(id, func(t *testing.T) {
			query, exists := GetQuery(id)
			require.True(t, exists, "PassRole query %s must exist", id)

			cypher := query.Cypher

			// PassRole methods target service_resource, not all victims
			assert.Contains(t, cypher, "CAN_PRIVESC]->(service_resource)",
				"PassRole query %s should target service_resource", id)

			// Must NOT have victim pattern (was never there, but guard against regression)
			assert.NotContains(t, cypher, "victim:Principal",
				"PassRole query %s must not have Cartesian victim pattern", id)
		})
	}
}

// TestAllPrivescQueries_NoVictimPattern is a broad sweep ensuring NO privesc
// query in the entire registry uses the old victim:Principal Cartesian pattern.
func TestAllPrivescQueries_NoVictimPattern(t *testing.T) {
	for _, id := range ListQueries() {
		if !strings.HasPrefix(id, "aws/enrich/privesc/") {
			continue
		}
		t.Run(id, func(t *testing.T) {
			query, exists := GetQuery(id)
			require.True(t, exists)

			assert.NotContains(t, query.Cypher, "victim:Principal",
				"privesc query %s must not use Cartesian victim:Principal pattern", id)
		})
	}
}
