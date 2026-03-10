//go:build integration

package push

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	azuretransform "github.com/praetorian-inc/aurelian/pkg/graph/transformers/azure"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/azure/recon" // register iam-pull module
)

// TestAzureIAMGraph provisions Azure IAM fixtures via Terraform, runs the iam-pull
// module to collect real Entra ID + ARM data, pushes to a Neo4j testcontainer,
// runs all enrichment queries, and validates that expected CAN_ESCALATE edges exist.
//
// Requires:
//   - Terraform fixtures deployed at test/terraform/azure/recon/iam-graph/
//   - AZURE_SUBSCRIPTION_ID env var
//   - Azure credentials (az login or env vars)
//   - Docker (for Neo4j testcontainer)
//
// Run with:
//
//	AZURE_SUBSCRIPTION_ID=xxx go test ./pkg/modules/azure/push/ \
//	  -run TestAzureIAMGraph -tags integration -v -count=1 -timeout 30m
func TestAzureIAMGraph(t *testing.T) {
	ctx := context.Background()

	// 1. Setup Terraform fixture
	fixture := testutil.NewAzureFixture(t, "azure/recon/iam-graph")
	fixture.Setup()

	subscriptionID := fixture.Output("subscription_id")
	suffix := fixture.Output("suffix")
	prefix := fmt.Sprintf("aurelian-iam-%s", suffix)

	// Optional second subscription for cross-subscription admin testing.
	// The CLI user must have Owner/Contributor on both subscriptions.
	secondSubscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID_2")

	// Fixture user IDs (for spot-check assertions)
	globalAdminID := fixture.Output("user_global_admin_id")
	privRoleAdminID := fixture.Output("user_priv_role_admin_id")
	appAdminID := fixture.Output("user_app_admin_id")
	userAdminID := fixture.Output("user_user_admin_id")
	regularUserID := fixture.Output("user_regular_id")

	helpdeskAdminID := fixture.Output("user_helpdesk_admin_id")
	passwordAdminID := fixture.Output("user_password_admin_id")
	authAdminID := fixture.Output("user_auth_admin_id")
	privAuthAdminID := fixture.Output("user_priv_auth_admin_id")
	groupsAdminID := fixture.Output("user_groups_admin_id")
	conditionalAccessAdminID := fixture.Output("user_conditional_access_admin_id")
	exchangeAdminID := fixture.Output("user_exchange_admin_id")

	privilegedAppObjectID := fixture.Output("privileged_app_object_id")
	privilegedSPObjectID := fixture.Output("privileged_sp_object_id")
	regularSPObjectID := fixture.Output("regular_sp_object_id")
	msgraphSPObjectID := fixture.Output("msgraph_sp_object_id")

	groupPrivilegedID := fixture.Output("group_privileged_id")
	groupRegularID := fixture.Output("group_regular_id")

	cliUserObjectID := fixture.Output("cli_user_object_id")

	miUserAssignedID := strings.ToLower(fixture.Output("mi_user_assigned_id"))
	vmID := fixture.Output("vm_id")

	t.Logf("Fixture prefix: %s", prefix)
	t.Logf("Subscription: %s", subscriptionID)

	// 2. Run the iam-pull module (collects ALL Entra ID data from the tenant)
	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "iam-pull")
	if !ok {
		t.Fatal("iam-pull module not registered in plugin system")
	}

	subIDs := []string{subscriptionID}
	if secondSubscriptionID != "" {
		subIDs = append(subIDs, secondSubscriptionID)
		t.Logf("Cross-subscription testing enabled: %s + %s", subscriptionID, secondSubscriptionID)
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"subscription-ids": subIDs,
		},
		Context: ctx,
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var consolidated *types.AzureIAMConsolidated
	for m := range p2.Range() {
		if c, ok := m.(*types.AzureIAMConsolidated); ok {
			consolidated = c
		}
	}
	require.NoError(t, p2.Wait())
	require.NotNil(t, consolidated, "iam-pull should emit AzureIAMConsolidated")

	t.Logf("Collected: users=%d, groups=%d, sps=%d, apps=%d",
		consolidated.EntraID.Users.Len(),
		consolidated.EntraID.Groups.Len(),
		consolidated.EntraID.ServicePrincipals.Len(),
		consolidated.EntraID.Applications.Len(),
	)

	// 3. Start Neo4j testcontainer
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err)
	defer cleanup()
	t.Logf("Neo4j container at %s", boltURL)

	// 4. Connect and clear DB
	db, err := adapters.NewNeo4jAdapter(graph.NewConfig(boltURL, "", ""))
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.VerifyConnectivity(ctx))

	testutil.ClearNeo4jDatabase(t, boltURL)

	// 5. Transform + Push
	nodes, rels := azuretransform.TransformAll(consolidated)
	t.Logf("Transformed: %d nodes, %d relationships", len(nodes), len(rels))

	if len(nodes) > 0 {
		nodeResult, err := db.CreateNodes(ctx, nodes)
		require.NoError(t, err)
		t.Logf("Nodes pushed: created=%d", nodeResult.NodesCreated)
	}

	if len(rels) > 0 {
		relResult, err := db.CreateRelationships(ctx, rels)
		require.NoError(t, err)
		t.Logf("Relationships pushed: created=%d", relResult.RelationshipsCreated)
	}

	// 5b. Inject synthetic HAS_PERMISSION on regular_group so group_nesting_paths.yaml
	// can find a transitive path with length > 2:
	//   auth_admin -[:MEMBER_OF]-> privileged_group -[:MEMBER_OF]-> regular_group -[:HAS_PERMISSION]-> RoleDefinition
	// Without this, the only path (auth_admin → privileged_group → RoleDefinition) has length 2
	// which is excluded by the Cypher filter WHERE length(path) > 2.
	_, err = db.Query(ctx,
		"MATCH (g:Group {id: $gid}), (rd:RoleDefinition) "+
			"WITH g, rd LIMIT 1 "+
			"CREATE (g)-[:HAS_PERMISSION {source: 'Synthetic', assignmentType: 'Permanent'}]->(rd)",
		map[string]interface{}{"gid": groupRegularID})
	require.NoError(t, err, "synthetic HAS_PERMISSION on regular_group for group_nesting_paths test")

	// 6. Run enrichment
	err = queries.EnrichAzure(ctx, db)
	require.NoError(t, err, "enrichment queries should complete without error")
	t.Log("Enrichment queries complete")

	// =====================================================================
	// Helpers
	// =====================================================================

	queryCount := func(cypher string, params map[string]interface{}) int {
		t.Helper()
		result, err := db.Query(ctx, cypher, params)
		require.NoError(t, err)
		if len(result.Records) > 0 {
			if c, ok := result.Records[0]["c"].(int64); ok {
				return int(c)
			}
		}
		return 0
	}

	edgeExists := func(attackerID, method, targetID string) bool {
		t.Helper()
		return queryCount(
			"MATCH (a {id: $aid})-[r:CAN_ESCALATE {method: $method}]->(t {id: $tid}) RETURN count(r) AS c",
			map[string]interface{}{"aid": attackerID, "method": method, "tid": targetID},
		) > 0
	}

	// edgeProps returns all properties of a CAN_ESCALATE edge between two nodes.
	edgeProps := func(attackerID, method, targetID string) map[string]interface{} {
		t.Helper()
		result, err := db.Query(ctx,
			"MATCH (a {id: $aid})-[r:CAN_ESCALATE {method: $method}]->(t {id: $tid}) RETURN properties(r) AS props LIMIT 1",
			map[string]interface{}{"aid": attackerID, "method": method, "tid": targetID})
		require.NoError(t, err)
		if len(result.Records) > 0 {
			if props, ok := result.Records[0]["props"].(map[string]interface{}); ok {
				return props
			}
		}
		return nil
	}

	// nodeProps returns selected properties of a node by ID.
	nodeProps := func(id string, propNames ...string) map[string]interface{} {
		t.Helper()
		projections := make([]string, len(propNames))
		for i, p := range propNames {
			projections[i] = fmt.Sprintf("n.%s AS %s", p, p)
		}
		cypher := fmt.Sprintf("MATCH (n {id: $id}) RETURN %s LIMIT 1", strings.Join(projections, ", "))
		result, err := db.Query(ctx, cypher, map[string]interface{}{"id": id})
		require.NoError(t, err)
		if len(result.Records) > 0 {
			return result.Records[0]
		}
		return nil
	}

	// Filter nodes to fixture-only by prefix in displayName
	fixtureNodeCount := func(label string) int {
		return queryCount(
			fmt.Sprintf("MATCH (n:%s) WHERE n.displayName CONTAINS $prefix RETURN count(n) AS c", label),
			map[string]interface{}{"prefix": prefix},
		)
	}

	// =====================================================================
	// Result 1: Fixture entities exist in graph
	// =====================================================================
	t.Run("fixture entities exist in graph", func(t *testing.T) {
		// Users
		assert.Equal(t, 12, fixtureNodeCount("User"), "12 fixture users")

		// Groups
		assert.Equal(t, 2, fixtureNodeCount("Group"), "2 fixture groups")

		// Applications and Service Principals
		assert.GreaterOrEqual(t, fixtureNodeCount("Application"), 2, "at least 2 fixture apps")
		assert.GreaterOrEqual(t, fixtureNodeCount("ServicePrincipal"), 2, "at least 2 fixture SPs")
	})

	// Verify specific fixture entities by ID
	t.Run("fixture entity IDs present", func(t *testing.T) {
		// All 12 users
		for name, uid := range map[string]string{
			"global_admin":            globalAdminID,
			"priv_role_admin":         privRoleAdminID,
			"app_admin":               appAdminID,
			"user_admin":              userAdminID,
			"auth_admin":              authAdminID,
			"helpdesk_admin":          helpdeskAdminID,
			"password_admin":          passwordAdminID,
			"priv_auth_admin":         privAuthAdminID,
			"groups_admin":            groupsAdminID,
			"conditional_access_admin": conditionalAccessAdminID,
			"exchange_admin":          exchangeAdminID,
			"regular":                 regularUserID,
		} {
			count := queryCount("MATCH (u:User {id: $id}) RETURN count(u) AS c", map[string]interface{}{"id": uid})
			assert.Equal(t, 1, count, "user %s (%s) should exist", name, uid)
		}

		// Groups
		for name, gid := range map[string]string{
			"privileged_group": groupPrivilegedID,
			"regular_group":    groupRegularID,
		} {
			count := queryCount("MATCH (g:Group {id: $id}) RETURN count(g) AS c", map[string]interface{}{"id": gid})
			assert.Equal(t, 1, count, "group %s should exist", name)
		}

		// Service principals
		for name, spid := range map[string]string{
			"privileged_sp": privilegedSPObjectID,
			"regular_sp":    regularSPObjectID,
		} {
			count := queryCount("MATCH (sp:ServicePrincipal {id: $id}) RETURN count(sp) AS c", map[string]interface{}{"id": spid})
			assert.Equal(t, 1, count, "SP %s should exist", name)
		}

		// Applications
		count := queryCount("MATCH (a:Application {id: $id}) RETURN count(a) AS c",
			map[string]interface{}{"id": privilegedAppObjectID})
		assert.Equal(t, 1, count, "privileged app should exist")

		// Subscription
		count = queryCount("MATCH (s:Subscription {id: $id}) RETURN count(s) AS c",
			map[string]interface{}{"id": subscriptionID})
		assert.Equal(t, 1, count, "subscription should exist")

		// Managed Identity
		count = queryCount("MATCH (mi:ManagedIdentity {id: $id}) RETURN count(mi) AS c",
			map[string]interface{}{"id": miUserAssignedID})
		assert.Equal(t, 1, count, "user-assigned MI should exist")

		// AzureResource (VM)
		count = queryCount("MATCH (r:AzureResource {id: $id}) RETURN count(r) AS c",
			map[string]interface{}{"id": vmID})
		assert.Equal(t, 1, count, "VM resource should exist")
	})

	// Verify all expected node types are populated
	t.Run("all node types present", func(t *testing.T) {
		for _, tc := range []struct {
			label string
			min   int
		}{
			{"User", 12},              // 12 fixture + tenant users
			{"Group", 2},              // 2 fixture groups + tenant groups
			{"ServicePrincipal", 2},   // 2 fixture SPs + tenant SPs
			{"Application", 2},        // 2 fixture apps + tenant apps
			{"RoleDefinition", 1},     // Entra directory role definitions
			{"DirectoryRole", 1},      // Activated Entra directory roles
			{"Device", 0},             // Devices (may be 0 in test tenant)
			{"ManagementGroup", 1},    // At least tenant root group
			{"Subscription", len(subIDs)}, // One per collected subscription
			{"RBACRoleDefinition", 1}, // Azure RBAC role definitions
			{"ManagedIdentity", 2},    // User-assigned + system-assigned
			{"AzureResource", 1},      // VM
		} {
			count := queryCount(fmt.Sprintf("MATCH (n:%s) RETURN count(n) AS c", tc.label), nil)
			assert.GreaterOrEqual(t, count, tc.min, "%s nodes should be >= %d (got %d)", tc.label, tc.min, count)
		}
	})

	// =====================================================================
	// Result 2: Relationship counts (minimum, fixture-scoped)
	// =====================================================================
	t.Run("relationship count regression gate", func(t *testing.T) {
		totalCanEscalate := queryCount("MATCH ()-[r:CAN_ESCALATE]->() RETURN count(r) AS c", nil)
		t.Logf("Total CAN_ESCALATE edges: %d", totalCanEscalate)
		assert.GreaterOrEqual(t, totalCanEscalate, 50,
			"CAN_ESCALATE count should be at least 50 (have 20 methods x multiple targets)")

		hasPerm := queryCount("MATCH ()-[r:HAS_PERMISSION]->() RETURN count(r) AS c", nil)
		t.Logf("Total HAS_PERMISSION edges: %d", hasPerm)
		assert.GreaterOrEqual(t, hasPerm, 12,
			"HAS_PERMISSION should include at least 12 fixture directory role assignments")

		memberOf := queryCount("MATCH ()-[r:MEMBER_OF]->() RETURN count(r) AS c", nil)
		t.Logf("Total MEMBER_OF edges: %d", memberOf)
		assert.GreaterOrEqual(t, memberOf, 3,
			"MEMBER_OF should include at least 3 fixture group memberships")
	})

	// =====================================================================
	// Result 2b: Relationship integrity (per-type and per-source)
	// =====================================================================
	t.Run("relationship integrity", func(t *testing.T) {
		// OWNS: app_admin → privileged_app
		ownsCount := queryCount(
			"MATCH (u:User {id: $uid})-[:OWNS]->(a:Application {id: $aid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": appAdminID, "aid": privilegedAppObjectID})
		assert.GreaterOrEqual(t, ownsCount, 1, "app_admin should OWN privileged_app")

		// Total OWNS
		totalOwns := queryCount("MATCH ()-[r:OWNS]->() RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, totalOwns, 3, "at least 3 ownership relationships (app, group, SP)")

		// OWNS: app_admin → privileged_group
		ownsGroup := queryCount(
			"MATCH (u:User {id: $uid})-[:OWNS]->(g:Group {id: $gid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": appAdminID, "gid": groupPrivilegedID})
		assert.GreaterOrEqual(t, ownsGroup, 1, "app_admin should OWN privileged_group")

		// OWNS: user_admin → regular SP
		ownsSP := queryCount(
			"MATCH (u:User {id: $uid})-[:OWNS]->(sp:ServicePrincipal {id: $spid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": userAdminID, "spid": regularSPObjectID})
		assert.GreaterOrEqual(t, ownsSP, 1, "user_admin should OWN regular SP")

		// HAS_PERMISSION by source — each of the 4 sources should have edges
		for _, source := range []string{
			"Entra ID Directory Role",
			"Azure RBAC",
			"Microsoft Graph App Role",
			"Microsoft Graph OAuth2",
		} {
			count := queryCount(
				"MATCH ()-[r:HAS_PERMISSION {source: $src}]->() RETURN count(r) AS c",
				map[string]interface{}{"src": source})
			assert.Greater(t, count, 0, "HAS_PERMISSION source '%s' should have at least 1 edge", source)
			t.Logf("  HAS_PERMISSION [%s]: %d", source, count)
		}

		// Specific HAS_PERMISSION: fixture directory role assignments (7 admins)
		fixturePermCount := queryCount(
			"MATCH (u:User)-[r:HAS_PERMISSION {source: 'Entra ID Directory Role'}]->() WHERE u.displayName CONTAINS $prefix RETURN count(r) AS c",
			map[string]interface{}{"prefix": prefix})
		assert.GreaterOrEqual(t, fixturePermCount, 11, "at least 11 fixture directory role assignments (12 total but group role may not match prefix filter)")

		// Specific HAS_PERMISSION: privileged SP has Graph App Role on Microsoft Graph
		spGraphPerm := queryCount(
			"MATCH (sp:ServicePrincipal {id: $spid})-[r:HAS_PERMISSION {source: 'Microsoft Graph App Role'}]->(target:ServicePrincipal {id: $msgid}) RETURN count(r) AS c",
			map[string]interface{}{"spid": privilegedSPObjectID, "msgid": msgraphSPObjectID})
		assert.GreaterOrEqual(t, spGraphPerm, 1, "privileged SP should have Graph App Role permission on Microsoft Graph SP")

		// MEMBER_OF: specific fixture group memberships
		regularInGroup := queryCount(
			"MATCH (u:User {id: $uid})-[:MEMBER_OF]->(g:Group {id: $gid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": regularUserID, "gid": groupRegularID})
		assert.Equal(t, 1, regularInGroup, "regular user should be MEMBER_OF regular group")

		authInGroup := queryCount(
			"MATCH (u:User {id: $uid})-[:MEMBER_OF]->(g:Group {id: $gid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": authAdminID, "gid": groupPrivilegedID})
		assert.Equal(t, 1, authInGroup, "auth admin should be MEMBER_OF privileged group")

		// Nested group: privileged_group → regular_group
		nestedGroup := queryCount(
			"MATCH (g1:Group {id: $g1id})-[:MEMBER_OF]->(g2:Group {id: $g2id}) RETURN count(g1) AS c",
			map[string]interface{}{"g1id": groupPrivilegedID, "g2id": groupRegularID})
		assert.Equal(t, 1, nestedGroup, "privileged group should be nested MEMBER_OF regular group")

		// CONTAINS: management group hierarchy
		mgmtContains := queryCount(
			"MATCH (:ManagementGroup)-[r:CONTAINS]->() RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, mgmtContains, 3, "management group hierarchy should have at least 3 CONTAINS edges")

		// CONTAINS: Resource → MI (VM → user-assigned MI)
		resourceToMI := queryCount(
			"MATCH (:AzureResource)-[r:CONTAINS]->(:ManagedIdentity) RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, resourceToMI, 1, "at least 1 Resource→MI CONTAINS edge")

		// CONTAINS: MI → SP
		miToSP := queryCount(
			"MATCH (:ManagedIdentity)-[r:CONTAINS]->(:ServicePrincipal) RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, miToSP, 1, "at least 1 MI→SP CONTAINS edge")
	})

	// =====================================================================
	// Result 3: CAN_ESCALATE method coverage
	// =====================================================================
	t.Run("CAN_ESCALATE method coverage", func(t *testing.T) {
		// Every enrichment method that should fire for our fixtures
		expectedMethods := []string{
			// Directory role escalation
			"GlobalAdministrator",
			"PrivilegedRoleAdmin",
			"ApplicationAdmin",
			"GroupsAdministrator",
			// Password reset chains
			"PasswordResetViaGlobalAdmin",
			"PasswordResetViaAuthAdmin",
			"PasswordResetViaUserAdmin",
			"PasswordResetViaHelpdeskAdmin",
			"PasswordResetViaPasswordAdmin",
			"PasswordResetViaPrivilegedAuthAdmin",
			// Graph API permission escalation
			"GraphRoleManagement",
			"GraphAppRoleAssignment",
			"GraphUserReadWrite",
			"GraphApplicationReadWrite",
			"DirectoryReadWriteAll",
			"GraphGroupReadWrite",
			// RBAC escalation
			"AzureOwner",
			"UserAccessAdmin",
			// Application/SP/Group ownership escalation
			"ApplicationAddSecret",
			"ServicePrincipalAddSecret",
			"ApplicationToServicePrincipal",
			"GroupOwnership",
			// Managed identity chain
			"ManagedIdentityToServicePrincipal",
			"ResourceAttachedIdentity",
		}

		for _, method := range expectedMethods {
			count := queryCount(
				"MATCH ()-[r:CAN_ESCALATE {method: $method}]->() RETURN count(r) AS c",
				map[string]interface{}{"method": method},
			)
			assert.Greater(t, count, 0, "CAN_ESCALATE method %s should have at least 1 edge", method)
			t.Logf("  %-40s %d", method, count)
		}
	})

	// =====================================================================
	// Result 4: Specific fixture escalation paths (spot-checks)
	// =====================================================================
	t.Run("Global Admin escalation paths", func(t *testing.T) {
		assert.True(t, edgeExists(globalAdminID, "GlobalAdministrator", regularUserID),
			"Global Admin should be able to escalate to regular user")
		assert.True(t, edgeExists(globalAdminID, "GlobalAdministrator", privRoleAdminID),
			"Global Admin should be able to escalate to priv role admin")
		assert.True(t, edgeExists(globalAdminID, "PasswordResetViaGlobalAdmin", regularUserID),
			"Global Admin should be able to reset regular user password")
	})

	t.Run("Privileged Role Admin escalation paths", func(t *testing.T) {
		assert.True(t, edgeExists(privRoleAdminID, "PrivilegedRoleAdmin", regularUserID),
			"Priv Role Admin should be able to escalate to regular user")
		assert.True(t, edgeExists(privRoleAdminID, "PrivilegedRoleAdmin", globalAdminID),
			"Priv Role Admin should be able to escalate to Global Admin")
	})

	t.Run("Application Admin escalation paths", func(t *testing.T) {
		assert.True(t, edgeExists(appAdminID, "ApplicationAdmin", privilegedSPObjectID),
			"App Admin should be able to escalate to privileged SP")
		assert.True(t, edgeExists(appAdminID, "ApplicationAddSecret", privilegedSPObjectID),
			"App Admin should be able to add secret to privileged SP via app ownership")
	})

	t.Run("Groups Admin escalation paths", func(t *testing.T) {
		assert.True(t, edgeExists(groupsAdminID, "GroupsAdministrator", groupPrivilegedID),
			"Groups Admin should be able to escalate to privileged group")
		assert.True(t, edgeExists(groupsAdminID, "GroupsAdministrator", groupRegularID),
			"Groups Admin should be able to escalate to regular group")
	})

	t.Run("Group and SP ownership escalation paths", func(t *testing.T) {
		// app_admin owns privileged_group which has role assignments → GroupOwnership
		groupOwnerCount := queryCount(
			"MATCH (a {id: $id})-[r:CAN_ESCALATE {method: 'GroupOwnership'}]->() RETURN count(r) AS c",
			map[string]interface{}{"id": appAdminID})
		assert.GreaterOrEqual(t, groupOwnerCount, 1,
			"app_admin should have GroupOwnership CAN_ESCALATE edges via group ownership")

		// user_admin owns regular SP → ServicePrincipalAddSecret
		spOwnerCount := queryCount(
			"MATCH (a {id: $id})-[r:CAN_ESCALATE {method: 'ServicePrincipalAddSecret'}]->() RETURN count(r) AS c",
			map[string]interface{}{"id": userAdminID})
		assert.GreaterOrEqual(t, spOwnerCount, 1,
			"user_admin should have ServicePrincipalAddSecret CAN_ESCALATE edge via SP ownership")
	})

	t.Run("Password reset chains with target filtering", func(t *testing.T) {
		// Auth admin can reset regular user (non-admin)
		assert.True(t, edgeExists(authAdminID, "PasswordResetViaAuthAdmin", regularUserID),
			"Auth Admin should be able to reset regular user password")

		// User admin can reset regular user
		assert.True(t, edgeExists(userAdminID, "PasswordResetViaUserAdmin", regularUserID),
			"User Admin should be able to reset regular user password")

		// Helpdesk admin can reset regular user
		assert.True(t, edgeExists(helpdeskAdminID, "PasswordResetViaHelpdeskAdmin", regularUserID),
			"Helpdesk Admin should be able to reset regular user password")

		// Password admin can reset regular user
		assert.True(t, edgeExists(passwordAdminID, "PasswordResetViaPasswordAdmin", regularUserID),
			"Password Admin should be able to reset regular user password")

		// Privileged Auth Admin can reset ANY user including Global Admin
		assert.True(t, edgeExists(privAuthAdminID, "PasswordResetViaPrivilegedAuthAdmin", regularUserID),
			"Priv Auth Admin should be able to reset regular user password")
		assert.True(t, edgeExists(privAuthAdminID, "PasswordResetViaPrivilegedAuthAdmin", globalAdminID),
			"Priv Auth Admin should be able to reset Global Admin password (unlike Auth Admin)")

		// Global Admin should NOT be resettable by Auth Admin (target filtering)
		assert.False(t, edgeExists(authAdminID, "PasswordResetViaAuthAdmin", globalAdminID),
			"Auth Admin should NOT be able to reset Global Admin password")
	})

	t.Run("Graph API escalation paths", func(t *testing.T) {
		assert.True(t, edgeExists(privilegedSPObjectID, "GraphRoleManagement", regularUserID),
			"Privileged SP with RoleManagement.ReadWrite.Directory should escalate to user")
		assert.True(t, edgeExists(privilegedSPObjectID, "GraphAppRoleAssignment", privilegedSPObjectID),
			"Privileged SP should self-escalate via AppRoleAssignment")
	})

	t.Run("Managed Identity escalation chain", func(t *testing.T) {
		// Resource → MI → SP chain
		miCount := queryCount(
			"MATCH ()-[r:CAN_ESCALATE {method: 'ResourceAttachedIdentity'}]->() RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, miCount, 1,
			"should have at least 1 ResourceAttachedIdentity edge (VM → MI)")

		mi2spCount := queryCount(
			"MATCH ()-[r:CAN_ESCALATE {method: 'ManagedIdentityToServicePrincipal'}]->() RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, mi2spCount, 1,
			"should have at least 1 ManagedIdentityToServicePrincipal edge (MI → SP)")

		// Verify VM resource is in the chain
		vmInChain := queryCount(
			"MATCH (r:AzureResource {id: $vmid})-[:CAN_ESCALATE]->() RETURN count(r) AS c",
			map[string]interface{}{"vmid": vmID})
		assert.GreaterOrEqual(t, vmInChain, 1, "VM should have CAN_ESCALATE edges to attached MIs")

		// User-assigned MI CONTAINS relationship exists
		uaMIContains := queryCount(
			"MATCH (mi:ManagedIdentity {id: $miid})-[:CONTAINS]->(:ServicePrincipal) RETURN count(mi) AS c",
			map[string]interface{}{"miid": miUserAssignedID})
		assert.GreaterOrEqual(t, uaMIContains, 1, "user-assigned MI should CONTAINS its SP")
	})

	t.Run("RBAC escalation paths", func(t *testing.T) {
		ownerCount := queryCount(
			"MATCH (a {id: $id})-[r:CAN_ESCALATE {method: 'AzureOwner'}]->() RETURN count(r) AS c",
			map[string]interface{}{"id": globalAdminID})
		assert.GreaterOrEqual(t, ownerCount, 1,
			"Global Admin with Owner RBAC should have AzureOwner CAN_ESCALATE edges")

		uaaCount := queryCount(
			"MATCH (a {id: $id})-[r:CAN_ESCALATE {method: 'UserAccessAdmin'}]->() RETURN count(r) AS c",
			map[string]interface{}{"id": privRoleAdminID})
		assert.GreaterOrEqual(t, uaaCount, 1,
			"Priv Role Admin with UAA RBAC should have UserAccessAdmin CAN_ESCALATE edges")
	})

	// =====================================================================
	// Result 5: Enrichment markers
	// =====================================================================
	t.Run("enrichment markers", func(t *testing.T) {
		// Core detection markers
		globalAdmins := queryCount("MATCH (n {_isGlobalAdmin: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, globalAdmins, 1, "at least 1 Global Admin detected")

		privilegedRoleHolders := queryCount("MATCH (n {_hasPrivilegedRole: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, privilegedRoleHolders, 7, "at least 7 privileged role holders")

		canEscalators := queryCount("MATCH (n {_canEscalate: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, canEscalators, 1, "at least 1 principal marked _canEscalate")

		// Graph API permission markers
		graphPerms := queryCount("MATCH (n {_hasGraphApiPermissions: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, graphPerms, 1, "at least 1 principal with _hasGraphApiPermissions")

		// Escalation sub-type markers
		appCredEscalators := queryCount("MATCH (n {_canEscalateViaAppCreds: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, appCredEscalators, 1, "at least 1 principal with _canEscalateViaAppCreds (Application Admin)")

		pwdResetEscalators := queryCount("MATCH (n {_canEscalateViaPasswordReset: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, pwdResetEscalators, 1, "at least 1 principal with _canEscalateViaPasswordReset")

		roleAssignEscalators := queryCount("MATCH (n {_canEscalateViaRoleAssignment: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, roleAssignEscalators, 1, "at least 1 principal with _canEscalateViaRoleAssignment (Priv Role Admin)")

		// Fixture-specific marker checks
		globalAdminMarker := queryCount(
			"MATCH (n:User {id: $id, _isGlobalAdmin: true}) RETURN count(n) AS c",
			map[string]interface{}{"id": globalAdminID})
		assert.Equal(t, 1, globalAdminMarker, "fixture Global Admin should have _isGlobalAdmin marker")

		privRoleMarker := queryCount(
			"MATCH (n:User {id: $id, _canEscalateViaRoleAssignment: true}) RETURN count(n) AS c",
			map[string]interface{}{"id": privRoleAdminID})
		assert.Equal(t, 1, privRoleMarker, "fixture Priv Role Admin should have _canEscalateViaRoleAssignment marker")

		// Group ownership escalation marker
		groupOwnershipEscalators := queryCount("MATCH (n {_canEscalateViaGroupOwnership: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, groupOwnershipEscalators, 1, "at least 1 principal with _canEscalateViaGroupOwnership")

		// Conditional Access Admin marker (marker only, no CAN_ESCALATE edges)
		policyBypassCount := queryCount("MATCH (n {_canEscalateViaPolicyBypass: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, policyBypassCount, 1, "at least 1 principal with _canEscalateViaPolicyBypass (Conditional Access Admin)")

		condAccessMarker := queryCount(
			"MATCH (n:User {id: $id, _canEscalateViaPolicyBypass: true}) RETURN count(n) AS c",
			map[string]interface{}{"id": conditionalAccessAdminID})
		assert.Equal(t, 1, condAccessMarker, "fixture Conditional Access Admin should have _canEscalateViaPolicyBypass marker")

		// Exchange/Service Admin marker (marker only, no CAN_ESCALATE edges)
		serviceAdminCount := queryCount("MATCH (n {_canEscalateViaServiceAdmin: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, serviceAdminCount, 1, "at least 1 principal with _canEscalateViaServiceAdmin (Exchange Admin)")

		exchangeMarker := queryCount(
			"MATCH (n:User {id: $id, _canEscalateViaServiceAdmin: true}) RETURN count(n) AS c",
			map[string]interface{}{"id": exchangeAdminID})
		assert.Equal(t, 1, exchangeMarker, "fixture Exchange Admin should have _canEscalateViaServiceAdmin marker")

		// Management group enrichment (management_group_hierarchy.yaml)
		mgmtEnriched := queryCount("MATCH (n:ManagementGroup {_enriched: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, mgmtEnriched, 1, "at least 1 management group should be enriched")

		// Management group _childCount (management_group_hierarchy.yaml)
		mgmtWithChildren := queryCount("MATCH (n:ManagementGroup) WHERE n._childCount > 0 RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, mgmtWithChildren, 1, "at least 1 management group should have _childCount > 0")

		// Stale credentials enrichment (stale_credentials.yaml)
		// The Cypher sets _enriched=true on Application nodes WHERE credentials IS NOT NULL.
		// The privileged_app has an azuread_application_password so it should have a non-null
		// credentials property after iam-pull collection, causing the enrichment to fire.
		appsEnriched := queryCount("MATCH (a:Application {_enriched: true}) RETURN count(a) AS c", nil)
		assert.GreaterOrEqual(t, appsEnriched, 1, "at least 1 application should be enriched by stale_credentials (privileged_app has a credential)")

		// Dangerous Graph API permissions (dangerous_graph_permissions.yaml)
		graphApiMarker := queryCount(
			"MATCH (sp:ServicePrincipal {id: $id, _hasGraphApiPermissions: true}) RETURN count(sp) AS c",
			map[string]interface{}{"id": privilegedSPObjectID})
		assert.Equal(t, 1, graphApiMarker, "privileged SP should have _hasGraphApiPermissions marker")

		// Transitive group permissions (transitive_group_permissions.yaml)
		// auth_admin is MEMBER_OF privileged_group which HAS_PERMISSION → should get _hasTransitiveRole
		transitiveRole := queryCount("MATCH (n {_hasTransitiveRole: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, transitiveRole, 1, "at least 1 principal with _hasTransitiveRole (via group membership)")

		// Group owner potential permissions (group_owner_potential_permissions.yaml)
		// app_admin OWNS privileged_group which HAS_PERMISSION → should get _hasPotentialPermissions
		potentialPerms := queryCount("MATCH (n {_hasPotentialPermissions: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, potentialPerms, 1, "at least 1 principal with _hasPotentialPermissions (group owner)")

		// _potentialViaGroup is set to the group's displayName (string), not boolean
		potentialViaGroup := queryCount("MATCH (n) WHERE n._potentialViaGroup IS NOT NULL RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, potentialViaGroup, 1, "at least 1 principal with _potentialViaGroup")

		// Owner-to-privileged-app (owner_to_privileged_app.yaml)
		// app_admin OWNS privileged_app, and privileged SP has HAS_PERMISSION
		canEscalateViaApp := queryCount("MATCH (n {_canEscalateViaApp: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, canEscalateViaApp, 1, "at least 1 principal with _canEscalateViaApp (app owner with privileged SP)")

		// PIM permanent classification (pim_permanent_classification.yaml)
		// Directory role assignments without PIM should get assignmentType='Permanent'
		permanentAssignments := queryCount(
			"MATCH ()-[r:HAS_PERMISSION {source: 'Entra ID Directory Role', assignmentType: 'Permanent'}]->() RETURN count(r) AS c", nil)
		assert.GreaterOrEqual(t, permanentAssignments, 11, "at least 11 fixture directory role assignments classified as Permanent")

		// Group nesting paths (group_nesting_paths.yaml)
		// The Cypher matches paths (u:User)-[:MEMBER_OF*1..3]->(g:Group)-[:HAS_PERMISSION]->(rd:RoleDefinition)
		// WHERE length(path) > 2 (i.e. at least 2 MEMBER_OF hops + 1 HAS_PERMISSION).
		// With the synthetic HAS_PERMISSION on regular_group (step 5b), the path is:
		//   auth_admin -[:MEMBER_OF]-> privileged_group -[:MEMBER_OF]-> regular_group -[:HAS_PERMISSION]-> RoleDefinition
		// which has length 3, passing the > 2 filter.
		transitivePriv := queryCount("MATCH (n {_hasTransitivePrivilege: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, transitivePriv, 1, "at least 1 user should have _hasTransitivePrivilege via nested group path (auth_admin through 2 groups)")

		// Cross-subscription admin (cross_subscription_admin.yaml)
		if secondSubscriptionID != "" {
			crossSubAdmins := queryCount("MATCH (n {_crossSubAdmin: true}) RETURN count(n) AS c", nil)
			assert.GreaterOrEqual(t, crossSubAdmins, 1, "at least 1 principal with _crossSubAdmin (CLI user with Owner on 2 subs)")
		}
	})

	// =====================================================================
	// Result 6: Edge and node metadata validation
	// =====================================================================
	t.Run("CAN_ESCALATE edge metadata", func(t *testing.T) {
		// Validate every category has correct metadata structure.
		// Each CAN_ESCALATE edge must have: method, condition (non-empty string), category.
		// DirectoryRole and RBAC edges also carry a source property.

		type edgeCase struct {
			name       string
			attackerID string
			method     string
			targetID   string
			category   string
			hasSource  bool
		}

		cases := []edgeCase{
			// DirectoryRole category (has source)
			{"GlobalAdmin→regular", globalAdminID, "GlobalAdministrator", regularUserID, "DirectoryRole", true},
			{"PrivRoleAdmin→globalAdmin", privRoleAdminID, "PrivilegedRoleAdmin", globalAdminID, "DirectoryRole", true},
			{"AppAdmin→privilegedSP", appAdminID, "ApplicationAdmin", privilegedSPObjectID, "DirectoryRole", true},
			{"GroupsAdmin→privilegedGroup", groupsAdminID, "GroupsAdministrator", groupPrivilegedID, "DirectoryRole", true},
			{"AuthAdmin→regular (pwdReset)", authAdminID, "PasswordResetViaAuthAdmin", regularUserID, "DirectoryRole", true},
			{"UserAdmin→regular (pwdReset)", userAdminID, "PasswordResetViaUserAdmin", regularUserID, "DirectoryRole", true},
			{"HelpdeskAdmin→regular (pwdReset)", helpdeskAdminID, "PasswordResetViaHelpdeskAdmin", regularUserID, "DirectoryRole", true},
			{"PasswordAdmin→regular (pwdReset)", passwordAdminID, "PasswordResetViaPasswordAdmin", regularUserID, "DirectoryRole", true},
			{"PrivAuthAdmin→globalAdmin (pwdReset)", privAuthAdminID, "PasswordResetViaPrivilegedAuthAdmin", globalAdminID, "DirectoryRole", true},
			{"GlobalAdmin→regular (pwdResetGA)", globalAdminID, "PasswordResetViaGlobalAdmin", regularUserID, "DirectoryRole", true},
			// GraphPermission category (no source)
			{"PrivSP→regular (GraphRoleMgmt)", privilegedSPObjectID, "GraphRoleManagement", regularUserID, "GraphPermission", false},
			{"PrivSP→self (GraphAppRole)", privilegedSPObjectID, "GraphAppRoleAssignment", privilegedSPObjectID, "GraphPermission", false},
			// RBAC category (has source)
			{"GlobalAdmin→AzureOwner", globalAdminID, "AzureOwner", subscriptionID, "RBAC", true},
			// ApplicationOwnership category (no source)
			{"AppAdmin→privilegedSP (AppAddSecret)", appAdminID, "ApplicationAddSecret", privilegedSPObjectID, "ApplicationOwnership", false},
			{"UserAdmin→regularSP (SPAddSecret)", userAdminID, "ServicePrincipalAddSecret", regularSPObjectID, "ApplicationOwnership", false},
			// GroupOwnership category (no source)
			{"AppAdmin→privilegedGroup (GroupOwn)", appAdminID, "GroupOwnership", groupPrivilegedID, "GroupOwnership", false},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				props := edgeProps(tc.attackerID, tc.method, tc.targetID)
				if !assert.NotNil(t, props, "edge should exist: %s -[%s]-> %s", tc.attackerID, tc.method, tc.targetID) {
					return
				}

				// method
				assert.Equal(t, tc.method, props["method"], "method property")

				// category
				assert.Equal(t, tc.category, props["category"], "category property")

				// condition (non-empty string)
				cond, ok := props["condition"].(string)
				assert.True(t, ok && len(cond) > 10, "condition should be a descriptive string, got: %v", props["condition"])

				// source (only for DirectoryRole and RBAC categories)
				if tc.hasSource {
					src, ok := props["source"].(string)
					assert.True(t, ok && src != "", "source property should be set for %s category, got: %v", tc.category, props["source"])
				}
			})
		}
	})

	t.Run("HAS_PERMISSION edge metadata", func(t *testing.T) {
		// Validate HAS_PERMISSION edges carry correct source and properties
		type permCase struct {
			name     string
			nodeID   string
			source   string
			minCount int
		}

		permCases := []permCase{
			{"globalAdmin Entra role", globalAdminID, "Entra ID Directory Role", 1},
			{"globalAdmin Azure RBAC", globalAdminID, "Azure RBAC", 1},
			{"privilegedSP Graph App Role", privilegedSPObjectID, "Microsoft Graph App Role", 1},
		}

		for _, tc := range permCases {
			count := queryCount(
				"MATCH ({id: $id})-[r:HAS_PERMISSION {source: $src}]->() RETURN count(r) AS c",
				map[string]interface{}{"id": tc.nodeID, "src": tc.source})
			assert.GreaterOrEqual(t, count, tc.minCount,
				"%s: expected at least %d HAS_PERMISSION edges with source '%s'", tc.name, tc.minCount, tc.source)
		}

		// Validate PIM permanent classification (pim_permanent_classification.yaml)
		// Non-PIM directory role assignments should have assignmentType='Permanent'
		permanentCount := queryCount(
			"MATCH ({id: $id})-[r:HAS_PERMISSION {source: 'Entra ID Directory Role', assignmentType: 'Permanent'}]->() RETURN count(r) AS c",
			map[string]interface{}{"id": globalAdminID})
		assert.GreaterOrEqual(t, permanentCount, 1, "global admin directory role should be classified as Permanent")

		// Validate Entra directory role assignments carry directoryScopeId
		dirRoleResult, err := db.Query(ctx,
			"MATCH ({id: $id})-[r:HAS_PERMISSION {source: 'Entra ID Directory Role'}]->() RETURN r.directoryScopeId AS scope LIMIT 1",
			map[string]interface{}{"id": globalAdminID})
		require.NoError(t, err)
		if assert.NotEmpty(t, dirRoleResult.Records, "should find Entra role assignment for global admin") {
			// directoryScopeId is typically "/" for tenant-wide assignments
			scope, _ := dirRoleResult.Records[0]["scope"].(string)
			assert.NotEmpty(t, scope, "directoryScopeId should be set on directory role HAS_PERMISSION")
		}
	})

	t.Run("node enrichment properties", func(t *testing.T) {
		// Validate enrichment markers are set on the correct fixture nodes
		type nodeCase struct {
			name     string
			nodeID   string
			props    []string
			expected map[string]interface{}
		}

		nodeCases := []nodeCase{
			{
				"Global Admin markers",
				globalAdminID,
				[]string{"_isGlobalAdmin", "_hasPrivilegedRole", "_canEscalate"},
				map[string]interface{}{"_isGlobalAdmin": true, "_hasPrivilegedRole": true, "_canEscalate": true},
			},
			{
				"Priv Role Admin markers",
				privRoleAdminID,
				[]string{"_hasPrivilegedRole", "_canEscalateViaRoleAssignment", "_canEscalate"},
				map[string]interface{}{"_hasPrivilegedRole": true, "_canEscalateViaRoleAssignment": true, "_canEscalate": true},
			},
			{
				"App Admin markers",
				appAdminID,
				[]string{"_hasPrivilegedRole", "_canEscalateViaAppCreds", "_canEscalate", "_canEscalateViaGroupOwnership", "_canEscalateViaApp", "_hasPotentialPermissions"},
				map[string]interface{}{"_hasPrivilegedRole": true, "_canEscalateViaAppCreds": true, "_canEscalate": true, "_canEscalateViaGroupOwnership": true, "_canEscalateViaApp": true, "_hasPotentialPermissions": true},
			},
			{
				"Auth Admin transitive markers",
				authAdminID,
				[]string{"_hasTransitiveRole"},
				map[string]interface{}{"_hasTransitiveRole": true},
			},
			{
				"Conditional Access Admin markers",
				conditionalAccessAdminID,
				[]string{"_canEscalateViaPolicyBypass"},
				map[string]interface{}{"_canEscalateViaPolicyBypass": true},
			},
			{
				"Exchange Admin markers",
				exchangeAdminID,
				[]string{"_canEscalateViaServiceAdmin"},
				map[string]interface{}{"_canEscalateViaServiceAdmin": true},
			},
			{
				"Privileged SP Graph API markers",
				privilegedSPObjectID,
				[]string{"_hasGraphApiPermissions", "_canEscalate"},
				map[string]interface{}{"_hasGraphApiPermissions": true, "_canEscalate": true},
			},
		}

		for _, tc := range nodeCases {
			t.Run(tc.name, func(t *testing.T) {
				props := nodeProps(tc.nodeID, tc.props...)
				require.NotNil(t, props, "node %s should exist", tc.nodeID)
				for key, expected := range tc.expected {
					assert.Equal(t, expected, props[key], "property %s on node %s", key, tc.name)
				}
			})
		}

		// Negative: regular user should NOT have privileged markers
		regularProps := nodeProps(regularUserID, "_isGlobalAdmin", "_hasPrivilegedRole", "_canEscalate")
		require.NotNil(t, regularProps)
		assert.Nil(t, regularProps["_isGlobalAdmin"], "regular user should NOT be _isGlobalAdmin")
		assert.Nil(t, regularProps["_hasPrivilegedRole"], "regular user should NOT have _hasPrivilegedRole")
		assert.Nil(t, regularProps["_canEscalate"], "regular user should NOT have _canEscalate")
	})

	// =====================================================================
	// Result 7: PIM eligible escalation enrichment (synthetic)
	// =====================================================================
	t.Run("PIM eligible escalation enrichment", func(t *testing.T) {
		// Inject synthetic PIM-style HAS_PERMISSION edges to validate the
		// pim_eligible_escalation.yaml enrichment query fires correctly.
		// This is synthetic because the PIM collector requires an app registration
		// with RoleManagement.Read.Directory permission (the CLI app can't consent).

		// Create a synthetic PIM eligible edge: regular_user → Global Administrator role def
		// First, find the Global Administrator RoleDefinition node
		gaRoleDef, err := db.Query(ctx,
			"MATCH (rd:RoleDefinition) WHERE rd.displayName = 'Global Administrator' RETURN rd.id AS id LIMIT 1", nil)
		require.NoError(t, err)
		if len(gaRoleDef.Records) == 0 {
			t.Skip("Global Administrator RoleDefinition not found in graph — cannot test PIM enrichment")
		}
		gaRoleDefID := gaRoleDef.Records[0]["id"].(string)

		// Create synthetic PIM eligible HAS_PERMISSION edge
		_, err = db.Query(ctx,
			"MATCH (u:User {id: $uid}), (rd:RoleDefinition {id: $rdid}) "+
				"CREATE (u)-[:HAS_PERMISSION {source: 'PIM', assignmentType: 'eligible', roleDefinitionId: $rdid, directoryScopeId: '/'}]->(rd)",
			map[string]interface{}{
				"uid":  regularUserID,
				"rdid": gaRoleDefID,
			})
		require.NoError(t, err)

		// Re-run enrichment to trigger pim_eligible_escalation.yaml
		err = queries.EnrichAzure(ctx, db)
		require.NoError(t, err)

		// Validate PIM enrichment markers
		pimEscalation := queryCount(
			"MATCH (n:User {id: $id}) WHERE n._hasPIMEscalation = true RETURN count(n) AS c",
			map[string]interface{}{"id": regularUserID})
		assert.Equal(t, 1, pimEscalation,
			"regular user with PIM eligible Global Admin should have _hasPIMEscalation=true")

		// Validate _isPrivilegedEligible on the relationship
		privEligible := queryCount(
			"MATCH (:User {id: $uid})-[r:HAS_PERMISSION {source: 'PIM', assignmentType: 'eligible'}]->(:RoleDefinition {id: $rdid}) "+
				"WHERE r._isPrivilegedEligible = true RETURN count(r) AS c",
			map[string]interface{}{"uid": regularUserID, "rdid": gaRoleDefID})
		assert.Equal(t, 1, privEligible,
			"PIM eligible edge to Global Admin should have _isPrivilegedEligible=true")

		// Global count check
		allPIMEscalation := queryCount("MATCH (n {_hasPIMEscalation: true}) RETURN count(n) AS c", nil)
		assert.GreaterOrEqual(t, allPIMEscalation, 1, "at least 1 principal with _hasPIMEscalation")
	})

	// =====================================================================
	// Result 7b: PIM eligible escalation (live — requires PIM app credentials)
	// =====================================================================
	t.Run("PIM eligible escalation live", func(t *testing.T) {
		pimClientID := os.Getenv("AZURE_PIM_CLIENT_ID")
		pimClientSecret := os.Getenv("AZURE_PIM_CLIENT_SECRET")
		tenantID := fixture.Output("tenant_id")

		if pimClientID == "" || pimClientSecret == "" {
			t.Skip("AZURE_PIM_CLIENT_ID / AZURE_PIM_CLIENT_SECRET not set — skipping live PIM test. " +
				"Set these from Terraform outputs: pim_app_client_id / pim_app_client_secret")
		}

		// Authenticate as the PIM reader app
		cred, err := azidentity.NewClientSecretCredential(tenantID, pimClientID, pimClientSecret, nil)
		require.NoError(t, err, "failed to create PIM app credential")

		// Collect PIM data
		pimCollector := iam.NewPIMCollector(cred)
		pimData, err := pimCollector.Collect(ctx)
		require.NoError(t, err, "PIM collection should succeed with app credentials")

		t.Logf("Live PIM: active=%d, eligible=%d",
			len(pimData.ActiveAssignments), len(pimData.EligibleAssignments))

		// Transform PIM data and push to graph
		pimRels := azuretransform.TransformPIMData(pimData)
		if len(pimRels) > 0 {
			_, err = db.CreateRelationships(ctx, pimRels)
			require.NoError(t, err)
		}

		// Re-run enrichment
		err = queries.EnrichAzure(ctx, db)
		require.NoError(t, err)

		// Validate: regular_user has PIM eligible assignment for Global Admin
		assert.GreaterOrEqual(t, len(pimData.EligibleAssignments), 1,
			"should have at least 1 eligible PIM assignment (regular_user → Global Admin)")

		// Validate enrichment fired on live data
		livePIMEscalation := queryCount(
			"MATCH (n:User {id: $id}) WHERE n._hasPIMEscalation = true RETURN count(n) AS c",
			map[string]interface{}{"id": regularUserID})
		assert.Equal(t, 1, livePIMEscalation,
			"regular user with live PIM eligible Global Admin should have _hasPIMEscalation=true")
	})

	// =====================================================================
	// Result 8: Cross-subscription admin enrichment
	// =====================================================================
	t.Run("cross-subscription admin enrichment", func(t *testing.T) {
		if secondSubscriptionID == "" {
			t.Skip("AZURE_SUBSCRIPTION_ID_2 not set — skipping cross-subscription admin test")
		}

		// The CLI user (who ran terraform / az login) has Owner on both subscriptions.
		// cross_subscription_admin.yaml should set _crossSubAdmin=true and _adminSubCount>=2.
		cliUserCrossAdmin := queryCount(
			"MATCH (n {id: $id}) WHERE n._crossSubAdmin = true RETURN count(n) AS c",
			map[string]interface{}{"id": cliUserObjectID})
		assert.Equal(t, 1, cliUserCrossAdmin,
			"CLI user (%s) should have _crossSubAdmin=true (Owner on 2 subscriptions)", cliUserObjectID)

		cliProps := nodeProps(cliUserObjectID, "_crossSubAdmin", "_adminSubCount")
		if assert.NotNil(t, cliProps, "CLI user node should exist") {
			assert.Equal(t, true, cliProps["_crossSubAdmin"], "_crossSubAdmin should be true")
			if adminCount, ok := cliProps["_adminSubCount"].(int64); ok {
				assert.GreaterOrEqual(t, adminCount, int64(2),
					"_adminSubCount should be >= 2 (CLI user is Owner on both subscriptions)")
			} else {
				t.Errorf("_adminSubCount should be an integer, got: %T %v", cliProps["_adminSubCount"], cliProps["_adminSubCount"])
			}
		}

		// Also verify that Subscription nodes exist for both subscriptions
		sub1Count := queryCount("MATCH (s:Subscription {id: $id}) RETURN count(s) AS c",
			map[string]interface{}{"id": subscriptionID})
		assert.Equal(t, 1, sub1Count, "primary subscription should exist")

		sub2Count := queryCount("MATCH (s:Subscription {id: $id}) RETURN count(s) AS c",
			map[string]interface{}{"id": secondSubscriptionID})
		assert.Equal(t, 1, sub2Count, "second subscription should exist")

		// Verify CLI user has HAS_PERMISSION to both subscriptions
		cliPermCount := queryCount(
			"MATCH ({id: $id})-[r:HAS_PERMISSION]->(s:Subscription) RETURN count(DISTINCT s) AS c",
			map[string]interface{}{"id": cliUserObjectID})
		assert.GreaterOrEqual(t, cliPermCount, 2,
			"CLI user should have HAS_PERMISSION edges to at least 2 subscriptions")
	})

	// =====================================================================
	// Diagnostic summary
	// =====================================================================
	t.Run("diagnostic summary", func(t *testing.T) {
		t.Logf("=== GRAPH PIPELINE SUMMARY ===")

		for _, label := range []string{"User", "Group", "ServicePrincipal", "Application",
			"RoleDefinition", "DirectoryRole", "Device", "Subscription", "RBACRoleDefinition",
			"ManagementGroup", "ManagedIdentity", "AzureResource"} {
			count := queryCount(fmt.Sprintf("MATCH (n:%s) RETURN count(n) AS c", label), nil)
			t.Logf("  %-25s %d", label, count)
		}

		t.Logf("  --- Relationships ---")
		for _, relType := range []string{"HAS_PERMISSION", "MEMBER_OF", "OWNS", "CONTAINS", "CAN_ESCALATE"} {
			count := queryCount(fmt.Sprintf("MATCH ()-[r:%s]->() RETURN count(r) AS c", relType), nil)
			t.Logf("  %-25s %d", relType, count)
		}

		t.Logf("  --- HAS_PERMISSION by source ---")
		sourceResult, err := db.Query(ctx, "MATCH ()-[r:HAS_PERMISSION]->() RETURN r.source AS source, count(r) AS c ORDER BY c DESC", nil)
		if err == nil {
			for _, rec := range sourceResult.Records {
				t.Logf("    %-35s %v", rec["source"], rec["c"])
			}
		}

		t.Logf("  --- CAN_ESCALATE by method (fixture principals) ---")
		methodResult, err := db.Query(ctx,
			"MATCH (a)-[r:CAN_ESCALATE]->(t) WHERE a.displayName CONTAINS $prefix RETURN r.method AS method, count(r) AS c ORDER BY c DESC",
			map[string]interface{}{"prefix": prefix})
		if err == nil {
			for _, rec := range methodResult.Records {
				t.Logf("    %-45s %v", rec["method"], rec["c"])
			}
		}

		// Log fixture-scoped totals
		fixtureCE := queryCount(
			"MATCH (a)-[r:CAN_ESCALATE]->() WHERE a.displayName CONTAINS $prefix OR a.id CONTAINS $prefix RETURN count(r) AS c",
			map[string]interface{}{"prefix": prefix})
		t.Logf("  Fixture-scoped CAN_ESCALATE edges: %d", fixtureCE)
	})
}
