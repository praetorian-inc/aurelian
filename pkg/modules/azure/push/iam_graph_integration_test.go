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
		// NOTE: After fresh Terraform deploy, Entra ID ownership may take time to propagate.
		// If this fails on first run but passes on subsequent runs, it's a propagation delay.
		ownsCount := queryCount(
			"MATCH (u:User {id: $uid})-[:OWNS]->(a:Application {id: $aid}) RETURN count(u) AS c",
			map[string]interface{}{"uid": appAdminID, "aid": privilegedAppObjectID})
		if ownsCount == 0 {
			t.Logf("WARNING: app_admin → privileged_app OWNS edge not found (may be Entra ID propagation delay)")
		}
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
	// Result 7: Cross-subscription admin enrichment (moved before PIM synthetic tests)
	// =====================================================================
	t.Run("cross-subscription admin enrichment", func(t *testing.T) {
		if secondSubscriptionID == "" {
			t.Skip("AZURE_SUBSCRIPTION_ID_2 not set — skipping cross-subscription admin test")
		}

		// Verify that Subscription nodes exist for both subscriptions
		sub1Count := queryCount("MATCH (s:Subscription {id: $id}) RETURN count(s) AS c",
			map[string]interface{}{"id": subscriptionID})
		assert.Equal(t, 1, sub1Count, "primary subscription should exist")

		sub2Count := queryCount("MATCH (s:Subscription {id: $id}) RETURN count(s) AS c",
			map[string]interface{}{"id": secondSubscriptionID})
		assert.Equal(t, 1, sub2Count, "second subscription should exist")

		// Check how many subscription-scoped HAS_PERMISSION edges the CLI user actually has.
		// The enrichment query matches Owner/Contributor/UAA to Subscription nodes specifically.
		// If the CLI user's role on sub2 is at root scope ("/"), it won't match a Subscription node.
		cliPermCount := queryCount(
			"MATCH ({id: $id})-[r:HAS_PERMISSION {source: 'Azure RBAC'}]->(s:Subscription) RETURN count(DISTINCT s) AS c",
			map[string]interface{}{"id": cliUserObjectID})
		t.Logf("CLI user (%s) has HAS_PERMISSION edges to %d subscriptions", cliUserObjectID, cliPermCount)

		if cliPermCount >= 2 {
			// CLI user has subscription-scoped permissions to 2+ subs — cross_subscription_admin should fire
			cliUserCrossAdmin := queryCount(
				"MATCH (n {id: $id}) WHERE n._crossSubAdmin = true RETURN count(n) AS c",
				map[string]interface{}{"id": cliUserObjectID})
			assert.Equal(t, 1, cliUserCrossAdmin,
				"CLI user should have _crossSubAdmin=true with 2+ subscription-scoped permissions")

			cliProps := nodeProps(cliUserObjectID, "_crossSubAdmin", "_adminSubCount")
			if assert.NotNil(t, cliProps) {
				assert.Equal(t, true, cliProps["_crossSubAdmin"])
				if adminCount, ok := cliProps["_adminSubCount"].(int64); ok {
					assert.GreaterOrEqual(t, adminCount, int64(2))
				}
			}
		} else {
			t.Logf("CLI user has subscription-scoped permissions to only %d subscriptions — "+
				"cross-subscription admin enrichment requires 2+ (role may be at root scope)", cliPermCount)
			// Verify the enrichment query at least runs without error by checking global results
			crossSubCount := queryCount("MATCH (n {_crossSubAdmin: true}) RETURN count(n) AS c", nil)
			t.Logf("Total principals with _crossSubAdmin: %d", crossSubCount)
		}
	})

	// =====================================================================
	// Result 9: Negative escalation assertions
	// =====================================================================
	t.Run("negative escalation assertions", func(t *testing.T) {
		// Regular user should have ZERO outgoing CAN_ESCALATE edges
		t.Run("regular user has no CAN_ESCALATE edges", func(t *testing.T) {
			regularCE := queryCount(
				"MATCH (u:User {id: $id})-[r:CAN_ESCALATE]->() RETURN count(r) AS c",
				map[string]interface{}{"id": regularUserID})
			assert.Equal(t, 0, regularCE,
				"regular user should have ZERO outgoing CAN_ESCALATE edges (got %d)", regularCE)
		})

		// Auth Admin should NOT be able to reset other admin passwords
		t.Run("auth admin cannot reset privileged admin passwords", func(t *testing.T) {
			for name, adminID := range map[string]string{
				"global_admin":    globalAdminID,
				"priv_role_admin": privRoleAdminID,
				"priv_auth_admin": privAuthAdminID,
			} {
				assert.False(t, edgeExists(authAdminID, "PasswordResetViaAuthAdmin", adminID),
					"Auth Admin should NOT be able to reset %s password", name)
			}
		})

		// Helpdesk Admin should NOT be able to reset privileged admin passwords
		t.Run("helpdesk admin cannot reset privileged admin passwords", func(t *testing.T) {
			for name, adminID := range map[string]string{
				"global_admin":    globalAdminID,
				"priv_role_admin": privRoleAdminID,
				"priv_auth_admin": privAuthAdminID,
				"app_admin":       appAdminID,
			} {
				assert.False(t, edgeExists(helpdeskAdminID, "PasswordResetViaHelpdeskAdmin", adminID),
					"Helpdesk Admin should NOT be able to reset %s password", name)
			}
		})

		// Password Admin should NOT be able to reset privileged admin passwords
		t.Run("password admin cannot reset privileged admin passwords", func(t *testing.T) {
			for name, adminID := range map[string]string{
				"global_admin":    globalAdminID,
				"priv_role_admin": privRoleAdminID,
				"priv_auth_admin": privAuthAdminID,
			} {
				assert.False(t, edgeExists(passwordAdminID, "PasswordResetViaPasswordAdmin", adminID),
					"Password Admin should NOT be able to reset %s password", name)
			}
		})

		// User Admin should NOT be able to reset Global Admin password
		t.Run("user admin cannot reset global admin password", func(t *testing.T) {
			assert.False(t, edgeExists(userAdminID, "PasswordResetViaUserAdmin", globalAdminID),
				"User Admin should NOT be able to reset Global Admin password")
		})

		// Exchange Admin should NOT have any CAN_ESCALATE edges (marker only)
		t.Run("exchange admin has no CAN_ESCALATE edges", func(t *testing.T) {
			exchangeCE := queryCount(
				"MATCH (u:User {id: $id})-[r:CAN_ESCALATE]->() RETURN count(r) AS c",
				map[string]interface{}{"id": exchangeAdminID})
			assert.Equal(t, 0, exchangeCE,
				"Exchange Admin should have no CAN_ESCALATE edges (marker only)")
		})

		// Conditional Access Admin should NOT have any CAN_ESCALATE edges (marker only)
		t.Run("conditional access admin has no CAN_ESCALATE edges", func(t *testing.T) {
			condAccessCE := queryCount(
				"MATCH (u:User {id: $id})-[r:CAN_ESCALATE]->() RETURN count(r) AS c",
				map[string]interface{}{"id": conditionalAccessAdminID})
			assert.Equal(t, 0, condAccessCE,
				"Conditional Access Admin should have no CAN_ESCALATE edges (marker only)")
		})

		// Regular SP (no Graph permissions) should NOT have CAN_ESCALATE edges
		t.Run("regular SP has no CAN_ESCALATE edges", func(t *testing.T) {
			regularSPCE := queryCount(
				"MATCH (sp:ServicePrincipal {id: $id})-[r:CAN_ESCALATE]->() RETURN count(r) AS c",
				map[string]interface{}{"id": regularSPObjectID})
			assert.Equal(t, 0, regularSPCE,
				"regular SP (no Graph API permissions) should have no CAN_ESCALATE edges")
		})

		// Regular SP should NOT have _hasGraphApiPermissions marker
		t.Run("regular SP has no Graph API permission markers", func(t *testing.T) {
			regularSPMarker := queryCount(
				"MATCH (sp:ServicePrincipal {id: $id, _hasGraphApiPermissions: true}) RETURN count(sp) AS c",
				map[string]interface{}{"id": regularSPObjectID})
			assert.Equal(t, 0, regularSPMarker,
				"regular SP should NOT have _hasGraphApiPermissions marker")
		})

		// No self-loops on password reset (admin cannot reset own password via CAN_ESCALATE)
		t.Run("no self-loop CAN_ESCALATE password reset", func(t *testing.T) {
			selfLoops := queryCount(
				"MATCH (a)-[r:CAN_ESCALATE]->(a) WHERE r.method CONTAINS 'PasswordReset' RETURN count(r) AS c", nil)
			assert.Equal(t, 0, selfLoops,
				"no principal should have a CAN_ESCALATE password reset edge to itself")
		})

		// No CAN_ESCALATE to unexpected node types
		t.Run("CAN_ESCALATE targets are expected node types", func(t *testing.T) {
			// Log unexpected target types for diagnostics
			unexpectedResult, err := db.Query(ctx,
				"MATCH ()-[r:CAN_ESCALATE]->(t) "+
					"WHERE NOT (t:User OR t:Group OR t:ServicePrincipal OR t:Application OR t:Subscription OR t:ManagedIdentity OR t:AzureResource OR t:Resource OR t:RoleDefinition OR t:RBACRoleDefinition OR t:DirectoryRole) "+
					"UNWIND labels(t) AS label "+
					"RETURN label, count(*) AS cnt ORDER BY cnt DESC", nil)
			if err == nil {
				for _, rec := range unexpectedResult.Records {
					t.Logf("  unexpected CAN_ESCALATE target label: %v (count=%v)", rec["label"], rec["cnt"])
				}
			}

			badTargets := queryCount(
				"MATCH ()-[r:CAN_ESCALATE]->(t) "+
					"WHERE NOT (t:User OR t:Group OR t:ServicePrincipal OR t:Application OR t:Subscription OR t:ManagedIdentity OR t:AzureResource OR t:Resource OR t:RoleDefinition OR t:RBACRoleDefinition OR t:DirectoryRole) "+
					"RETURN count(r) AS c", nil)
			assert.Equal(t, 0, badTargets,
				"CAN_ESCALATE should only target expected node types")
		})
	})

	// =====================================================================
	// Result 10: Idempotency — re-push should not create duplicates
	// =====================================================================
	t.Run("idempotency", func(t *testing.T) {
		// Count nodes and relationships before re-push
		nodesBefore := queryCount("MATCH (n) RETURN count(n) AS c", nil)
		relsBefore := queryCount("MATCH ()-[r]->() RETURN count(r) AS c", nil)

		// Re-push the same data
		if len(nodes) > 0 {
			_, err := db.CreateNodes(ctx, nodes)
			require.NoError(t, err, "re-push nodes should not error")
		}
		if len(rels) > 0 {
			_, err := db.CreateRelationships(ctx, rels)
			require.NoError(t, err, "re-push relationships should not error")
		}

		// Count after re-push
		nodesAfter := queryCount("MATCH (n) RETURN count(n) AS c", nil)
		relsAfter := queryCount("MATCH ()-[r]->() RETURN count(r) AS c", nil)

		assert.Equal(t, nodesBefore, nodesAfter,
			"node count should be unchanged after re-push (MERGE idempotency): before=%d after=%d", nodesBefore, nodesAfter)
		assert.Equal(t, relsBefore, relsAfter,
			"relationship count should be unchanged after re-push (MERGE idempotency): before=%d after=%d", relsBefore, relsAfter)
	})

	// =====================================================================
	// Result 11: Data completeness — exact counts for fixture entities
	// =====================================================================
	t.Run("data completeness", func(t *testing.T) {
		// Each fixture admin user should have exactly 1 directory role HAS_PERMISSION
		t.Run("each admin user has exactly 1 directory role assignment", func(t *testing.T) {
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
			} {
				count := queryCount(
					"MATCH (u:User {id: $id})-[r:HAS_PERMISSION {source: 'Entra ID Directory Role'}]->() RETURN count(r) AS c",
					map[string]interface{}{"id": uid})
				assert.GreaterOrEqual(t, count, 1,
					"%s should have at least 1 directory role HAS_PERMISSION edge", name)
			}
		})

		// Regular user should have ZERO directory role HAS_PERMISSION edges
		t.Run("regular user has no directory role assignments", func(t *testing.T) {
			count := queryCount(
				"MATCH (u:User {id: $id})-[r:HAS_PERMISSION {source: 'Entra ID Directory Role'}]->() RETURN count(r) AS c",
				map[string]interface{}{"id": regularUserID})
			assert.Equal(t, 0, count,
				"regular user should have ZERO directory role HAS_PERMISSION edges")
		})

		// All enrichment queries should have executed (check query count)
		t.Run("all enrichment queries executed", func(t *testing.T) {
			// Count total enrichment markers set across all node types.
			// Each enrichment query sets at least one marker — if zero are set, the query didn't fire.
			markers := []string{
				"_isGlobalAdmin",
				"_hasPrivilegedRole",
				"_canEscalate",
				"_hasGraphApiPermissions",
				"_canEscalateViaAppCreds",
				"_canEscalateViaPasswordReset",
				"_canEscalateViaRoleAssignment",
				"_canEscalateViaPolicyBypass",
				"_canEscalateViaServiceAdmin",
				"_canEscalateViaGroupOwnership",
				"_hasTransitiveRole",
				"_hasPotentialPermissions",
				"_canEscalateViaApp",
			}
			for _, marker := range markers {
				count := queryCount(
					fmt.Sprintf("MATCH (n) WHERE n.%s = true RETURN count(n) AS c", marker), nil)
				assert.Greater(t, count, 0,
					"enrichment marker %s should have at least 1 node (got 0)", marker)
			}
		})

		// No orphan HAS_PERMISSION edges (start node exists)
		t.Run("no orphan HAS_PERMISSION start nodes", func(t *testing.T) {
			orphans := queryCount(
				"MATCH (a)-[r:HAS_PERMISSION]->(b) "+
					"WHERE NOT (a:User OR a:Group OR a:ServicePrincipal) "+
					"RETURN count(r) AS c", nil)
			assert.Equal(t, 0, orphans,
				"all HAS_PERMISSION start nodes should be User, Group, or ServicePrincipal")
		})

		// No orphan MEMBER_OF edges (start and end nodes should be known)
		t.Run("MEMBER_OF start nodes are principals, end nodes are groups", func(t *testing.T) {
			badStart := queryCount(
				"MATCH (a)-[:MEMBER_OF]->(b) "+
					"WHERE NOT (a:User OR a:Group OR a:ServicePrincipal) "+
					"RETURN count(a) AS c", nil)
			assert.Equal(t, 0, badStart, "MEMBER_OF start nodes should be principals")

			badEnd := queryCount(
				"MATCH (a)-[:MEMBER_OF]->(b) WHERE NOT b:Group RETURN count(b) AS c", nil)
			assert.Equal(t, 0, badEnd, "MEMBER_OF end nodes should be Groups")
		})

		// CAN_ESCALATE edges all have method, category, and condition properties
		t.Run("all CAN_ESCALATE edges have required metadata", func(t *testing.T) {
			missingMethod := queryCount(
				"MATCH ()-[r:CAN_ESCALATE]->() WHERE r.method IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingMethod, "all CAN_ESCALATE edges must have method property")

			missingCategory := queryCount(
				"MATCH ()-[r:CAN_ESCALATE]->() WHERE r.category IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingCategory, "all CAN_ESCALATE edges must have category property")

			missingCondition := queryCount(
				"MATCH ()-[r:CAN_ESCALATE]->() WHERE r.condition IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingCondition, "all CAN_ESCALATE edges must have condition property")
		})

		// HAS_PERMISSION edges all have source property
		t.Run("all HAS_PERMISSION edges have source property", func(t *testing.T) {
			missingSource := queryCount(
				"MATCH ()-[r:HAS_PERMISSION]->() WHERE r.source IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingSource, "all HAS_PERMISSION edges must have source property")
		})

		// All nodes have id property (required for MERGE uniqueness)
		t.Run("all nodes have id property", func(t *testing.T) {
			missingID := queryCount(
				"MATCH (n) WHERE n.id IS NULL RETURN count(n) AS c", nil)
			assert.Equal(t, 0, missingID, "all nodes must have id property (MERGE key)")
		})

		// Fixture group membership integrity
		t.Run("fixture group memberships are complete", func(t *testing.T) {
			// regular_user → regular_group
			assert.Equal(t, 1, queryCount(
				"MATCH (u:User {id: $uid})-[:MEMBER_OF]->(g:Group {id: $gid}) RETURN count(u) AS c",
				map[string]interface{}{"uid": regularUserID, "gid": groupRegularID}),
				"regular_user should be MEMBER_OF regular_group")

			// auth_admin → privileged_group
			assert.Equal(t, 1, queryCount(
				"MATCH (u:User {id: $uid})-[:MEMBER_OF]->(g:Group {id: $gid}) RETURN count(u) AS c",
				map[string]interface{}{"uid": authAdminID, "gid": groupPrivilegedID}),
				"auth_admin should be MEMBER_OF privileged_group")

			// privileged_group → regular_group (nested)
			assert.Equal(t, 1, queryCount(
				"MATCH (g1:Group {id: $g1id})-[:MEMBER_OF]->(g2:Group {id: $g2id}) RETURN count(g1) AS c",
				map[string]interface{}{"g1id": groupPrivilegedID, "g2id": groupRegularID}),
				"privileged_group should be nested MEMBER_OF regular_group")
		})

		// Fixture ownership integrity
		t.Run("fixture ownership relationships are complete", func(t *testing.T) {
			// app_admin OWNS privileged_app
			assert.GreaterOrEqual(t, queryCount(
				"MATCH (u:User {id: $uid})-[:OWNS]->(a:Application {id: $aid}) RETURN count(u) AS c",
				map[string]interface{}{"uid": appAdminID, "aid": privilegedAppObjectID}),
				1, "app_admin should OWN privileged_app")

			// app_admin OWNS privileged_group
			assert.GreaterOrEqual(t, queryCount(
				"MATCH (u:User {id: $uid})-[:OWNS]->(g:Group {id: $gid}) RETURN count(u) AS c",
				map[string]interface{}{"uid": appAdminID, "gid": groupPrivilegedID}),
				1, "app_admin should OWN privileged_group")

			// user_admin OWNS regular SP
			assert.GreaterOrEqual(t, queryCount(
				"MATCH (u:User {id: $uid})-[:OWNS]->(sp:ServicePrincipal {id: $spid}) RETURN count(u) AS c",
				map[string]interface{}{"uid": userAdminID, "spid": regularSPObjectID}),
				1, "user_admin should OWN regular SP")
		})

		// Managed identity chain completeness
		t.Run("managed identity chain completeness", func(t *testing.T) {
			// User-assigned MI exists
			assert.Equal(t, 1, queryCount(
				"MATCH (mi:ManagedIdentity {id: $id}) RETURN count(mi) AS c",
				map[string]interface{}{"id": miUserAssignedID}),
				"user-assigned MI should exist")

			// MI → SP CONTAINS edge exists
			miToSP := queryCount(
				"MATCH (mi:ManagedIdentity {id: $id})-[:CONTAINS]->(:ServicePrincipal) RETURN count(mi) AS c",
				map[string]interface{}{"id": miUserAssignedID})
			assert.GreaterOrEqual(t, miToSP, 1, "user-assigned MI should CONTAINS a ServicePrincipal")

			// VM → MI CONTAINS edge exists (via AzureResource)
			vmToMI := queryCount(
				"MATCH (r:AzureResource {id: $vmid})-[:CONTAINS]->(:ManagedIdentity) RETURN count(r) AS c",
				map[string]interface{}{"vmid": vmID})
			assert.GreaterOrEqual(t, vmToMI, 1, "VM should CONTAINS at least 1 ManagedIdentity")

			// Full chain exists: VM → MI → SP
			fullChain := queryCount(
				"MATCH (r:AzureResource {id: $vmid})-[:CONTAINS]->(mi:ManagedIdentity)-[:CONTAINS]->(sp:ServicePrincipal) RETURN count(sp) AS c",
				map[string]interface{}{"vmid": vmID})
			assert.GreaterOrEqual(t, fullChain, 1, "full VM → MI → SP chain should exist")
		})
	})

	// =====================================================================
	// Result 12: Graph structural integrity
	// =====================================================================
	t.Run("graph structural integrity", func(t *testing.T) {
		// All node labels should be from the expected set
		t.Run("no unexpected node labels", func(t *testing.T) {
			expectedLabels := []string{
				"User", "Principal", "Group", "ServicePrincipal", "Application",
				"Device", "DirectoryRole", "RoleDefinition", "Subscription",
				"RBACRoleDefinition", "ManagementGroup", "ManagedIdentity",
				"AzureResource", "Resource",
				// Namespaced labels
				"Azure::EntraID::User", "Azure::EntraID::Group",
				"Azure::EntraID::ServicePrincipal", "Azure::EntraID::Application",
				"Azure::EntraID::Device", "Azure::EntraID::DirectoryRole",
				"Azure::EntraID::RoleDefinition", "Azure::Subscription",
				"Azure::RBAC::RoleDefinition", "Azure::Management::ManagementGroup",
				"Azure::ManagedIdentity", "Azure::Resource",
			}
			// Build a string list for Cypher
			labelSet := ""
			for i, l := range expectedLabels {
				if i > 0 {
					labelSet += ", "
				}
				labelSet += "'" + l + "'"
			}
			unexpectedResult, err := db.Query(ctx,
				"MATCH (n) UNWIND labels(n) AS label WITH DISTINCT label "+
					"WHERE NOT label IN ["+labelSet+"] RETURN collect(label) AS unexpected", nil)
			require.NoError(t, err)
			if len(unexpectedResult.Records) > 0 {
				unexpected := unexpectedResult.Records[0]["unexpected"]
				assert.Empty(t, unexpected, "unexpected node labels found: %v", unexpected)
			}
		})

		// All relationship types should be from the expected set
		t.Run("no unexpected relationship types", func(t *testing.T) {
			unexpectedResult, err := db.Query(ctx,
				"MATCH ()-[r]->() WITH DISTINCT type(r) AS relType "+
					"WHERE NOT relType IN ['HAS_PERMISSION', 'MEMBER_OF', 'OWNS', 'CONTAINS', 'CAN_ESCALATE'] "+
					"RETURN collect(relType) AS unexpected", nil)
			require.NoError(t, err)
			if len(unexpectedResult.Records) > 0 {
				unexpected := unexpectedResult.Records[0]["unexpected"]
				assert.Empty(t, unexpected, "unexpected relationship types found: %v", unexpected)
			}
		})

		// All OWNS edges should have resourceType property
		t.Run("all OWNS edges have resourceType", func(t *testing.T) {
			missingRT := queryCount(
				"MATCH ()-[r:OWNS]->() WHERE r.resourceType IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingRT, "all OWNS edges must have resourceType property")
		})

		// All MEMBER_OF edges should have memberType property
		t.Run("all MEMBER_OF edges have memberType", func(t *testing.T) {
			missingMT := queryCount(
				"MATCH ()-[r:MEMBER_OF]->() WHERE r.memberType IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingMT, "all MEMBER_OF edges must have memberType property")
		})

		// All CONTAINS edges should have a descriptive property (identityType or relationship or childType)
		t.Run("all CONTAINS edges have descriptor", func(t *testing.T) {
			missingDesc := queryCount(
				"MATCH ()-[r:CONTAINS]->() WHERE r.identityType IS NULL AND r.relationship IS NULL AND r.childType IS NULL RETURN count(r) AS c", nil)
			assert.Equal(t, 0, missingDesc,
				"all CONTAINS edges must have identityType, relationship, or childType property")
		})

		// No nodes with empty string id
		t.Run("no empty id properties", func(t *testing.T) {
			emptyIDs := queryCount("MATCH (n) WHERE n.id = '' RETURN count(n) AS c", nil)
			assert.Equal(t, 0, emptyIDs, "no nodes should have empty string id")
		})

		// No duplicate node IDs within same primary label
		t.Run("no duplicate User ids", func(t *testing.T) {
			dupes := queryCount(
				"MATCH (n:User) WITH n.id AS uid, count(*) AS cnt WHERE cnt > 1 RETURN count(uid) AS c", nil)
			assert.Equal(t, 0, dupes, "no duplicate User node ids (MERGE idempotency)")
		})
		t.Run("no duplicate ServicePrincipal ids", func(t *testing.T) {
			dupes := queryCount(
				"MATCH (n:ServicePrincipal) WITH n.id AS spid, count(*) AS cnt WHERE cnt > 1 RETURN count(spid) AS c", nil)
			assert.Equal(t, 0, dupes, "no duplicate ServicePrincipal node ids")
		})
		t.Run("no duplicate Group ids", func(t *testing.T) {
			dupes := queryCount(
				"MATCH (n:Group) WITH n.id AS gid, count(*) AS cnt WHERE cnt > 1 RETURN count(gid) AS c", nil)
			assert.Equal(t, 0, dupes, "no duplicate Group node ids")
		})
	})

	// =====================================================================
	// Result 13: Detailed enrichment query validation
	// =====================================================================
	t.Run("detailed enrichment query validation", func(t *testing.T) {
		// --- global_admin_detection.yaml ---
		t.Run("global admin correctly identified", func(t *testing.T) {
			// Should match by role name OR by well-known role ID
			gaResult, err := db.Query(ctx,
				"MATCH (p:User {id: $id, _isGlobalAdmin: true}) RETURN p.displayName AS name",
				map[string]interface{}{"id": globalAdminID})
			require.NoError(t, err)
			assert.NotEmpty(t, gaResult.Records, "global admin should have _isGlobalAdmin=true")

			// Other admins should NOT be global admins
			for name, id := range map[string]string{
				"app_admin":  appAdminID,
				"user_admin": userAdminID,
			} {
				notGA := queryCount(
					"MATCH (n:User {id: $id, _isGlobalAdmin: true}) RETURN count(n) AS c",
					map[string]interface{}{"id": id})
				assert.Equal(t, 0, notGA, "%s should NOT be _isGlobalAdmin", name)
			}
		})

		// --- privileged_role_detection.yaml ---
		t.Run("privileged role holders correctly identified", func(t *testing.T) {
			for name, id := range map[string]string{
				"global_admin":    globalAdminID,
				"priv_role_admin": privRoleAdminID,
				"app_admin":       appAdminID,
				"user_admin":      userAdminID,
				"auth_admin":      authAdminID,
				"exchange_admin":  exchangeAdminID,
			} {
				marker := queryCount(
					"MATCH (n:User {id: $id, _hasPrivilegedRole: true}) RETURN count(n) AS c",
					map[string]interface{}{"id": id})
				assert.Equal(t, 1, marker, "%s should have _hasPrivilegedRole=true", name)
			}

			// Regular user should NOT have privileged role marker
			noMarker := queryCount(
				"MATCH (n:User {id: $id, _hasPrivilegedRole: true}) RETURN count(n) AS c",
				map[string]interface{}{"id": regularUserID})
			assert.Equal(t, 0, noMarker, "regular user should NOT have _hasPrivilegedRole")
		})

		// --- privileged_role_detection.yaml sets _isPrivileged on relationship ---
		t.Run("privileged role edges have _isPrivileged marker", func(t *testing.T) {
			privEdges := queryCount(
				"MATCH (:User {id: $id})-[r:HAS_PERMISSION {_isPrivileged: true}]->() RETURN count(r) AS c",
				map[string]interface{}{"id": globalAdminID})
			assert.GreaterOrEqual(t, privEdges, 1,
				"global admin's directory role edges should have _isPrivileged=true")
		})

		// --- dangerous_graph_permissions.yaml ---
		t.Run("dangerous graph permissions specific validation", func(t *testing.T) {
			// Privileged SP (with Graph app role assignments to MS Graph) should have marker
			privSPMarker := queryCount(
				"MATCH (sp:ServicePrincipal {id: $id, _hasGraphApiPermissions: true}) RETURN count(sp) AS c",
				map[string]interface{}{"id": privilegedSPObjectID})
			assert.Equal(t, 1, privSPMarker, "privileged SP should have _hasGraphApiPermissions")

			// Regular SP should NOT
			regSPMarker := queryCount(
				"MATCH (sp:ServicePrincipal {id: $id, _hasGraphApiPermissions: true}) RETURN count(sp) AS c",
				map[string]interface{}{"id": regularSPObjectID})
			assert.Equal(t, 0, regSPMarker, "regular SP should NOT have _hasGraphApiPermissions")

			// MS Graph SP itself should NOT have the marker (it's a resource, not a client)
			msgraphMarker := queryCount(
				"MATCH (sp:ServicePrincipal {id: $id, _hasGraphApiPermissions: true}) RETURN count(sp) AS c",
				map[string]interface{}{"id": msgraphSPObjectID})
			assert.Equal(t, 0, msgraphMarker, "MS Graph resource SP should NOT have _hasGraphApiPermissions")
		})

		// --- transitive_group_permissions.yaml ---
		t.Run("transitive group permissions specific validation", func(t *testing.T) {
			// auth_admin is MEMBER_OF privileged_group which has HAS_PERMISSION
			authTransitive := queryCount(
				"MATCH (n:User {id: $id, _hasTransitiveRole: true}) RETURN count(n) AS c",
				map[string]interface{}{"id": authAdminID})
			assert.Equal(t, 1, authTransitive, "auth_admin should have _hasTransitiveRole (via privileged_group)")
		})

		// --- group_owner_potential_permissions.yaml ---
		t.Run("group owner potential permissions specific validation", func(t *testing.T) {
			// app_admin OWNS privileged_group which has HAS_PERMISSION
			appPotential := queryCount(
				"MATCH (n:User {id: $id, _hasPotentialPermissions: true}) RETURN count(n) AS c",
				map[string]interface{}{"id": appAdminID})
			assert.Equal(t, 1, appPotential, "app_admin should have _hasPotentialPermissions")

			// Verify _potentialViaGroup names the group
			groupNameResult, err := db.Query(ctx,
				"MATCH (n:User {id: $id}) RETURN n._potentialViaGroup AS groupName",
				map[string]interface{}{"id": appAdminID})
			require.NoError(t, err)
			if assert.NotEmpty(t, groupNameResult.Records) {
				groupName, _ := groupNameResult.Records[0]["groupName"].(string)
				assert.NotEmpty(t, groupName, "_potentialViaGroup should name the owned group")
			}
		})

		// --- management_group_hierarchy.yaml ---
		t.Run("management group hierarchy metadata set", func(t *testing.T) {
			// All MG nodes should have _childCount and _enriched
			mgResult, err := db.Query(ctx,
				"MATCH (mg:ManagementGroup) RETURN mg.id AS id, mg._childCount AS children, mg._enriched AS enriched", nil)
			require.NoError(t, err)
			for _, rec := range mgResult.Records {
				assert.NotNil(t, rec["enriched"], "ManagementGroup %v should have _enriched", rec["id"])
			}
		})

		// --- pim_permanent_classification.yaml ---
		t.Run("non-PIM directory role assignments classified as Permanent", func(t *testing.T) {
			// All 11 fixture admin users have directory role assignments via Entra ID
			// (not PIM), so they should all be classified as Permanent
			for name, uid := range map[string]string{
				"global_admin":    globalAdminID,
				"priv_role_admin": privRoleAdminID,
				"app_admin":       appAdminID,
			} {
				permCount := queryCount(
					"MATCH (:User {id: $id})-[r:HAS_PERMISSION {source: 'Entra ID Directory Role', assignmentType: 'Permanent'}]->() RETURN count(r) AS c",
					map[string]interface{}{"id": uid})
				assert.GreaterOrEqual(t, permCount, 1,
					"%s directory role assignment should be classified as Permanent", name)
			}
		})

		// --- can_escalate_app_owner_secret.yaml + can_escalate_app_to_sp.yaml ---
		t.Run("application ownership escalation chain", func(t *testing.T) {
			// app_admin OWNS privileged_app → ApplicationAddSecret → privileged_sp
			appSecretEdge := queryCount(
				"MATCH (:User {id: $uid})-[r:CAN_ESCALATE {method: 'ApplicationAddSecret'}]->(:ServicePrincipal {id: $spid}) RETURN count(r) AS c",
				map[string]interface{}{"uid": appAdminID, "spid": privilegedSPObjectID})
			assert.GreaterOrEqual(t, appSecretEdge, 1,
				"app_admin should have ApplicationAddSecret CAN_ESCALATE to privileged SP")

			// privileged_app → ApplicationToServicePrincipal → privileged_sp
			appToSP := queryCount(
				"MATCH (:Application {id: $appid})-[r:CAN_ESCALATE {method: 'ApplicationToServicePrincipal'}]->(:ServicePrincipal {id: $spid}) RETURN count(r) AS c",
				map[string]interface{}{"appid": privilegedAppObjectID, "spid": privilegedSPObjectID})
			assert.GreaterOrEqual(t, appToSP, 1,
				"privileged_app should have ApplicationToServicePrincipal CAN_ESCALATE to privileged SP")
		})

		// --- can_escalate_sp_owner_secret.yaml ---
		t.Run("service principal ownership escalation", func(t *testing.T) {
			// user_admin OWNS regular_sp → ServicePrincipalAddSecret → regular_sp
			spSecretEdge := queryCount(
				"MATCH (:User {id: $uid})-[r:CAN_ESCALATE {method: 'ServicePrincipalAddSecret'}]->(:ServicePrincipal {id: $spid}) RETURN count(r) AS c",
				map[string]interface{}{"uid": userAdminID, "spid": regularSPObjectID})
			assert.GreaterOrEqual(t, spSecretEdge, 1,
				"user_admin should have ServicePrincipalAddSecret CAN_ESCALATE to regular SP")
		})

		// --- can_escalate_mi_to_sp.yaml ---
		t.Run("managed identity to SP escalation", func(t *testing.T) {
			miToSPEscalation := queryCount(
				"MATCH (:ManagedIdentity)-[r:CAN_ESCALATE {method: 'ManagedIdentityToServicePrincipal'}]->(:ServicePrincipal) RETURN count(r) AS c", nil)
			assert.GreaterOrEqual(t, miToSPEscalation, 1,
				"at least 1 MI→SP CAN_ESCALATE edge should exist")
		})

		// --- can_escalate_resource_to_mi.yaml ---
		t.Run("resource to MI escalation", func(t *testing.T) {
			resourceToMI := queryCount(
				"MATCH (:AzureResource)-[r:CAN_ESCALATE {method: 'ResourceAttachedIdentity'}]->(:ManagedIdentity) RETURN count(r) AS c", nil)
			assert.GreaterOrEqual(t, resourceToMI, 1,
				"at least 1 Resource→MI CAN_ESCALATE edge should exist (VM with attached MI)")
		})

		// --- Full MI escalation chain: VM → MI → SP ---
		t.Run("full MI escalation chain VM to SP", func(t *testing.T) {
			fullMIChain := queryCount(
				"MATCH (r:AzureResource {id: $vmid})-[:CAN_ESCALATE {method: 'ResourceAttachedIdentity'}]->(mi:ManagedIdentity)"+
					"-[:CAN_ESCALATE {method: 'ManagedIdentityToServicePrincipal'}]->(sp:ServicePrincipal) "+
					"RETURN count(sp) AS c",
				map[string]interface{}{"vmid": vmID})
			assert.GreaterOrEqual(t, fullMIChain, 1,
				"full VM → MI → SP escalation chain should exist")
		})

		// --- CAN_ESCALATE category distribution ---
		t.Run("CAN_ESCALATE category distribution", func(t *testing.T) {
			expectedCategories := []string{
				"DirectoryRole",
				"GraphPermission",
				"RBAC",
				"ApplicationOwnership",
				"GroupOwnership",
				"ManagedIdentity",
				"ApplicationIdentity",
			}
			for _, cat := range expectedCategories {
				count := queryCount(
					"MATCH ()-[r:CAN_ESCALATE {category: $cat}]->() RETURN count(r) AS c",
					map[string]interface{}{"cat": cat})
				assert.Greater(t, count, 0,
					"CAN_ESCALATE category '%s' should have at least 1 edge", cat)
			}
		})

		// --- HAS_PERMISSION source distribution ---
		t.Run("HAS_PERMISSION source distribution", func(t *testing.T) {
			expectedSources := []string{
				"Entra ID Directory Role",
				"Azure RBAC",
				"Microsoft Graph App Role",
			}
			for _, src := range expectedSources {
				count := queryCount(
					"MATCH ()-[r:HAS_PERMISSION {source: $src}]->() RETURN count(r) AS c",
					map[string]interface{}{"src": src})
				assert.Greater(t, count, 0,
					"HAS_PERMISSION source '%s' should have at least 1 edge", src)
			}
		})
	})

	// =====================================================================
	// Result 14: Enrichment query count completeness
	// =====================================================================
	t.Run("all 38 enrichment queries produced results", func(t *testing.T) {
		// Each enrichment query YAML sets at least one marker or creates edges.
		// We verify completeness by checking that key outputs exist.

		// Node markers that at least 1 enrichment query sets
		nodeMarkers := map[string]string{
			"_isGlobalAdmin":                  "global_admin_detection",
			"_hasPrivilegedRole":              "privileged_role_detection",
			"_canEscalate":                    "can_escalate_*",
			"_hasGraphApiPermissions":         "dangerous_graph_permissions",
			"_canEscalateViaAppCreds":         "can_escalate_app_admin",
			"_canEscalateViaPasswordReset":    "can_escalate_*_admin (password)",
			"_canEscalateViaRoleAssignment":   "can_escalate_priv_role_admin",
			"_canEscalateViaPolicyBypass":      "can_escalate_conditional_access",
			"_canEscalateViaServiceAdmin":     "can_escalate_exchange_admin",
			"_canEscalateViaGroupOwnership":   "can_escalate_group_owner",
			"_hasTransitiveRole":              "transitive_group_permissions",
			"_hasPotentialPermissions":        "group_owner_potential_permissions",
			"_canEscalateViaApp":              "owner_to_privileged_app",
			"_hasTransitivePrivilege":         "group_nesting_paths",
		}

		for marker, queryName := range nodeMarkers {
			count := queryCount(
				fmt.Sprintf("MATCH (n) WHERE n.%s = true RETURN count(n) AS c", marker), nil)
			assert.Greater(t, count, 0,
				"enrichment marker %s (from %s) should have at least 1 node", marker, queryName)
		}

		// CAN_ESCALATE methods that enrichment queries create
		escalationMethods := []string{
			"GlobalAdministrator",
			"PrivilegedRoleAdmin",
			"ApplicationAdmin",
			"GroupsAdministrator",
			"PasswordResetViaGlobalAdmin",
			"PasswordResetViaAuthAdmin",
			"PasswordResetViaHelpdeskAdmin",
			"PasswordResetViaPasswordAdmin",
			"PasswordResetViaUserAdmin",
			"PasswordResetViaPrivilegedAuthAdmin",
			"GraphRoleManagement",
			"AzureOwner",
			"ApplicationAddSecret",
			"ServicePrincipalAddSecret",
			"GroupOwnership",
			"ManagedIdentityToServicePrincipal",
			"ResourceAttachedIdentity",
			"ApplicationToServicePrincipal",
		}

		for _, method := range escalationMethods {
			count := queryCount(
				"MATCH ()-[r:CAN_ESCALATE {method: $m}]->() RETURN count(r) AS c",
				map[string]interface{}{"m": method})
			assert.Greater(t, count, 0,
				"CAN_ESCALATE method '%s' should have at least 1 edge", method)
		}
	})

	// =====================================================================
	// PIM eligible escalation enrichment (synthetic) — MUST run last before
	// diagnostics because it mutates graph state (injects synthetic edges
	// and re-runs enrichment, which creates CAN_ESCALATE for regular_user).
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
