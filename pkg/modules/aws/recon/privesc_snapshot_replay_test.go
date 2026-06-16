//go:build integration

package recon

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/praetorian-inc/aurelian/pkg/graph/adapters"
	"github.com/praetorian-inc/aurelian/pkg/graph/queries"
	awstransformers "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/aurelian/test/testutil/privescsynth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// factsFromInputs reconstructs the fixtureFacts the labCase assertions need from the snapshot's
// SyntheticInputs, so the replay reuses the SAME assertTP/assertFP/assertTargetAllowlist helpers as
// the live test.
func factsFromInputs(in privescsynth.SyntheticInputs) fixtureFacts {
	return fixtureFacts{
		attackerARNs:            in.AttackerARNs,
		serviceAdminARNs:        in.ServiceAdminARNs,
		adminTargetARN:          in.AdminTargetARN,
		computeAdminARN:         in.ComputeAdminARN,
		privUserARN:             in.PrivUserARN,
		noProfileUserARN:        in.NoProfileUserARN,
		attackerTrustedRoleARN:  in.AttackerTrustedRoleARN,
		directTrustAdminRoleARN: in.DirectTrustAdminRoleARN,
		prefix:                  in.Prefix,
		accountID:               in.AccountID,
		decoyARNs:               in.DecoyARNs,
		privUserFPTargetARNs:    in.PrivUserFPTargetARNs,
	}
}

// TestPrivescSnapshotReplay replays a captured recon snapshot (no AWS): it rebuilds the graph
// through the REAL production transformers, re-applies the kept synthetics from privescsynth, seeds
// a fresh Neo4j container, enriches, and runs the SAME labCase TP/FP assertions as the live test.
// This exercises the seeded suite against realistic captured data with no cloud access.
//
// The snapshot file is written by the live test under AURELIAN_CAPTURE_PRIVESC_SNAPSHOT=1; until a
// tester captures it this test SKIPs.
//
// Run: go test -tags integration -run TestPrivescSnapshotReplay ./pkg/modules/aws/recon/...
func TestPrivescSnapshotReplay(t *testing.T) {
	ctx := context.Background()

	if !privescsynth.SnapshotExists(privescsynth.SnapshotPath) {
		t.Skip("snapshot not captured; run live test with AURELIAN_CAPTURE_PRIVESC_SNAPSHOT=1")
	}
	snap, err := privescsynth.LoadFromFile(privescsynth.SnapshotPath)
	require.NoError(t, err, "load snapshot")

	facts := factsFromInputs(snap.SyntheticInputs)
	require.NotEmpty(t, facts.attackerARNs, "snapshot must carry attacker ARNs")
	require.NotEmpty(t, facts.prefix, "snapshot must carry the fixture prefix")

	// --- Seed a fresh Neo4j ---
	boltURL, cleanup, err := testutil.StartNeo4jContainer(ctx)
	require.NoError(t, err)
	t.Cleanup(cleanup)

	dbCfg := graph.NewConfig(boltURL, "", "")
	db, err := adapters.NewNeo4jAdapter(dbCfg)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	seen := map[string]bool{}
	var nodes []*graph.Node
	addNode := func(n *graph.Node) {
		if n == nil || len(n.UniqueKey) == 0 {
			return
		}
		key := fmt.Sprintf("%v", n.Properties[n.UniqueKey[0]])
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		nodes = append(nodes, n)
	}

	// Rebuild RICH IAM nodes through the real transformer path: wrap each typed GAAD struct back
	// into an AWSIAMResource (carrying OriginalData) and run NodeFromAWSIAMResource — identical to
	// how the live test seeds them, so trust/HAS_ROLE/admin/self-loop guards see the same inputs.
	for _, u := range snap.Users {
		addNode(awstransformers.NodeFromAWSIAMResource(gaad.FromUserDetail(u, snap.SyntheticInputs.AccountID)))
	}
	for _, r := range snap.Roles {
		addNode(awstransformers.NodeFromAWSIAMResource(gaad.FromRoleDetail(r)))
	}
	for _, g := range snap.Groups {
		addNode(awstransformers.NodeFromAWSIAMResource(gaad.FromGroupDetail(g)))
	}
	for _, p := range snap.Policies {
		addNode(awstransformers.NodeFromAWSIAMResource(gaad.FromManagedPolicyDetail(p)))
	}

	// Rebuild the REAL collected backing-resource nodes via the production transformer.
	for _, r := range snap.Resources {
		addNode(awstransformers.NodeFromAWSResource(r))
	}

	// Re-apply ONLY the kept synthetics (the same ones the live test seeds).
	syntheticResources := privescsynth.SyntheticComputeResources(
		facts.computeAdminARN,
		snap.SyntheticInputs.EC2InstanceARN,
		snap.SyntheticInputs.BedrockExecRole,
	)
	for _, sr := range syntheticResources {
		addNode(sr.Node())
	}

	// Seed the captured permission relationships (action edges).
	var rels []*graph.Relationship
	for _, r := range snap.Relationships {
		if rel := awstransformers.RelationshipFromAWSIAMRelationship(r); rel != nil {
			rels = append(rels, rel)
			addNode(rel.StartNode)
			addNode(rel.EndNode)
		}
	}
	require.NotEmpty(t, rels, "snapshot must carry IAM relationships")

	// Same-node action edges (real node wins over synthetic when both exist).
	realResourceARNs := map[string]string{}
	for _, r := range snap.Resources {
		realResourceARNs[r.ResourceType] = r.ARN
	}
	rels = append(rels, privescsynth.SyntheticActionEdges(facts.attackerARNs, syntheticResources, realResourceARNs)...)

	stub := privescsynth.SameNodeStubNode()
	addNode(stub)
	rels = append(rels, privescsynth.SameNodeStubEdges(facts.attackerARNs, stub)...)

	_, err = db.CreateNodes(ctx, nodes)
	require.NoError(t, err)
	_, err = db.CreateRelationships(ctx, rels)
	require.NoError(t, err)

	// Apply Principal label to IAM entity nodes (production schema fix-up).
	_, err = db.Query(ctx, `
		MATCH (n)
		WHERE any(lbl IN labels(n) WHERE lbl IN ['AWS::IAM::User','AWS::IAM::Role','AWS::IAM::Group'])
		  AND n.arn IS NOT NULL
		SET n:Principal, n.Arn = n.arn`, nil)
	require.NoError(t, err)

	require.NoError(t, queries.EnrichAWS(ctx, db))
	t.Logf("Replay seeded: %d nodes, %d edges", len(nodes), len(rels))

	// Run the SAME labCase TP/FP assertions as the live test. Full-tier attackers are only present
	// in a full-tier capture; skip a case whose attacker the snapshot does not carry.
	for _, tc := range labCases {
		tc := tc
		name := fmt.Sprintf("%s/%s/%s",
			map[bool]string{true: "TP", false: "FP"}[tc.want],
			tc.attackerKey, tc.methodID[strings.LastIndex(tc.methodID, "/")+1:])
		t.Run(name, func(t *testing.T) {
			attacker, ok := facts.attackerARNs[tc.attackerKey]
			if !ok || attacker == "" {
				t.Skipf("snapshot does not carry attacker %q (likely a full-tier case)", tc.attackerKey)
			}
			if tc.want {
				assertTP(t, ctx, db, facts, tc, attacker)
			} else {
				assertFP(t, ctx, db, tc, attacker)
			}
		})
	}

	t.Run("global_no_cartesian_fanout", func(t *testing.T) {
		assertTargetAllowlist(t, ctx, db, facts)
	})
}

// TestPrivescSnapshotFreshness fails loud if the labCase table grew a want=true common-tier case
// whose attacker the captured snapshot does not cover — so a table change without a regenerated
// snapshot is caught rather than silently skipped by the replay. It is a no-op when no snapshot
// exists yet (the replay's skip already covers that state).
func TestPrivescSnapshotFreshness(t *testing.T) {
	if !privescsynth.SnapshotExists(privescsynth.SnapshotPath) {
		t.Skip("snapshot not captured; run live test with AURELIAN_CAPTURE_PRIVESC_SNAPSHOT=1")
	}
	snap, err := privescsynth.LoadFromFile(privescsynth.SnapshotPath)
	require.NoError(t, err)

	covered := snap.SyntheticInputs.AttackerARNs
	require.NotEmpty(t, covered, "snapshot must carry attacker ARNs")

	var missing []string
	for _, tc := range labCases {
		if !tc.want || tc.tier != tierCommon {
			continue
		}
		if arn, ok := covered[tc.attackerKey]; !ok || arn == "" {
			missing = append(missing, tc.attackerKey)
		}
	}
	assert.Empty(t, missing,
		"captured snapshot is stale: it does not cover these want=true common-tier attacker keys %v — "+
			"re-run the live test with AURELIAN_CAPTURE_PRIVESC_SNAPSHOT=1 to regenerate it", missing)
}
