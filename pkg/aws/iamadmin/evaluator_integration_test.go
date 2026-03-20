//go:build integration

package iamadmin

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluatorIntegration(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list-administrators")
	fixture.Setup()

	adminUser := fixture.Output("admin_user_name")
	nonAdminUser := fixture.Output("non_admin_user_name")
	adminRole := fixture.Output("admin_role_name")
	nonAdminRole := fixture.Output("non_admin_role_name")
	adminGroup := fixture.Output("admin_group_name")
	nonAdminGroup := fixture.Output("non_admin_group_name")
	adminGroupMember := fixture.Output("admin_group_member_user_name")

	evaluator := New(plugin.AWSCommonRecon{})

	in := pipeline.From(
		output.AWSResource{ResourceType: "AWS::IAM::User", ResourceID: adminUser, Region: "global", AccountRef: "test"},
		output.AWSResource{ResourceType: "AWS::IAM::User", ResourceID: nonAdminUser, Region: "global", AccountRef: "test"},
		output.AWSResource{ResourceType: "AWS::IAM::Role", ResourceID: adminRole, Region: "global", AccountRef: "test"},
		output.AWSResource{ResourceType: "AWS::IAM::Role", ResourceID: nonAdminRole, Region: "global", AccountRef: "test"},
		output.AWSResource{ResourceType: "AWS::IAM::Group", ResourceID: adminGroup, Region: "global", AccountRef: "test"},
		output.AWSResource{ResourceType: "AWS::IAM::Group", ResourceID: nonAdminGroup, Region: "global", AccountRef: "test"},
	)
	out := pipeline.New[output.AWSResource]()
	pipeline.Pipe(in, evaluator.EvaluatePrincipal, out)

	results, err := out.Collect()
	require.NoError(t, err)
	require.NotEmpty(t, results)

	t.Run("emits admin user", func(t *testing.T) {
		assertContainsAdminFinding(t, results, "AWS::IAM::User", adminUser)
	})

	t.Run("emits admin role", func(t *testing.T) {
		assertContainsAdminFinding(t, results, "AWS::IAM::Role", adminRole)
	})

	t.Run("emits admin group", func(t *testing.T) {
		assertContainsAdminFinding(t, results, "AWS::IAM::Group", adminGroup)
	})

	t.Run("emits admin group member user", func(t *testing.T) {
		assertContainsAdminFinding(t, results, "AWS::IAM::User", adminGroupMember)
	})

	t.Run("filters non-admin user", func(t *testing.T) {
		assertNotPresent(t, results, nonAdminUser)
	})

	t.Run("filters non-admin role", func(t *testing.T) {
		assertNotPresent(t, results, nonAdminRole)
	})

	t.Run("filters non-admin group", func(t *testing.T) {
		assertNotPresent(t, results, nonAdminGroup)
	})

	t.Run("all emitted results have IsAdmin set", func(t *testing.T) {
		for _, r := range results {
			assert.True(t, r.IsAdmin, "expected IsAdmin=true for %s %s", r.ResourceType, r.ResourceID)
		}
	})
}

func assertContainsAdminFinding(t *testing.T, results []output.AWSResource, resourceType, resourceID string) {
	t.Helper()

	for _, result := range results {
		if result.ResourceType == resourceType && result.ResourceID == resourceID {
			assert.True(t, result.IsAdmin)
			return
		}
	}

	t.Fatalf("expected admin finding for %s %s", resourceType, resourceID)
}

func assertNotPresent(t *testing.T, results []output.AWSResource, unexpectedResourceID string) {
	t.Helper()

	for _, result := range results {
		if result.ResourceID == unexpectedResourceID {
			t.Fatalf("did not expect result for %s", unexpectedResourceID)
		}
	}
}
