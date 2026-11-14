package escalation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTerraformPlanToCollectionSnapshotRecoversRoleReference(t *testing.T) {
	plan := []byte(`{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address":"aws_iam_role.admin","type":"aws_iam_role","values":{"name":"admin","path":"/","assume_role_policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"}}]}"}},
    {"address":"aws_lambda_function.processor","type":"aws_lambda_function","values":{"function_name":"processor","role":null}}
  ]}},
  "configuration": {"root_module": {"resources": [
    {"address":"aws_iam_role.admin","type":"aws_iam_role","expressions":{}},
    {"address":"aws_lambda_function.processor","type":"aws_lambda_function","expressions":{"role":{"references":["aws_iam_role.admin.arn"]}}}
  ]}}
}`)

	snapshot, err := CollectionSnapshotFromTerraformPlan(plan, TerraformPlanOptions{
		AccountID: "111111111111",
		Region:    "us-east-1",
	})
	require.NoError(t, err)
	require.Empty(t, snapshot.Unknowns)
	require.Len(t, snapshot.Resources, 1)
	require.Equal(t, "arn:aws:iam::111111111111:role/admin", snapshot.Resources[0].Properties["Role"])

	model, err := snapshot.Assemble()
	require.NoError(t, err)
	require.Contains(t, model.StructuralFacts, StructuralFact{
		Type:       FactLambdaExecutionRole,
		From:       "arn:aws:lambda:us-east-1:111111111111:function:processor",
		To:         "arn:aws:iam::111111111111:role/admin",
		Confidence: 1.0,
	})
}

func TestTerraformPlanToCollectionSnapshotMarksUnresolvedRoleReferenceCritical(t *testing.T) {
	plan := []byte(`{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address":"aws_lambda_function.processor","type":"aws_lambda_function","values":{"function_name":"processor","role":null}}
  ]}},
  "configuration": {"root_module": {"resources": [
    {"address":"aws_lambda_function.processor","type":"aws_lambda_function","expressions":{"role":{"references":["module.roles.aws_iam_role.admin.arn"]}}}
  ]}}
}`)

	snapshot, err := CollectionSnapshotFromTerraformPlan(plan, TerraformPlanOptions{
		AccountID: "111111111111",
		Region:    "us-east-1",
	})
	require.NoError(t, err)
	require.Len(t, snapshot.Unknowns, 1)
	require.True(t, snapshot.Unknowns[0].SecurityCritical)
	_, err = snapshot.Assemble()
	require.ErrorContains(t, err, "role")
}

func TestTerraformPlanToCollectionSnapshotResolvesReferencesInsideChildModule(t *testing.T) {
	plan := []byte(`{
  "format_version": "1.2",
  "planned_values": {"root_module": {"child_modules": [{"resources": [
    {"address":"module.workload.aws_iam_role.admin","type":"aws_iam_role","values":{"name":"admin","path":"/"}},
    {"address":"module.workload.aws_lambda_function.processor","type":"aws_lambda_function","values":{"function_name":"processor","role":null}}
  ]}]}},
  "configuration": {"root_module": {"module_calls": {"workload": {"module": {"resources": [
    {"address":"aws_lambda_function.processor","expressions":{"role":{"references":["aws_iam_role.admin.arn"]}}}
  ]}}}}}
}`)

	snapshot, err := CollectionSnapshotFromTerraformPlan(plan, TerraformPlanOptions{
		AccountID: "111111111111",
		Region:    "us-east-1",
	})
	require.NoError(t, err)
	require.Empty(t, snapshot.Unknowns)
	require.Equal(t, "arn:aws:iam::111111111111:role/admin", snapshot.Resources[0].Properties["Role"])
}

func TestTerraformPlanToCollectionSnapshotConvertsIAMInlinePolicies(t *testing.T) {
	plan := []byte(`{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address":"aws_iam_user.attacker","type":"aws_iam_user","values":{"name":"attacker","path":"/"}},
    {"address":"aws_iam_user_policy.lambda_update","type":"aws_iam_user_policy","values":{"name":"lambda-update","user":"attacker","policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"lambda:UpdateFunctionCode\",\"Resource\":\"arn:aws:lambda:us-east-1:111111111111:function:processor\"}]}"}}
  ]}},
  "configuration": {"root_module": {"resources": []}}
}`)

	snapshot, err := CollectionSnapshotFromTerraformPlan(plan, TerraformPlanOptions{
		AccountID: "111111111111",
		Region:    "us-east-1",
	})
	require.NoError(t, err)
	require.Equal(t, 1, snapshot.GAAD.Users.Len())
	user, ok := snapshot.GAAD.Users.Get("arn:aws:iam::111111111111:user/attacker")
	require.True(t, ok)
	require.Len(t, user.UserPolicyList, 1)
	require.Equal(t, "lambda-update", user.UserPolicyList[0].PolicyName)
}
