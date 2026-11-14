package escalation

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCollectionSnapshotAssembleUsesProductionAssembly(t *testing.T) {
	gaad := types.NewAuthorizationAccountDetails(
		"111111111111",
		[]types.UserDetail{{Arn: "arn:aws:iam::111111111111:user/developer", UserName: "developer"}},
		nil,
		[]types.RoleDetail{{Arn: "arn:aws:iam::111111111111:role/admin", RoleName: "admin"}},
		nil,
	)
	snapshot := CollectionSnapshot{
		Version: CollectionSnapshotVersion,
		GAAD:    gaad,
		Resources: []output.AWSResource{{
			ResourceType: "AWS::Lambda::Function",
			ResourceID:   "function:processor",
			ARN:          "arn:aws:lambda:us-east-1:111111111111:function:processor",
			AccountRef:   "111111111111",
			Region:       "us-east-1",
			Properties: map[string]any{
				"Role": "arn:aws:iam::111111111111:role/admin",
			},
		}},
		Attacker: "arn:aws:iam::111111111111:user/developer",
		CollectionCoverage: map[string]*CollectionCoverage{
			"111111111111": {IAMGAAD: true, LambdaExecutionRoles: true},
		},
	}

	data, err := json.Marshal(snapshot)
	require.NoError(t, err)

	loaded, err := LoadCollectionSnapshot(data)
	require.NoError(t, err)
	model, err := loaded.Assemble()
	require.NoError(t, err)

	require.Equal(t, ModelVersion, model.Version)
	require.Equal(t, snapshot.Attacker, model.Goal.Attacker)
	require.Len(t, model.Principals, 2)
	require.NotEmpty(t, model.StructuralFacts, "the snapshot must cross the production structural-fact collector")
	require.Equal(t, snapshot.CollectionCoverage, model.CollectionCoverage)
}

func TestCollectionSnapshotRejectsEverySecurityCriticalUnknown(t *testing.T) {
	fields := []string{"arn", "principal", "policy", "trust", "role_association", "account", "region"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			snapshot := CollectionSnapshot{
				Version: CollectionSnapshotVersion,
				GAAD: types.NewAuthorizationAccountDetails(
					"111111111111",
					[]types.UserDetail{{Arn: "arn:aws:iam::111111111111:user/developer", UserName: "developer"}},
					nil, nil, nil,
				),
				Unknowns: []CollectionUnknown{{
					Address:          "aws_lambda_function.processor",
					Field:            field,
					Reason:           "value is unknown after plan",
					SecurityCritical: true,
				}},
			}

			_, err := snapshot.Assemble()
			require.ErrorContains(t, err, field)
		})
	}
}

func TestCollectionSnapshotRejectsDuplicateResourceIdentity(t *testing.T) {
	snapshot := CollectionSnapshot{
		Version: CollectionSnapshotVersion,
		GAAD: types.NewAuthorizationAccountDetails(
			"111111111111",
			[]types.UserDetail{{Arn: "arn:aws:iam::111111111111:user/developer", UserName: "developer"}},
			nil, nil, nil,
		),
		Resources: []output.AWSResource{
			{ResourceType: "AWS::Lambda::Function", ResourceID: "first", ARN: "arn:aws:lambda:us-east-1:111111111111:function:duplicate", AccountRef: "111111111111"},
			{ResourceType: "AWS::Lambda::Function", ResourceID: "second", ARN: "arn:aws:lambda:us-east-1:111111111111:function:duplicate", AccountRef: "111111111111"},
		},
	}

	_, err := snapshot.Assemble()
	require.ErrorContains(t, err, "duplicate resource identity")
}

func TestCollectionSnapshotRejectsUnsupportedVersion(t *testing.T) {
	snapshot := CollectionSnapshot{Version: "collection-snapshot-v2"}
	_, err := snapshot.Assemble()
	require.ErrorContains(t, err, "unsupported collection snapshot version")
}
