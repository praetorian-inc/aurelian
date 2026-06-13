package gaad

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithy "github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transformaws "github.com/praetorian-inc/aurelian/pkg/graph/transformers/aws"
	"github.com/praetorian-inc/aurelian/pkg/store"
	iampkg "github.com/praetorian-inc/aurelian/pkg/types"
)

// mockIAMClient is a userEnrichClient stub returning canned ListAccessKeys /
// GetLoginProfile responses (or errors) so the enrichment classification logic can
// be exercised without AWS.
type mockIAMClient struct {
	listKeysOut *iam.ListAccessKeysOutput
	listKeysErr error
	loginOut    *iam.GetLoginProfileOutput
	loginErr    error
}

func (m *mockIAMClient) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return m.listKeysOut, m.listKeysErr
}

func (m *mockIAMClient) GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	return m.loginOut, m.loginErr
}

func keysOutput(statuses ...iamtypes.StatusType) *iam.ListAccessKeysOutput {
	out := &iam.ListAccessKeysOutput{}
	for _, s := range statuses {
		out.AccessKeyMetadata = append(out.AccessKeyMetadata, iamtypes.AccessKeyMetadata{Status: s})
	}
	return out
}

func accessDenied() error {
	return &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized"}
}

func throttled() error {
	return &smithy.GenericAPIError{Code: "Throttling", Message: "rate exceeded"}
}

func noSuchEntityGeneric() error {
	return &smithy.GenericAPIError{Code: "NoSuchEntity", Message: "no login profile"}
}

func TestCountActiveAccessKeys(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		userName string
		out      *iam.ListAccessKeysOutput
		err      error
		want     *int // nil = unknown / fail-open
	}{
		{
			name:     "empty user name is unknown",
			userName: "",
			want:     nil,
		},
		{
			name:     "zero active keys is a confirmed 0, not unknown",
			userName: "u",
			out:      keysOutput(),
			want:     ptr(0),
		},
		{
			name:     "inactive keys are not counted",
			userName: "u",
			out:      keysOutput(iamtypes.StatusTypeInactive, iamtypes.StatusTypeInactive),
			want:     ptr(0),
		},
		{
			name:     "only active keys are counted",
			userName: "u",
			out:      keysOutput(iamtypes.StatusTypeActive, iamtypes.StatusTypeInactive, iamtypes.StatusTypeActive),
			want:     ptr(2),
		},
		{
			name:     "AccessDenied is unknown (fail-open)",
			userName: "u",
			err:      accessDenied(),
			want:     nil,
		},
		{
			name:     "throttle is unknown (fail-open)",
			userName: "u",
			err:      throttled(),
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockIAMClient{listKeysOut: tt.out, listKeysErr: tt.err}
			got := countActiveAccessKeys(ctx, client, tt.userName)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func TestHasLoginProfile(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		userName string
		out      *iam.GetLoginProfileOutput
		err      error
		want     *bool // nil = unknown / fail-open
	}{
		{
			name:     "empty user name is unknown",
			userName: "",
			want:     nil,
		},
		{
			name:     "success means a profile exists",
			userName: "u",
			out:      &iam.GetLoginProfileOutput{},
			want:     ptr(true),
		},
		{
			name:     "typed NoSuchEntity is a confirmed false, not unknown",
			userName: "u",
			err:      &iamtypes.NoSuchEntityException{},
			want:     ptr(false),
		},
		{
			name:     "generic NoSuchEntity APIError is a confirmed false",
			userName: "u",
			err:      noSuchEntityGeneric(),
			want:     ptr(false),
		},
		{
			name:     "AccessDenied is unknown (fail-open)",
			userName: "u",
			err:      accessDenied(),
			want:     nil,
		},
		{
			name:     "throttle is unknown (fail-open)",
			userName: "u",
			err:      throttled(),
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockIAMClient{loginOut: tt.out, loginErr: tt.err}
			got := hasLoginProfile(ctx, client, tt.userName)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, *tt.want, *got)
			}
		})
	}
}

func TestIsNoSuchEntity(t *testing.T) {
	assert.True(t, isNoSuchEntity(&iamtypes.NoSuchEntityException{}), "typed NoSuchEntity")
	assert.True(t, isNoSuchEntity(noSuchEntityGeneric()), "generic NoSuchEntity APIError")
	assert.False(t, isNoSuchEntity(accessDenied()), "AccessDenied is not NoSuchEntity")
	assert.False(t, isNoSuchEntity(errors.New("plain error")), "non-API error is not NoSuchEntity")
}

// TestEnrichUsersSerializesToNode is the regression test for the omitempty bug: it
// drives enrichUsers with a mock that confirms a privileged user has NO login profile
// (NoSuchEntity) and 0 active keys, then serializes the resulting user through the
// REAL NodeFromGaadUser path and asserts the node carries the explicit false / 0. A
// plain bool/int + omitempty would drop both, leaving the node without the prop and
// the iam_update_login_profile / iam_create_access_key guards unable to suppress.
func TestEnrichUsersSerializesToNode(t *testing.T) {
	ctx := context.Background()
	const arn = "arn:aws:iam::123456789012:user/no-profile-no-keys"

	users := store.NewMap[iampkg.UserDetail]()
	users.Set(arn, iampkg.UserDetail{Arn: arn, UserName: "no-profile-no-keys"})

	client := &mockIAMClient{
		listKeysOut: keysOutput(), // 0 active keys
		loginErr:    &iamtypes.NoSuchEntityException{},
	}
	enrichUsers(ctx, client, users)

	enriched, ok := users.Get(arn)
	require.True(t, ok)
	require.NotNil(t, enriched.AccessKeyCount, "confirmed 0 keys must be non-nil")
	assert.Equal(t, 0, *enriched.AccessKeyCount)
	require.NotNil(t, enriched.HasLoginProfile, "confirmed no-profile must be non-nil")
	assert.False(t, *enriched.HasLoginProfile)

	// The load-bearing assertion: the serialized node must carry the explicit values
	// so the Cypher guards can read them. flattenStruct drops only null pointers.
	node := transformaws.NodeFromGaadUser(enriched)
	gotCount, hasCount := node.Properties["AccessKeyCount"]
	require.True(t, hasCount, "AccessKeyCount must survive serialization (confirmed 0, not dropped)")
	assert.EqualValues(t, 0, gotCount)
	gotProfile, hasProfile := node.Properties["HasLoginProfile"]
	require.True(t, hasProfile, "HasLoginProfile must survive serialization (confirmed false, not dropped)")
	assert.Equal(t, false, gotProfile)
}

// TestEnrichUsersUnknownIsDropped proves the fail-open path: when both calls fail
// (AccessDenied), the fields stay nil and the serialized node carries NEITHER prop,
// so the guards fall open exactly as for a pre-enricher graph.
func TestEnrichUsersUnknownIsDropped(t *testing.T) {
	ctx := context.Background()
	const arn = "arn:aws:iam::123456789012:user/denied"

	users := store.NewMap[iampkg.UserDetail]()
	users.Set(arn, iampkg.UserDetail{Arn: arn, UserName: "denied"})

	client := &mockIAMClient{listKeysErr: accessDenied(), loginErr: accessDenied()}
	enrichUsers(ctx, client, users)

	enriched, ok := users.Get(arn)
	require.True(t, ok)
	assert.Nil(t, enriched.AccessKeyCount)
	assert.Nil(t, enriched.HasLoginProfile)

	node := transformaws.NodeFromGaadUser(enriched)
	_, hasCount := node.Properties["AccessKeyCount"]
	assert.False(t, hasCount, "nil AccessKeyCount must be dropped (absent → fail-open)")
	_, hasProfile := node.Properties["HasLoginProfile"]
	assert.False(t, hasProfile, "nil HasLoginProfile must be dropped (absent → fail-open)")
}

func ptr[T any](v T) *T { return &v }
