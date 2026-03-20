package iam

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullResult_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		jsonInput   string
		wantErr     bool
		checkResult func(t *testing.T, fr *FullResult)
	}{
		{
			name:      "UserDetail principal detected by UserName field",
			jsonInput: `{"principal":{"UserName":"alice","Arn":"arn:aws:iam::123456789012:user/alice"},"action":"s3:GetObject","resource":null,"result":null}`,
			wantErr:   false,
			checkResult: func(t *testing.T, fr *FullResult) {
				user, ok := fr.Principal.(*types.UserDetail)
				require.True(t, ok, "expected *types.UserDetail, got %T", fr.Principal)
				assert.Equal(t, "alice", user.UserName)
				assert.Equal(t, "arn:aws:iam::123456789012:user/alice", user.Arn)
				assert.Equal(t, "s3:GetObject", fr.Action)
			},
		},
		{
			name:      "RoleDetail principal detected by RoleName field",
			jsonInput: `{"principal":{"RoleName":"my-role","Arn":"arn:aws:iam::123456789012:role/my-role"},"action":"sts:AssumeRole","resource":null,"result":null}`,
			wantErr:   false,
			checkResult: func(t *testing.T, fr *FullResult) {
				role, ok := fr.Principal.(*types.RoleDetail)
				require.True(t, ok, "expected *types.RoleDetail, got %T", fr.Principal)
				assert.Equal(t, "my-role", role.RoleName)
				assert.Equal(t, "arn:aws:iam::123456789012:role/my-role", role.Arn)
			},
		},
		{
			name:      "GroupDetail principal detected by GroupName field",
			jsonInput: `{"principal":{"GroupName":"admins","Arn":"arn:aws:iam::123456789012:group/admins"},"action":"iam:ListGroups","resource":null,"result":null}`,
			wantErr:   false,
			checkResult: func(t *testing.T, fr *FullResult) {
				group, ok := fr.Principal.(*types.GroupDetail)
				require.True(t, ok, "expected *types.GroupDetail, got %T", fr.Principal)
				assert.Equal(t, "admins", group.GroupName)
				assert.Equal(t, "arn:aws:iam::123456789012:group/admins", group.Arn)
			},
		},
		{
			name:      "string principal (service principal)",
			jsonInput: `{"principal":"lambda.amazonaws.com","action":"sts:AssumeRole","resource":null,"result":null}`,
			wantErr:   false,
			checkResult: func(t *testing.T, fr *FullResult) {
				s, ok := fr.Principal.(string)
				require.True(t, ok, "expected string, got %T", fr.Principal)
				assert.Equal(t, "lambda.amazonaws.com", s)
			},
		},
		{
			name:      "unknown object falls back to map",
			jsonInput: `{"principal":{"CustomField":"custom-value","AnotherField":42},"action":"custom:Action","resource":null,"result":null}`,
			wantErr:   false,
			checkResult: func(t *testing.T, fr *FullResult) {
				m, ok := fr.Principal.(map[string]interface{})
				require.True(t, ok, "expected map[string]interface{}, got %T", fr.Principal)
				assert.Equal(t, "custom-value", m["CustomField"])
			},
		},
		{
			name:      "malformed JSON returns error",
			jsonInput: `{"principal": {invalid json}`,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fr FullResult
			err := json.Unmarshal([]byte(tt.jsonInput), &fr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.checkResult != nil {
				tt.checkResult(t, &fr)
			}
		})
	}
}
