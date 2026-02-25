package iam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionService(t *testing.T) {
	tests := []struct {
		name   string
		action Action
		want   string
	}{
		{
			name:   "standard action with colon",
			action: Action("s3:GetObject"),
			want:   "s3",
		},
		{
			name:   "action with no colon",
			action: Action("NoColon"),
			want:   "",
		},
		{
			name:   "action with multiple colons",
			action: Action("sts:AssumeRole:Extra"),
			want:   "",
		},
		{
			name:   "empty action",
			action: Action(""),
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.action.Service()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadJSONFile(t *testing.T) {
	t.Run("valid JSON file", func(t *testing.T) {
		type TestStruct struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "test.json")
		err := os.WriteFile(path, []byte(`{"name":"hello","value":42}`), 0644)
		require.NoError(t, err)

		result, err := LoadJSONFile[TestStruct](path)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "hello", result.Name)
		assert.Equal(t, 42, result.Value)
	})

	t.Run("file not found", func(t *testing.T) {
		type TestStruct struct {
			Name string `json:"name"`
		}

		result, err := LoadJSONFile[TestStruct]("/nonexistent/path/does-not-exist.json")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "reading")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		type TestStruct struct {
			Name string `json:"name"`
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "invalid.json")
		err := os.WriteFile(path, []byte(`{invalid json`), 0644)
		require.NoError(t, err)

		result, err := LoadJSONFile[TestStruct](path)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "parsing")
	})
}

func TestGetAccountFromArn(t *testing.T) {
	tests := []struct {
		name       string
		arnStr     string
		expectedID string
	}{
		{
			name:       "Valid ARN with account ID",
			arnStr:     "arn:aws:iam::123456789012:user/test-user",
			expectedID: "123456789012",
		},
		{
			name:       "Valid ARN without account ID",
			arnStr:     "arn:aws:s3:::example-bucket",
			expectedID: "",
		},
		{
			name:       "Invalid ARN format",
			arnStr:     "invalid-arn-format",
			expectedID: "",
		},
		{
			name:       "Empty ARN string",
			arnStr:     "",
			expectedID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountID := getAccountFromArn(tt.arnStr)
			assert.Equal(t, tt.expectedID, accountID)
		})
	}
}

func TestDeepCopy(t *testing.T) {
	type SampleStruct struct {
		Field1 string
		Field2 int
		Field3 []string
	}

	tests := []struct {
		name    string
		src     any
		dst     any
		wantErr bool
	}{
		{
			name: "Valid deep copy of struct",
			src: &SampleStruct{
				Field1: "test",
				Field2: 42,
				Field3: []string{"a", "b", "c"},
			},
			dst:     &SampleStruct{},
			wantErr: false,
		},
		{
			name:    "Nil source",
			src:     nil,
			dst:     &SampleStruct{},
			wantErr: true,
		},
		{
			name:    "Nil destination",
			src:     &SampleStruct{Field1: "test"},
			dst:     nil,
			wantErr: true,
		},
		{
			name: "Mismatched types",
			src: &SampleStruct{
				Field1: "test",
				Field2: 42,
			},
			dst:     &struct{ OtherField string }{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := deepCopy(tt.src, tt.dst)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.src, tt.dst)
			}
		})
	}
}

func TestGetIdentifierForEvalRequest(t *testing.T) {
	cfErd := types.NewEnrichedResourceDescription(
		"cloudformation.amazonaws.com",
		"AWS::Service",
		"*",
		"*",
		make(map[string]string),
	)
	s3, _ := types.NewEnrichedResourceDescriptionFromArn("arn:aws:s3:::example-bucket")

	tests := []struct {
		name     string
		erd      *types.EnrichedResourceDescription
		expected string
	}{
		{
			name:     "TypeName is AWS::Service",
			erd:      &cfErd,
			expected: "arn:aws:cloudformation:*:*:*",
		},
		{
			name:     "TypeName is not AWS::Service",
			erd:      &s3,
			expected: "arn:aws:s3:::example-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getIdentifierForEvalRequest(tt.erd)
			assert.Equal(t, tt.expected, result)
		})
	}
}
