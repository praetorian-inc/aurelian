package aws

import (
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/stretchr/testify/assert"
)

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
			expected: "cloudformation.amazonaws.com",
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
