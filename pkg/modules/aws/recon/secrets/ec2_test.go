package secrets

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEC2UserDataClient struct {
	userData string
	err      error
}

func (m *mockEC2UserDataClient) DescribeInstanceAttribute(
	ctx context.Context,
	input *ec2.DescribeInstanceAttributeInput,
	opts ...func(*ec2.Options),
) (*ec2.DescribeInstanceAttributeOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := &ec2.DescribeInstanceAttributeOutput{}
	if m.userData != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(m.userData))
		out.UserData = &ec2types.AttributeValue{Value: aws.String(encoded)}
	}
	return out, nil
}

func TestExtractEC2_WithUserData(t *testing.T) {
	client := &mockEC2UserDataClient{
		userData: "#!/bin/bash\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
	}

	r := output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"InstanceId": "i-1234567890abcdef0"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractEC2WithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	assert.Equal(t, "UserData", items[0].Label)
	assert.Equal(t, r.ResourceID, items[0].ResourceID)
	assert.Contains(t, string(items[0].Content), "AWS_SECRET_ACCESS_KEY")
}

func TestExtractEC2_NoUserData(t *testing.T) {
	client := &mockEC2UserDataClient{userData: ""}

	r := output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   map[string]any{"InstanceId": "i-1234567890abcdef0"},
	}

	out := pipeline.New[ScanInput]()
	go func() {
		defer out.Close()
		err := extractEC2WithClient(client, r, out)
		require.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}
