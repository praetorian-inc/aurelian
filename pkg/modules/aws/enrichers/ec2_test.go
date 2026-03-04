package enrichers_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEC2Client struct {
	sgOutput   *ec2.DescribeSecurityGroupsOutput
	sgError    error
	naclOutput *ec2.DescribeNetworkAclsOutput
	naclError  error
}

func (m *mockEC2Client) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return m.sgOutput, m.sgError
}

func (m *mockEC2Client) DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	return m.naclOutput, m.naclError
}

func TestEnrichEC2Instance_NoPublicIP(t *testing.T) {
	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties:   map[string]any{},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichEC2Instance(cfg, resource, &mockEC2Client{})
	require.NoError(t, err)
	assert.Empty(t, resource.Properties["SecurityGroupIngressRules"])
}

func TestEnrichEC2Instance_WithPublicIP(t *testing.T) {
	mockClient := &mockEC2Client{
		sgOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-12345"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(443),
							ToPort:     aws.Int32(443),
							IpRanges: []ec2types.IpRange{
								{CidrIp: aws.String("0.0.0.0/0")},
							},
						},
					},
				},
			},
		},
		naclOutput: &ec2.DescribeNetworkAclsOutput{
			NetworkAcls: []ec2types.NetworkAcl{},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties: map[string]any{
			"PublicIpAddress": "1.2.3.4",
			"SubnetId":        "subnet-12345",
			"SecurityGroups": []any{
				map[string]any{"GroupId": "sg-12345"},
			},
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichEC2Instance(cfg, resource, mockClient)
	require.NoError(t, err)

	rules, ok := resource.Properties["SecurityGroupIngressRules"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, rules, 1)
	assert.Equal(t, "sg-12345", rules[0]["SecurityGroupId"])
}

func TestEnrichEC2Instance_WithNACLRules(t *testing.T) {
	egress := true
	ingress := false
	mockClient := &mockEC2Client{
		sgOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-12345"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("tcp"),
							FromPort:   aws.Int32(80),
							ToPort:     aws.Int32(80),
							IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
						},
					},
				},
			},
		},
		naclOutput: &ec2.DescribeNetworkAclsOutput{
			NetworkAcls: []ec2types.NetworkAcl{
				{
					Entries: []ec2types.NetworkAclEntry{
						{
							Egress:     &egress,
							RuleNumber: aws.Int32(100),
							RuleAction: ec2types.RuleActionAllow,
							Protocol:   aws.String("-1"),
							CidrBlock:  aws.String("0.0.0.0/0"),
						},
						{
							Egress:     &ingress,
							RuleNumber: aws.Int32(100),
							RuleAction: ec2types.RuleActionAllow,
							Protocol:   aws.String("6"),
							CidrBlock:  aws.String("0.0.0.0/0"),
							PortRange:  &ec2types.PortRange{From: aws.Int32(80), To: aws.Int32(80)},
						},
						{
							Egress:        &ingress,
							RuleNumber:    aws.Int32(200),
							RuleAction:    ec2types.RuleActionDeny,
							Protocol:      aws.String("-1"),
							Ipv6CidrBlock: aws.String("::/0"),
						},
					},
				},
			},
		},
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-abc",
		Properties: map[string]any{
			"PublicIpAddress": "1.2.3.4",
			"SubnetId":        "subnet-12345",
			"SecurityGroups": []any{
				map[string]any{"GroupId": "sg-12345"},
			},
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichEC2Instance(cfg, resource, mockClient)
	require.NoError(t, err)

	// Verify SG rules include IPv6
	sgRules, ok := resource.Properties["SecurityGroupIngressRules"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, sgRules, 1)
	cidrs := sgRules[0]["CidrRanges"].([]string)
	assert.Contains(t, cidrs, "0.0.0.0/0")
	assert.Contains(t, cidrs, "::/0")

	// Verify NACL rules: egress filtered out, 2 ingress entries remain
	naclRules, ok := resource.Properties["NetworkAclIngressRules"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, naclRules, 2)
	// First ingress rule has port range
	assert.Equal(t, int32(80), naclRules[0]["FromPort"])
	assert.Equal(t, int32(80), naclRules[0]["ToPort"])
	assert.Equal(t, "0.0.0.0/0", naclRules[0]["CidrBlock"])
	// Second ingress rule has IPv6
	assert.Equal(t, "::/0", naclRules[1]["Ipv6CidrBlock"])
}

func TestEnrichEC2Instance_SecurityGroupError(t *testing.T) {
	mockClient := &mockEC2Client{
		sgError: fmt.Errorf("access denied"),
	}

	resource := &output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   "i-1234567890abcdef0",
		Properties: map[string]any{
			"PublicIpAddress": "1.2.3.4",
			"SecurityGroups": []any{
				map[string]any{"GroupId": "sg-12345"},
			},
		},
	}

	cfg := plugin.EnricherConfig{Context: context.Background(), AWSConfig: aws.Config{}}
	err := enrichers.EnrichEC2Instance(cfg, resource, mockClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to describe security groups")
}
