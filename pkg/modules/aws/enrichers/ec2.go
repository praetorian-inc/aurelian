package enrichers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::EC2::Instance", enrichEC2InstanceWrapper)
}

// EC2Client interface for testing
type EC2Client interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
}

func enrichEC2InstanceWrapper(cfg plugin.EnricherConfig, r *output.CloudResource) error {
	client := ec2.NewFromConfig(cfg.AWSConfig)
	return EnrichEC2Instance(cfg, r, client)
}

// EnrichEC2Instance adds security group and NACL information to EC2 instances with public IPs.
func EnrichEC2Instance(cfg plugin.EnricherConfig, r *output.CloudResource, client EC2Client) error {
	// Check if instance has a public IP
	// CloudControl uses "PublicIp", CloudFormation uses "PublicIpAddress"
	publicIP, _ := r.Properties["PublicIp"].(string)
	if publicIP == "" {
		publicIP, _ = r.Properties["PublicIpAddress"].(string)
	}
	if publicIP == "" {
		return nil
	}

	// Fetch security group details
	sgIDs := extractSecurityGroupIDs(r)
	if len(sgIDs) > 0 {
		sgOut, err := client.DescribeSecurityGroups(cfg.Context, &ec2.DescribeSecurityGroupsInput{
			GroupIds: sgIDs,
		})
		if err != nil {
			return fmt.Errorf("failed to describe security groups: %w", err)
		}

		var ingressRules []map[string]any
		for _, sg := range sgOut.SecurityGroups {
			for _, perm := range sg.IpPermissions {
				rule := map[string]any{
					"SecurityGroupId": stringVal(sg.GroupId),
					"IpProtocol":      stringVal(perm.IpProtocol),
				}
				if perm.FromPort != nil {
					rule["FromPort"] = *perm.FromPort
				}
				if perm.ToPort != nil {
					rule["ToPort"] = *perm.ToPort
				}
				var cidrs []string
				for _, r := range perm.IpRanges {
					if r.CidrIp != nil {
						cidrs = append(cidrs, *r.CidrIp)
					}
				}
				for _, r := range perm.Ipv6Ranges {
					if r.CidrIpv6 != nil {
						cidrs = append(cidrs, *r.CidrIpv6)
					}
				}
				rule["CidrRanges"] = cidrs
				ingressRules = append(ingressRules, rule)
			}
		}
		if len(ingressRules) > 0 {
			r.Properties["SecurityGroupIngressRules"] = ingressRules
		}
	}

	// Fetch NACL details for the subnet
	subnetID, _ := r.Properties["SubnetId"].(string)
	if subnetID != "" {
		naclOut, err := client.DescribeNetworkAcls(cfg.Context, &ec2.DescribeNetworkAclsInput{
			Filters: []ec2types.Filter{
				{
					Name:   strPtr("association.subnet-id"),
					Values: []string{subnetID},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to describe network ACLs: %w", err)
		}

		var naclRules []map[string]any
		for _, nacl := range naclOut.NetworkAcls {
			for _, entry := range nacl.Entries {
				if entry.Egress != nil && *entry.Egress {
					continue // Skip egress rules
				}
				rule := map[string]any{
					"RuleNumber": intVal(entry.RuleNumber),
					"RuleAction": string(entry.RuleAction),
					"Protocol":   stringVal(entry.Protocol),
				}
				if entry.CidrBlock != nil {
					rule["CidrBlock"] = *entry.CidrBlock
				}
				if entry.Ipv6CidrBlock != nil {
					rule["Ipv6CidrBlock"] = *entry.Ipv6CidrBlock
				}
				if entry.PortRange != nil {
					rule["FromPort"] = intVal(entry.PortRange.From)
					rule["ToPort"] = intVal(entry.PortRange.To)
				}
				naclRules = append(naclRules, rule)
			}
		}
		if len(naclRules) > 0 {
			r.Properties["NetworkAclIngressRules"] = naclRules
		}
	}

	return nil
}

func extractSecurityGroupIDs(r *output.CloudResource) []string {
	// CloudControl returns "SecurityGroupIds" as []string
	if sgIDs, ok := r.Properties["SecurityGroupIds"].([]any); ok {
		var ids []string
		for _, id := range sgIDs {
			if s, ok := id.(string); ok && s != "" {
				ids = append(ids, s)
			}
		}
		if len(ids) > 0 {
			return ids
		}
	}

	// Fallback: check "SecurityGroups" as []map with "GroupId" key
	sgList, ok := r.Properties["SecurityGroups"].([]any)
	if !ok {
		return nil
	}

	var ids []string
	for _, sg := range sgList {
		sgMap, ok := sg.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := sgMap["GroupId"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func strPtr(s string) *string { return &s }

func stringVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intVal(i *int32) int32 {
	if i == nil {
		return 0
	}
	return *i
}
