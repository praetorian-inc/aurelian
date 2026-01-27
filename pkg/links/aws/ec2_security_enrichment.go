package aws

import (
	"context"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// EC2SecurityEnrichmentLink enriches EC2 instances with security group and NACL details
type EC2SecurityEnrichmentLink struct {
	*base.AwsReconLink
}

func NewEC2SecurityEnrichmentLink(configs ...cfg.Config) chain.Link {
	e := &EC2SecurityEnrichmentLink{}
	e.AwsReconLink = base.NewAwsReconLink(e, configs...)
	return e
}

func (e *EC2SecurityEnrichmentLink) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::EC2::Instance" {
		// Pass through non-EC2 resources unchanged
		e.Send(resource)
		return nil
	}

	config, err := e.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config for region", "region", resource.Region, "error", err)
		// Pass through the resource even if we can't enrich it
		e.Send(resource)
		return nil
	}

	ec2Client := ec2.NewFromConfig(config)

	// Get instance details including network interfaces
	instanceInput := &ec2.DescribeInstancesInput{
		InstanceIds: []string{resource.Identifier},
	}

	instanceOutput, err := ec2Client.DescribeInstances(context.TODO(), instanceInput)
	if err != nil {
		slog.Error("Failed to describe EC2 instance", "instance", resource.Identifier, "error", err)
		e.Send(resource)
		return nil
	}

	if len(instanceOutput.Reservations) == 0 || len(instanceOutput.Reservations[0].Instances) == 0 {
		slog.Error("No instance found", "instance", resource.Identifier)
		e.Send(resource)
		return nil
	}

	instance := instanceOutput.Reservations[0].Instances[0]

	// Extract security group IDs
	var securityGroupIds []string
	var networkInterfaceIds []string
	var subnetIds []string

	for _, networkInterface := range instance.NetworkInterfaces {
		networkInterfaceIds = append(networkInterfaceIds, *networkInterface.NetworkInterfaceId)
		if networkInterface.SubnetId != nil {
			subnetIds = append(subnetIds, *networkInterface.SubnetId)
		}
		for _, group := range networkInterface.Groups {
			securityGroupIds = append(securityGroupIds, *group.GroupId)
		}
	}

	// Get security group details
	securityGroups := e.getSecurityGroupDetails(ec2Client, securityGroupIds)

	// Get NACL details for associated subnets
	networkAcls := e.getNetworkAclDetails(ec2Client, subnetIds)

	// Enrich the resource properties
	if resource.Properties == nil {
		resource.Properties = make(map[string]interface{})
	}

	props := resource.Properties.(map[string]interface{})
	props["SecurityGroups"] = securityGroups
	props["NetworkAcls"] = networkAcls
	props["NetworkInterfaceIds"] = networkInterfaceIds
	props["SubnetIds"] = subnetIds

	e.Send(resource)
	return nil
}

func (e *EC2SecurityEnrichmentLink) getSecurityGroupDetails(client *ec2.Client, groupIds []string) []map[string]interface{} {
	if len(groupIds) == 0 {
		return nil
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniqueGroupIds []string
	for _, id := range groupIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniqueGroupIds = append(uniqueGroupIds, id)
		}
	}

	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: uniqueGroupIds,
	}

	output, err := client.DescribeSecurityGroups(context.TODO(), input)
	if err != nil {
		slog.Error("Failed to describe security groups", "groupIds", uniqueGroupIds, "error", err)
		return nil
	}

	// Get all unique prefix list IDs to resolve their names
	var allPrefixListIds []string
	for _, sg := range output.SecurityGroups {
		for _, rule := range sg.IpPermissions {
			for _, prefixList := range rule.PrefixListIds {
				allPrefixListIds = append(allPrefixListIds, *prefixList.PrefixListId)
			}
		}
		for _, rule := range sg.IpPermissionsEgress {
			for _, prefixList := range rule.PrefixListIds {
				allPrefixListIds = append(allPrefixListIds, *prefixList.PrefixListId)
			}
		}
	}

	// Resolve prefix list names and entries
	prefixListNames, prefixListDetails := e.resolvePrefixListNames(client, allPrefixListIds)

	var securityGroups []map[string]interface{}
	for _, sg := range output.SecurityGroups {
		sgInfo := map[string]interface{}{
			"GroupId":     *sg.GroupId,
			"GroupName":   *sg.GroupName,
			"VpcId":       *sg.VpcId,
			"Description": *sg.Description,
		}

		// Add additional security group metadata
		if sg.OwnerId != nil {
			sgInfo["OwnerId"] = *sg.OwnerId
		}
		if sg.SecurityGroupArn != nil {
			sgInfo["SecurityGroupArn"] = *sg.SecurityGroupArn
		}
		if len(sg.Tags) > 0 {
			tags := make(map[string]string)
			for _, tag := range sg.Tags {
				if tag.Key != nil && tag.Value != nil {
					tags[*tag.Key] = *tag.Value
				}
			}
			if len(tags) > 0 {
				sgInfo["Tags"] = tags
			}
		}

		// Add ingress rules
		var ingressRules []map[string]interface{}
		for _, rule := range sg.IpPermissions {
			ingressRule := map[string]interface{}{
				"Protocol": rule.IpProtocol,
			}

			// Handle port ranges - AWS uses -1 for "all ports"
			if rule.FromPort != nil {
				ingressRule["FromPort"] = *rule.FromPort
			}
			if rule.ToPort != nil {
				ingressRule["ToPort"] = *rule.ToPort
			}

			// Add source IP ranges (IPv4)
			var sourceRanges []map[string]interface{}
			for _, ipRange := range rule.IpRanges {
				rangeInfo := map[string]interface{}{
					"Range": *ipRange.CidrIp,
				}
				if ipRange.Description != nil {
					rangeInfo["Description"] = *ipRange.Description
				}
				sourceRanges = append(sourceRanges, rangeInfo)
			}
			if len(sourceRanges) > 0 {
				ingressRule["SourceRanges"] = sourceRanges
			}

			// Add source IPv6 ranges
			var sourceIpv6Ranges []map[string]interface{}
			for _, ipv6Range := range rule.Ipv6Ranges {
				rangeInfo := map[string]interface{}{
					"Range": *ipv6Range.CidrIpv6,
				}
				if ipv6Range.Description != nil {
					rangeInfo["Description"] = *ipv6Range.Description
				}
				sourceIpv6Ranges = append(sourceIpv6Ranges, rangeInfo)
			}
			if len(sourceIpv6Ranges) > 0 {
				ingressRule["SourceIpv6Ranges"] = sourceIpv6Ranges
			}

			// Add source security groups
			var sourceGroups []map[string]interface{}
			for _, group := range rule.UserIdGroupPairs {
				groupInfo := map[string]interface{}{
					"GroupId": *group.GroupId,
				}

				// Add additional group reference information
				if group.Description != nil {
					groupInfo["Description"] = *group.Description
				}
				if group.GroupName != nil {
					groupInfo["GroupName"] = *group.GroupName
				}
				if group.PeeringStatus != nil {
					groupInfo["PeeringStatus"] = *group.PeeringStatus
				}
				if group.UserId != nil {
					groupInfo["UserId"] = *group.UserId
				}
				if group.VpcId != nil {
					groupInfo["VpcId"] = *group.VpcId
				}

				sourceGroups = append(sourceGroups, groupInfo)
			}
			if len(sourceGroups) > 0 {
				ingressRule["SourceGroups"] = sourceGroups
			}

			// Add source prefix lists with names and entries
			var sourcePrefixLists []map[string]interface{}
			for _, prefixList := range rule.PrefixListIds {
				prefixListInfo := map[string]interface{}{
					"PrefixListId": *prefixList.PrefixListId,
				}

				// Add prefix list name if resolved
				if name, exists := prefixListNames[*prefixList.PrefixListId]; exists {
					prefixListInfo["Name"] = name
				}

				// Add description if available
				if prefixList.Description != nil {
					prefixListInfo["Description"] = *prefixList.Description
				}

				// Add actual prefix list entries (IP ranges)
				if details, exists := prefixListDetails[*prefixList.PrefixListId]; exists {
					if entries, hasEntries := details["Entries"]; hasEntries {
						prefixListInfo["Entries"] = entries
					}
					// Also add other metadata
					for key, value := range details {
						if key != "Entries" { // Don't duplicate entries
							prefixListInfo[key] = value
						}
					}
				}

				sourcePrefixLists = append(sourcePrefixLists, prefixListInfo)
			}
			if len(sourcePrefixLists) > 0 {
				ingressRule["SourcePrefixLists"] = sourcePrefixLists
			}

			ingressRules = append(ingressRules, ingressRule)
		}
		sgInfo["IngressRules"] = ingressRules

		// Add egress rules
		var egressRules []map[string]interface{}
		for _, rule := range sg.IpPermissionsEgress {
			egressRule := map[string]interface{}{
				"Protocol": rule.IpProtocol,
			}

			// Handle port ranges - AWS uses -1 for "all ports"
			if rule.FromPort != nil {
				egressRule["FromPort"] = *rule.FromPort
			}
			if rule.ToPort != nil {
				egressRule["ToPort"] = *rule.ToPort
			}

			// Add destination IP ranges (IPv4)
			var destRanges []map[string]interface{}
			for _, ipRange := range rule.IpRanges {
				rangeInfo := map[string]interface{}{
					"Range": *ipRange.CidrIp,
				}
				if ipRange.Description != nil {
					rangeInfo["Description"] = *ipRange.Description
				}
				destRanges = append(destRanges, rangeInfo)
			}
			if len(destRanges) > 0 {
				egressRule["DestinationRanges"] = destRanges
			}

			// Add destination IPv6 ranges
			var destIpv6Ranges []map[string]interface{}
			for _, ipv6Range := range rule.Ipv6Ranges {
				rangeInfo := map[string]interface{}{
					"Range": *ipv6Range.CidrIpv6,
				}
				if ipv6Range.Description != nil {
					rangeInfo["Description"] = *ipv6Range.Description
				}
				destIpv6Ranges = append(destIpv6Ranges, rangeInfo)
			}
			if len(destIpv6Ranges) > 0 {
				egressRule["DestinationIpv6Ranges"] = destIpv6Ranges
			}

			// Add destination security groups
			var destGroups []map[string]interface{}
			for _, group := range rule.UserIdGroupPairs {
				groupInfo := map[string]interface{}{
					"GroupId": *group.GroupId,
				}

				// Add additional group reference information
				if group.Description != nil {
					groupInfo["Description"] = *group.Description
				}
				if group.GroupName != nil {
					groupInfo["GroupName"] = *group.GroupName
				}
				if group.PeeringStatus != nil {
					groupInfo["PeeringStatus"] = *group.PeeringStatus
				}
				if group.UserId != nil {
					groupInfo["UserId"] = *group.UserId
				}
				if group.VpcId != nil {
					groupInfo["VpcId"] = *group.VpcId
				}

				destGroups = append(destGroups, groupInfo)
			}
			if len(destGroups) > 0 {
				egressRule["DestinationGroups"] = destGroups
			}

			// Add destination prefix lists with names and entries
			var destPrefixLists []map[string]interface{}
			for _, prefixList := range rule.PrefixListIds {
				prefixListInfo := map[string]interface{}{
					"PrefixListId": *prefixList.PrefixListId,
				}

				// Add prefix list name if resolved
				if name, exists := prefixListNames[*prefixList.PrefixListId]; exists {
					prefixListInfo["Name"] = name
				}

				// Add description if available
				if prefixList.Description != nil {
					prefixListInfo["Description"] = *prefixList.Description
				}

				// Add actual prefix list entries (IP ranges)
				if details, exists := prefixListDetails[*prefixList.PrefixListId]; exists {
					if entries, hasEntries := details["Entries"]; hasEntries {
						prefixListInfo["Entries"] = entries
					}
					// Also add other metadata
					for key, value := range details {
						if key != "Entries" { // Don't duplicate entries
							prefixListInfo[key] = value
						}
					}
				}

				destPrefixLists = append(destPrefixLists, prefixListInfo)
			}
			if len(destPrefixLists) > 0 {
				egressRule["DestinationPrefixLists"] = destPrefixLists
			}

			egressRules = append(egressRules, egressRule)
		}
		sgInfo["EgressRules"] = egressRules

		// Add summary information
		sgInfo["RuleSummary"] = map[string]interface{}{
			"IngressRuleCount": len(ingressRules),
			"EgressRuleCount":  len(egressRules),
			"TotalRuleCount":   len(ingressRules) + len(egressRules),
		}

		securityGroups = append(securityGroups, sgInfo)
	}

	return securityGroups
}

// resolvePrefixListNames resolves prefix list IDs to their names and entries for better readability
func (e *EC2SecurityEnrichmentLink) resolvePrefixListNames(client *ec2.Client, prefixListIds []string) (map[string]string, map[string]map[string]interface{}) {
	if len(prefixListIds) == 0 {
		return make(map[string]string), make(map[string]map[string]interface{})
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniquePrefixListIds []string
	for _, id := range prefixListIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniquePrefixListIds = append(uniquePrefixListIds, id)
		}
	}

	slog.Info("Resolving prefix list names and entries", "count", len(uniquePrefixListIds))

	// AWS API has a limit on the number of IDs per request, so we might need to batch
	const maxIdsPerRequest = 200
	prefixListNames := make(map[string]string)
	prefixListDetails := make(map[string]map[string]interface{})

	for i := 0; i < len(uniquePrefixListIds); i += maxIdsPerRequest {
		end := i + maxIdsPerRequest
		if end > len(uniquePrefixListIds) {
			end = len(uniquePrefixListIds)
		}

		batch := uniquePrefixListIds[i:end]
		input := &ec2.DescribeManagedPrefixListsInput{
			PrefixListIds: batch,
		}

		output, err := client.DescribeManagedPrefixLists(context.TODO(), input)
		if err != nil {
			slog.Error("Failed to describe prefix lists", "prefixListIds", batch, "error", err)
			continue
		}

		for _, prefixList := range output.PrefixLists {
			if prefixList.PrefixListId != nil && prefixList.PrefixListName != nil {
				prefixListNames[*prefixList.PrefixListId] = *prefixList.PrefixListName

				// Store additional prefix list metadata
				details := map[string]interface{}{
					"Name": *prefixList.PrefixListName,
				}

				if prefixList.PrefixListArn != nil {
					details["PrefixListArn"] = *prefixList.PrefixListArn
				}
				if prefixList.Version != nil {
					details["Version"] = *prefixList.Version
				}
				if prefixList.MaxEntries != nil {
					details["MaxEntries"] = *prefixList.MaxEntries
				}
				details["State"] = prefixList.State
				if prefixList.StateMessage != nil {
					details["StateMessage"] = *prefixList.StateMessage
				}
				if prefixList.AddressFamily != nil {
					details["AddressFamily"] = *prefixList.AddressFamily
				}
				if prefixList.OwnerId != nil {
					details["OwnerId"] = *prefixList.OwnerId
				}
				if len(prefixList.Tags) > 0 {
					tags := make(map[string]string)
					for _, tag := range prefixList.Tags {
						if tag.Key != nil && tag.Value != nil {
							tags[*tag.Key] = *tag.Value
						}
					}
					if len(tags) > 0 {
						details["Tags"] = tags
					}
				}

				prefixListDetails[*prefixList.PrefixListId] = details
				slog.Debug("Resolved prefix list", "id", *prefixList.PrefixListId, "name", *prefixList.PrefixListName)
			}
		}
	}

	// Now get the actual entries for each prefix list
	for i := 0; i < len(uniquePrefixListIds); i += maxIdsPerRequest {
		end := i + maxIdsPerRequest
		if end > len(uniquePrefixListIds) {
			end = len(uniquePrefixListIds)
		}

		batch := uniquePrefixListIds[i:end]

		// Process each prefix list individually since GetManagedPrefixListEntries doesn't support batching
		for _, prefixListId := range batch {
			input := &ec2.GetManagedPrefixListEntriesInput{
				PrefixListId: &prefixListId,
			}

			entriesOutput, err := client.GetManagedPrefixListEntries(context.TODO(), input)
			if err != nil {
				slog.Error("Failed to get prefix list entries", "prefixListId", prefixListId, "error", err)
				continue
			}

			var entries []map[string]interface{}
			for _, entry := range entriesOutput.Entries {
				entryInfo := map[string]interface{}{
					"Cidr": *entry.Cidr,
				}

				// Add description if available
				if entry.Description != nil {
					entryInfo["Description"] = *entry.Description
				}

				entries = append(entries, entryInfo)
			}

			if len(entries) > 0 {
				// Add entries to existing details
				if details, exists := prefixListDetails[prefixListId]; exists {
					details["Entries"] = entries
					details["EntryCount"] = len(entries)
				} else {
					// Create new details if none existed
					prefixListDetails[prefixListId] = map[string]interface{}{
						"Entries":    entries,
						"EntryCount": len(entries),
					}
				}
				slog.Debug("Retrieved prefix list entries", "id", prefixListId, "entryCount", len(entries))
			}
		}
	}

	slog.Info("Successfully resolved prefix list names and entries",
		"resolvedNames", len(prefixListNames),
		"resolvedDetails", len(prefixListDetails),
		"total", len(uniquePrefixListIds))

	return prefixListNames, prefixListDetails
}

func (e *EC2SecurityEnrichmentLink) getNetworkAclDetails(client *ec2.Client, subnetIds []string) []map[string]interface{} {
	if len(subnetIds) == 0 {
		return nil
	}

	// Remove duplicates
	uniqueIds := make(map[string]bool)
	var uniqueSubnetIds []string
	for _, id := range subnetIds {
		if !uniqueIds[id] {
			uniqueIds[id] = true
			uniqueSubnetIds = append(uniqueSubnetIds, id)
		}
	}

	// Get subnet details to find associated NACLs
	// Note: We'll get NACL associations directly from the DescribeNetworkAcls API

	// For subnets, we need to use the DescribeNetworkAcls API with subnet filters
	// since subnets don't directly expose their NACL ID
	var naclIds []string
	if len(uniqueSubnetIds) > 0 {
		// Get all NACLs in the VPC and filter by subnet association
		naclInput := &ec2.DescribeNetworkAclsInput{}
		naclOutput, err := client.DescribeNetworkAcls(context.TODO(), naclInput)
		if err != nil {
			slog.Error("Failed to describe network ACLs", "error", err)
			return nil
		}

		// Find NACLs that are associated with our subnets
		for _, nacl := range naclOutput.NetworkAcls {
			for _, association := range nacl.Associations {
				if association.SubnetId != nil {
					for _, subnetId := range uniqueSubnetIds {
						if *association.SubnetId == subnetId {
							naclIds = append(naclIds, *nacl.NetworkAclId)
							break
						}
					}
				}
			}
		}
	}

	if len(naclIds) == 0 {
		return nil
	}

	// Get NACL details
	naclInput := &ec2.DescribeNetworkAclsInput{
		NetworkAclIds: naclIds,
	}

	naclOutput, err := client.DescribeNetworkAcls(context.TODO(), naclInput)
	if err != nil {
		slog.Error("Failed to describe network ACLs", "naclIds", naclIds, "error", err)
		return nil
	}

	var networkAcls []map[string]interface{}
	for _, nacl := range naclOutput.NetworkAcls {
		naclInfo := map[string]interface{}{
			"NetworkAclId": *nacl.NetworkAclId,
			"VpcId":        *nacl.VpcId,
			"IsDefault":    nacl.IsDefault,
		}

		// Add entries (rules)
		var entries []map[string]interface{}
		for _, entry := range nacl.Entries {
			entryInfo := map[string]interface{}{
				"RuleNumber": entry.RuleNumber,
				"Protocol":   entry.Protocol,
				"RuleAction": entry.RuleAction,
				"Egress":     entry.Egress,
			}

			if entry.CidrBlock != nil {
				entryInfo["CidrBlock"] = *entry.CidrBlock
			}
			if entry.IcmpTypeCode != nil {
				entryInfo["IcmpTypeCode"] = map[string]interface{}{
					"Type": entry.IcmpTypeCode.Type,
					"Code": entry.IcmpTypeCode.Code,
				}
			}
			if entry.PortRange != nil {
				entryInfo["PortRange"] = map[string]interface{}{
					"From": entry.PortRange.From,
					"To":   entry.PortRange.To,
				}
			}

			entries = append(entries, entryInfo)
		}
		naclInfo["Entries"] = entries

		networkAcls = append(networkAcls, naclInfo)
	}

	return networkAcls
}
