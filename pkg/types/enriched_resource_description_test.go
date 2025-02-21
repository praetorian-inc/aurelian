package types

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTags(t *testing.T) {
	testCases := []struct {
		name     string
		erd      string
		expected map[string]string
	}{
		{
			name: "Tags present",
			erd: `{
    "Identifier": "eni-0e8bade12fb6000d8",
    "TypeName": "AWS::EC2::NetworkInterface",
    "Region": "us-east-2",
    "Properties": "{\"Description\":\"EFS mount target for fs-011adcbc820abb7da (fsmt-abcdef12345678901)\",\"PrivateIpAddress\":\"172.31.11.78\",\"PrimaryIpv6Address\":\"\",\"PrivateIpAddresses\":[{\"PrivateIpAddress\":\"172.31.11.78\",\"Primary\":true}],\"SecondaryPrivateIpAddressCount\":0,\"Ipv6PrefixCount\":0,\"PrimaryPrivateIpAddress\":\"172.31.11.78\",\"Ipv4Prefixes\":[],\"Ipv4PrefixCount\":0,\"GroupSet\":[\"sg-00abcdef123456789\",\"sg-d123456d\"],\"Ipv6Prefixes\":[],\"SubnetId\":\"subnet-b1234456\",\"SourceDestCheck\":true,\"InterfaceType\":\"null\",\"SecondaryPrivateIpAddresses\":[],\"VpcId\":\"vpc-7abcdef1\",\"Id\":\"eni-0e1234567890000d8\",\"Tags\":[{\"Value\":\"arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAmazonElasticFileSystem/001540145697\",\"Key\":\"AutoTag_Creator\"},{\"Value\":\"elasticfilesystem.amazonaws.com\",\"Key\":\"AutoTag_InvokedBy\"},{\"Value\":\"2024-05-21T23:12:32Z\",\"Key\":\"AutoTag_CreateTime\"}]}",                                                                                                          "AccountId": "555045483459",
    "Arn": {
      "Partition": "aws",
      "Service": "ec2",
      "Region": "us-east-2",
      "AccountID": "555045483459",
      "Resource": "eni-0e8bade12fb6000d8"
    }
  }`,
			expected: map[string]string{
				"AutoTag_CreateTime": "2024-05-21T23:12:32Z",
				"AutoTag_Creator":    "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForAmazonElasticFileSystem/001540145697",
				"AutoTag_InvokedBy":  "elasticfilesystem.amazonaws.com",
			},
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var erd EnrichedResourceDescription
			json.Unmarshal([]byte(tc.erd), &erd)

			tags := erd.Tags()
			if !reflect.DeepEqual(tags, tc.expected) {
				t.Errorf("Expected tags: %v, got: %v", tc.expected, tags)
			}
		})
	}
}
