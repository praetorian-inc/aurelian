package aws

import (
	"testing"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestEvaluateConditions(t *testing.T) {
	testCases := []struct {
		name       string
		conditions *types.Condition
		context    *RequestContext
		expected   bool
	}{
		{
			name: "StringEquals match",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:username": {"test-user"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"aws:username": "test-user",
				},
			},
			expected: true,
		},
		{
			name: "StringEquals no match",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:username": {"test-user"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"aws:username": "another-user",
				},
			},
			expected: false,
		},
		{
			name: "IpAddress match",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"192.168.1.1/24"},
				},
			},
			context: &RequestContext{
				SourceIp: "192.168.1.5",
			},
			expected: true,
		},
		{
			name: "IpAddress no match",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"192.168.1.1/24"},
				},
			},
			context: &RequestContext{
				SourceIp: "10.0.0.1",
			},
			expected: false,
		},
		{
			name: "DateGreaterThan match",
			conditions: &types.Condition{
				"DateGreaterThan": {
					"aws:CurrentTime": {"2023-01-01T00:00:00Z"},
				},
			},
			context: &RequestContext{
				CurrentTime: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
			},
			expected: true,
		},
		{
			name: "DateGreaterThan no match",
			conditions: &types.Condition{
				"DateGreaterThan": {
					"aws:CurrentTime": {"2023-01-01T00:00:00Z"},
				},
			},
			context: &RequestContext{
				CurrentTime: time.Date(2022, 12, 31, 0, 0, 0, 0, time.UTC),
			},
			expected: false,
		},

		{
			name: "Multiple string conditions with wildcards - all must match",
			conditions: &types.Condition{
				"StringLike": {
					"aws:PrincipalArn": []string{"arn:aws:iam::*:user/test-*"},
					"aws:UserAgent":    []string{"*Console*"},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:user/test-user",
				UserAgent:    "AWS-Console-SignIn",
			},
			expected: true,
		},
		{
			name: "IfExists allows missing key",
			conditions: &types.Condition{
				"StringEqualsIfExists": {
					"aws:ResourceTag/environment": []string{"production"},
				},
			},
			context: &RequestContext{
				ResourceTags: map[string]string{}, // No tags present
			},
			expected: true,
		},
		{
			name: "IfExists still evaluates present key",
			conditions: &types.Condition{
				"StringEqualsIfExists": {
					"aws:ResourceTag/environment": []string{"production"},
				},
			},
			context: &RequestContext{
				ResourceTags: map[string]string{
					"environment": "development",
				},
			},
			expected: false,
		},
		{
			name: "IP address with both IPv4 and IPv6",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": []string{
						"203.0.113.0/24",
						"2001:DB8:1234:5678::/64",
					},
				},
			},
			context: &RequestContext{
				SourceIp: "203.0.113.45",
			},
			expected: true,
		},
		{
			name: "NotIpAddress with IPv6",
			conditions: &types.Condition{
				"NotIpAddress": {
					"aws:SourceIp": []string{"2001:DB8:1234:5678::/64"},
				},
			},
			context: &RequestContext{
				SourceIp: "203.0.113.45",
			},
			expected: true,
		},
		{
			name: "String case insensitive with multiple values",
			conditions: &types.Condition{
				"StringEqualsIgnoreCase": {
					"aws:PrincipalTag/Department": []string{"HR", "Finance"},
				},
			},
			context: &RequestContext{
				ResourceTags: map[string]string{
					"Department": "hr",
				},
			},
			expected: true,
		},
		{
			name: "Date comparison with current time",
			conditions: &types.Condition{
				"DateGreaterThan": {
					"aws:CurrentTime": []string{"2020-01-01T00:00:00Z"},
				},
			},
			context: &RequestContext{
				CurrentTime: time.Now(),
			},
			expected: true,
		},
		{
			name: "Multiple conditions - all must match",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": []string{"true"},
				},
				"StringLike": {
					"aws:PrincipalArn": []string{"arn:aws:iam::*:user/*"},
				},
				"NumericLessThanEquals": {
					"aws:MultiFactorAuthAge": []string{"3600"},
				},
			},
			context: &RequestContext{
				SecureTransport: true,
				PrincipalArn:    "arn:aws:iam::123456789012:user/test",
				RequestParameters: map[string]string{
					"MultiFactorAuthAge": "1800",
				},
			},
			expected: true,
		},
		{
			name: "Null condition checking non-existent tag",
			conditions: &types.Condition{
				"Null": {
					"aws:ResourceTag/Owner": []string{"true"},
				},
			},
			context: &RequestContext{
				ResourceTags: map[string]string{
					"Environment": "Production",
				},
			},
			expected: true,
		},
		{
			name: "Complex ARN matching with multiple wildcards",
			conditions: &types.Condition{
				"ArnLike": {
					"aws:PrincipalArn": []string{
						"arn:aws:iam::*:role/service-*/*",
						"arn:aws:iam::*:user/*",
					},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/service-role/lambda-function",
			},
			expected: true,
		},
		{
			name: "Multivalued tag keys with ForAllValues",
			conditions: &types.Condition{
				"ForAllValues:StringEquals": {
					"aws:TagKeys": []string{"Environment", "CostCenter"},
				},
			},
			context: &RequestContext{
				RequestTags: map[string]string{
					"Environment": "Production",
					"CostCenter":  "12345",
				},
			},
			expected: true,
		},
		{
			name: "Multivalued tag keys with ForAnyValue",
			conditions: &types.Condition{
				"ForAnyValue:StringLike": {
					"aws:PrincipalOrgPaths": []string{
						"o-a1b2c3d4e5/r-ab12/ou-ab12-*/*",
					},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"PrincipalOrgPaths": "o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/ou-ab12-22222222",
				},
			},
			expected: true,
		},
		{
			name: "StringNotLike with multiple patterns",
			conditions: &types.Condition{
				"StringNotLike": {
					"aws:PrincipalArn": []string{
						"arn:aws:iam::*:role/banned-*",
						"arn:aws:iam::*:user/blocked-*",
					},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:user/allowed-user",
			},
			expected: true,
		},
		{
			name: "Empty string in values",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:ResourceTag/environment": []string{""},
				},
			},
			context: &RequestContext{
				ResourceTags: map[string]string{
					"environment": "",
				},
			},
			expected: true,
		},
		{
			name: "Combined date and numeric conditions",
			conditions: &types.Condition{
				"DateGreaterThan": {
					"aws:CurrentTime": []string{"2023-01-01T00:00:00Z"},
				},
				"NumericLessThan": {
					"aws:MultiFactorAuthAge": []string{"300"},
				},
			},
			context: &RequestContext{
				CurrentTime: time.Now(),
				RequestParameters: map[string]string{
					"MultiFactorAuthAge": "200",
				},
			},
			expected: true,
		},
		{
			name: "StringNotEquals OrgId",
			conditions: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalOrgID": []string{"o-1234567"},
				},
			},
			context: &RequestContext{
				PrincipalOrgId: "o-7654321",
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluateConditions(tc.conditions, tc.context)
			if result != tc.expected {
				t.Errorf("Expected %v, but got %v for conditions %v and context %v", tc.expected, result, tc.conditions, tc.context)
			}
		})
	}
}
