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
		expected   *ConditionEval
	}{
		{
			name: "StringEquals match",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:username": {"test-user"},
				},
			},
			context: &RequestContext{
				PrincipalUsername: "test-user",
			},

			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "StringEquals no match",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:username": {"test-user"},
				},
			},
			context: &RequestContext{
				PrincipalUsername: "another-user",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "IpAddress match",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"192.168.1.1/24"},
				},
			},
			context: &RequestContext{
				SourceIP: "192.168.1.5",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "IpAddress no match",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"192.168.1.1/24"},
				},
			},
			context: &RequestContext{
				SourceIP: "10.0.0.1",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
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
				SourceIP: "203.0.113.45",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "NotIpAddress with IPv6",
			conditions: &types.Condition{
				"NotIpAddress": {
					"aws:SourceIp": []string{"2001:DB8:1234:5678::/64"},
				},
			},
			context: &RequestContext{
				SourceIP: "203.0.113.45",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "String case insensitive with multiple values",
			conditions: &types.Condition{
				"StringEqualsIgnoreCase": {
					"aws:PrincipalTag/Department": []string{"HR", "Finance"},
				},
			},
			context: &RequestContext{
				PrincipalTags: map[string]string{
					"Department": "hr",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
				SecureTransport:    Bool(true),
				PrincipalArn:       "arn:aws:iam::123456789012:user/test",
				MultiFactorAuthAge: 1800,
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
				PrincipalOrgPaths: []string{"o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/ou-ab12-22222222"},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
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
				CurrentTime:        time.Now(),
				MultiFactorAuthAge: 200,
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "StringNotEquals OrgId",
			conditions: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalOrgID": []string{"o-1234567"},
				},
			},
			context: &RequestContext{
				PrincipalOrgID: "o-7654321",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "Critical condition aws:SourceArn missing",
			conditions: &types.Condition{
				"ArnLike": types.ConditionStatement{
					"aws:SourceArn": []string{"arn:aws:s3:::example-bucket"},
				},
			},
			context: &RequestContext{
				// No source ARN provided in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:SourceArn"},
			},
		},
		{
			name: "Critical condition aws:SourceVpc missing",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"aws:SourceVpc": []string{"vpc-12345678"},
				},
			},
			context: &RequestContext{
				// No SourceVpc provided in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:SourceVpc"},
			},
		},
		{
			name: "Critical condition aws:PrincipalOrgID missing",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"aws:PrincipalOrgID": []string{"o-exampleorgid"},
				},
			},
			context: &RequestContext{
				// No PrincipalOrgId provided in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:PrincipalOrgID"},
			},
		},
		{
			name: "Multiple critical conditions missing",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"aws:SourceAccount": []string{"123456789012"},
					"aws:SourceVpc":     []string{"vpc-12345678"},
				},
			},
			context: &RequestContext{
				// No SourceAccount or SourceVpc in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:SourceAccount", "aws:SourceVpc"},
			},
		},
		{
			name: "Critical condition aws:CalledVia missing",
			conditions: &types.Condition{
				"ForAnyValue:StringEquals": types.ConditionStatement{
					"aws:CalledVia": []string{"cloudformation.amazonaws.com"},
				},
			},
			context: &RequestContext{
				// No CalledVia information in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:CalledVia"},
			},
		},
		{
			name: "Critical condition with IfExists should not be inconclusive",
			conditions: &types.Condition{
				"StringEqualsIfExists": types.ConditionStatement{
					"aws:SourceVpc": []string{"vpc-12345678"},
				},
			},
			context: &RequestContext{
				// No SourceVpc in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
				// No missing keys because IfExists handles this case
			},
		},
		{
			name: "Non-critical condition missing should not be inconclusive",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"s3:prefix": []string{"documents/"},
				},
			},
			context: &RequestContext{
				// No s3:prefix in context
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"s3:prefix"},
			},
		},
		{
			name: "Mixed critical and non-critical conditions with all critical missing",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"aws:SourceVpc":    []string{"vpc-12345678"},
					"s3:prefix":        []string{"documents/"},
					"ec2:InstanceType": []string{"t2.micro"},
				},
			},
			context: &RequestContext{
				// Only s3:prefix and ec2:InstanceType present
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
				RequestParameters: map[string]string{
					"s3:prefix":        "documents/",
					"ec2:InstanceType": "t2.micro",
				},
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:SourceVpc"},
			},
		},
		{
			name: "Critical condition aws:SourceArn present in API Gateway pattern",
			conditions: &types.Condition{
				"ArnLike": types.ConditionStatement{
					"AWS:SourceArn": []string{"arn:aws:execute-api:us-west-2:123456789012:*/*/PUT/asset"},
				},
			},
			context: &RequestContext{
				SourceArn:    "arn:aws:execute-api:us-west-2:123456789012:7054m6vvp4/prod/PUT/asset",
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
				// No missing keys
			},
		},
		{
			name: "aws:ViaAWSService condition missing should be inconclusive",
			conditions: &types.Condition{
				"Bool": types.ConditionStatement{
					"aws:ViaAWSService": []string{"true"},
				},
			},
			context: &RequestContext{
				// No ViaAWSService flag
				PrincipalArn: "arn:aws:iam::123456789012:role/example-role",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:ViaAWSService"},
			},
		},
		{
			name: "aws:SourceAccount pattern from lambda triggers",
			conditions: &types.Condition{
				"StringEquals": types.ConditionStatement{
					"aws:SourceAccount": []string{"123456789012"},
				},
			},
			context: &RequestContext{
				// No SourceAccount in context
				PrincipalArn: "arn:aws:service-role:lambda.amazonaws.com",
			},
			expected: &ConditionEval{
				Result:      ConditionInconclusive,
				MissingKeys: []string{"aws:SourceAccount"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			//tc.context.PopulateDefaultRequestConditionKeys("arn:aws:iam::123456789012:role/test-role")
			result := evaluateConditions(tc.conditions, tc.context)
			if result.Result != tc.expected.Result {
				t.Errorf("Expected %v, but got %v for conditions %v and context %v", tc.expected, result, tc.conditions, tc.context)
			}
		})
	}
}
