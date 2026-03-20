package iam

import (
	"testing"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
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
		// NumericEquals match
		{
			name: "NumericEquals match",
			conditions: &types.Condition{
				"NumericEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 3600},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// NumericEquals no match
		{
			name: "NumericEquals no match",
			conditions: &types.Condition{
				"NumericEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 1800},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// NumericNotEquals match
		{
			name: "NumericNotEquals match",
			conditions: &types.Condition{
				"NumericNotEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 1800},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// NumericNotEquals no match
		{
			name: "NumericNotEquals no match",
			conditions: &types.Condition{
				"NumericNotEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 3600},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// NumericGreaterThan match
		{
			name: "NumericGreaterThan match",
			conditions: &types.Condition{
				"NumericGreaterThan": {"aws:MultiFactorAuthAge": {"1800"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 3600},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// NumericGreaterThan no match
		{
			name: "NumericGreaterThan no match",
			conditions: &types.Condition{
				"NumericGreaterThan": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 1800},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// NumericGreaterThanEquals match exact
		{
			name: "NumericGreaterThanEquals match exact",
			conditions: &types.Condition{
				"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 3600},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// NumericGreaterThanEquals no match
		{
			name: "NumericGreaterThanEquals no match",
			conditions: &types.Condition{
				"NumericGreaterThanEquals": {"aws:MultiFactorAuthAge": {"3600"}},
			},
			context:  &RequestContext{MultiFactorAuthAge: 1800},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// DateEquals match
		{
			name: "DateEquals match",
			conditions: &types.Condition{
				"DateEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// DateEquals no match
		{
			name: "DateEquals no match",
			conditions: &types.Condition{
				"DateEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 16, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// DateNotEquals match
		{
			name: "DateNotEquals match",
			conditions: &types.Condition{
				"DateNotEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 16, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// DateNotEquals no match
		{
			name: "DateNotEquals no match",
			conditions: &types.Condition{
				"DateNotEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// DateLessThan match
		{
			name: "DateLessThan match",
			conditions: &types.Condition{
				"DateLessThan": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 14, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// DateLessThan no match
		{
			name: "DateLessThan no match",
			conditions: &types.Condition{
				"DateLessThan": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 16, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// DateLessThanEquals match exact
		{
			name: "DateLessThanEquals match exact",
			conditions: &types.Condition{
				"DateLessThanEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// DateGreaterThanEquals match exact
		{
			name: "DateGreaterThanEquals match exact",
			conditions: &types.Condition{
				"DateGreaterThanEquals": {"aws:CurrentTime": {"2023-06-15T12:00:00Z"}},
			},
			context:  &RequestContext{CurrentTime: time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// ArnNotEquals match - different ARN
		{
			name: "ArnNotEquals match - different ARN",
			conditions: &types.Condition{
				"ArnNotEquals": {
					"aws:PrincipalArn": {"arn:aws:iam::111111111111:role/blocked-role"},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/allowed-role",
			},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// ArnNotEquals no match - same ARN
		{
			name: "ArnNotEquals no match - same ARN",
			conditions: &types.Condition{
				"ArnNotEquals": {
					"aws:PrincipalArn": {"arn:aws:iam::123456789012:role/blocked-role"},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/blocked-role",
			},
			expected: &ConditionEval{Result: ConditionFailed},
		},
		// ArnNotLike match - no wildcard match
		{
			name: "ArnNotLike match - no wildcard match",
			conditions: &types.Condition{
				"ArnNotLike": {
					"aws:PrincipalArn": {"arn:aws:iam::*:role/blocked-*"},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/allowed-role",
			},
			expected: &ConditionEval{Result: ConditionMatched},
		},
		// ArnNotLike no match - wildcard matches
		{
			name: "ArnNotLike no match - wildcard matches",
			conditions: &types.Condition{
				"ArnNotLike": {
					"aws:PrincipalArn": {"arn:aws:iam::*:role/blocked-*"},
				},
			},
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/blocked-admin",
			},
			expected: &ConditionEval{Result: ConditionFailed},
		},
	}

	// Add Lambda Function URL and S3 public access condition tests
	lambdaS3TestCases := []struct {
		name       string
		conditions *types.Condition
		context    *RequestContext
		expected   *ConditionEval
	}{
		{
			name: "Lambda FunctionUrlAuthType NONE with key present - should match",
			conditions: &types.Condition{
				"StringEquals": {
					"lambda:FunctionUrlAuthType": {"NONE"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"lambda:FunctionUrlAuthType": "NONE",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "Lambda FunctionUrlAuthType NONE with key missing - should fail",
			conditions: &types.Condition{
				"StringEquals": {
					"lambda:FunctionUrlAuthType": {"NONE"},
				},
			},
			context: &RequestContext{}, // Missing the key
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"lambda:FunctionUrlAuthType"},
			},
		},
		{
			name: "Lambda FunctionUrlAuthType AWS_IAM with NONE value - should fail match",
			conditions: &types.Condition{
				"StringEquals": {
					"lambda:FunctionUrlAuthType": {"AWS_IAM"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"lambda:FunctionUrlAuthType": "NONE",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "S3 SecureTransport true with key present - should match",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": {"true"},
				},
			},
			context: &RequestContext{
				SecureTransport: Bool(true),
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "S3 SecureTransport true with key missing - should fail",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": {"true"},
				},
			},
			context: &RequestContext{}, // Missing SecureTransport
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"aws:SecureTransport"},
			},
		},
		{
			name: "S3 PrincipalType not Anonymous with AssumedRole - should match",
			conditions: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalType": {"Anonymous"},
				},
			},
			context: &RequestContext{
				PrincipalType: "AssumedRole",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "S3 PrincipalType not Anonymous with Anonymous - should fail match",
			conditions: &types.Condition{
				"StringNotEquals": {
					"aws:PrincipalType": {"Anonymous"},
				},
			},
			context: &RequestContext{
				PrincipalType: "Anonymous",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "Complex S3 public policy - SecureTransport true AND PrincipalType not Anonymous",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": {"true"},
				},
				"StringNotEquals": {
					"aws:PrincipalType": {"Anonymous"},
				},
			},
			context: &RequestContext{
				SecureTransport: Bool(true),
				PrincipalType:   "AssumedRole",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "Complex S3 public policy - SecureTransport missing, PrincipalType present",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": {"true"},
				},
				"StringNotEquals": {
					"aws:PrincipalType": {"Anonymous"},
				},
			},
			context: &RequestContext{
				PrincipalType: "AssumedRole", // Only one condition satisfied
			},
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"aws:SecureTransport"},
			},
		},
	}
	testCases = append(testCases, lambdaS3TestCases...)

	// Add GitHub Actions specific condition tests
	gitHubActionsTestCases := []struct {
		name       string
		conditions *types.Condition
		context    *RequestContext
		expected   *ConditionEval
	}{
		{
			name: "GitHub Actions subject equals specific repo and branch",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions subject does not match - different branch",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/heads/develop",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "GitHub Actions subject with wildcard matching any context",
			conditions: &types.Condition{
				"StringLike": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:*"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:environment:production",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions subject with wildcard not matching different repo",
			conditions: &types.Condition{
				"StringLike": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:*"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:different-org/other-repo:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "GitHub Actions environment-specific access",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:environment:production"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:environment:production",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions environment mismatch",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:environment:production"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:environment:staging",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "GitHub Actions pull request context",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:pull_request"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:pull_request",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions subject missing should fail",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
					// Missing subject key
				},
			},
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"token.actions.githubusercontent.com:sub"},
			},
		},
		{
			name: "GitHub Actions audience missing should fail",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:praetorian-inc/nebula:ref:refs/heads/main",
					// Missing audience key
				},
			},
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"token.actions.githubusercontent.com:aud"},
			},
		},
		{
			name: "GitHub Actions multiple subject patterns - any should match",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub": {
						"repo:praetorian-inc/nebula:ref:refs/heads/main",
						"repo:praetorian-inc/nebula:environment:production",
					},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:environment:production",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			// StringNotEquals uses AND logic across all keys. The aud key value
			// "sts.amazonaws.com" EQUALS the condition value, so StringNotEquals
			// FAILS for that key. Since all conditions must pass (AND), overall result is FAILED.
			name: "GitHub Actions StringNotEquals - fails because aud matches condition value",
			conditions: &types.Condition{
				"StringNotEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:blocked-org/blocked-repo:*"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "GitHub Actions StringNotEquals - should fail for matching subject",
			conditions: &types.Condition{
				"StringNotEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:*"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "GitHub Actions with ForAnyValue modifier",
			conditions: &types.Condition{
				"ForAnyValue:StringLike": {
					"token.actions.githubusercontent.com:sub": {
						"repo:*/nebula:*",
						"repo:praetorian-inc/*:environment:production",
					},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions multi-level repository name",
			conditions: &types.Condition{
				"StringEquals": {
					"token.actions.githubusercontent.com:sub":   {"repo:org/sub-org/repo-name:ref:refs/heads/main"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:org/sub-org/repo-name:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "GitHub Actions tag-based deployment",
			conditions: &types.Condition{
				"StringLike": {
					"token.actions.githubusercontent.com:sub":   {"repo:praetorian-inc/nebula:ref:refs/tags/v*"},
					"token.actions.githubusercontent.com:aud": {"sts.amazonaws.com"},
				},
			},
			context: &RequestContext{
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub":   "repo:praetorian-inc/nebula:ref:refs/tags/v1.2.3",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
	}
	testCases = append(testCases, gitHubActionsTestCases...)

	// Test 5: IP edge cases
	ipEdgeCases := []struct {
		name       string
		conditions *types.Condition
		context    *RequestContext
		expected   *ConditionEval
	}{
		{
			name: "IpAddress single IP match (not CIDR)",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"10.0.0.1"},
				},
			},
			context: &RequestContext{
				SourceIP: "10.0.0.1",
			},
			expected: &ConditionEval{
				Result: ConditionMatched,
			},
		},
		{
			name: "IpAddress single IP no match",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"10.0.0.1"},
				},
			},
			context: &RequestContext{
				SourceIP: "10.0.0.2",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "IpAddress invalid actual IP returns false",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"10.0.0.0/8"},
				},
			},
			context: &RequestContext{
				SourceIP: "not-an-ip",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
		{
			name: "IpAddress invalid value in condition",
			conditions: &types.Condition{
				"IpAddress": {
					"aws:SourceIp": {"invalid-cidr"},
				},
			},
			context: &RequestContext{
				SourceIP: "10.0.0.1",
			},
			expected: &ConditionEval{
				Result: ConditionFailed,
			},
		},
	}
	testCases = append(testCases, ipEdgeCases...)

	// Test 6: Bool condition with nil *bool
	boolNilCases := []struct {
		name       string
		conditions *types.Condition
		context    *RequestContext
		expected   *ConditionEval
	}{
		{
			name: "Bool condition with nil SecureTransport pointer",
			conditions: &types.Condition{
				"Bool": {
					"aws:SecureTransport": {"true"},
				},
			},
			context: &RequestContext{
				SecureTransport: nil,
			},
			expected: &ConditionEval{
				Result:      ConditionFailed,
				MissingKeys: []string{"aws:SecureTransport"},
			},
		},
	}
	testCases = append(testCases, boolNilCases...)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			//tc.context.PopulateDefaultRequestConditionKeys("arn:aws:iam::123456789012:role/test-role")
			result := EvaluateConditions(tc.conditions, tc.context)
			if result.Result != tc.expected.Result {
				t.Errorf("Expected %v, but got %v for conditions %v and context %v", tc.expected, result, tc.conditions, tc.context)
			}
		})
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantValue float64
		wantOk    bool
	}{
		{
			name:      "float64 value",
			input:     float64(3.14),
			wantValue: 3.14,
			wantOk:    true,
		},
		{
			name:      "float32 value",
			input:     float32(2.5),
			wantValue: float64(float32(2.5)),
			wantOk:    true,
		},
		{
			name:      "int value",
			input:     42,
			wantValue: 42.0,
			wantOk:    true,
		},
		{
			name:      "int64 value",
			input:     int64(9999999999),
			wantValue: 9999999999.0,
			wantOk:    true,
		},
		{
			name:      "valid string",
			input:     "123.456",
			wantValue: 123.456,
			wantOk:    true,
		},
		{
			name:      "invalid string",
			input:     "not-a-number",
			wantValue: 0,
			wantOk:    false,
		},
		{
			name:      "unsupported type bool",
			input:     true,
			wantValue: 0,
			wantOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := toFloat64(tt.input)
			assert.Equal(t, tt.wantOk, ok, "toFloat64(%v) ok", tt.input)
			if tt.wantOk {
				assert.InDelta(t, tt.wantValue, got, 0.001, "toFloat64(%v) value", tt.input)
			}
		})
	}
}

func TestFindContextKeyValue(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		ctx        *RequestContext
		wantExists bool
		wantValue  interface{}
	}{
		{
			name:       "nil context returns false",
			key:        "aws:PrincipalArn",
			ctx:        nil,
			wantExists: false,
			wantValue:  nil,
		},
		{
			name: "ec2:sourceinstancearn returns value",
			key:  "ec2:SourceInstanceArn",
			ctx: &RequestContext{
				ec2_SourceInstanceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef",
			},
			wantExists: true,
			wantValue:  "arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef",
		},
		{
			name: "glue:roleassumedby returns value",
			key:  "glue:roleassumedby",
			ctx: &RequestContext{
				glue_RoleAssumedBy: "arn:aws:iam::123456789012:role/glue-role",
			},
			wantExists: true,
			wantValue:  "arn:aws:iam::123456789012:role/glue-role",
		},
		{
			name: "lambda:sourcefunctionarn returns value",
			key:  "lambda:sourcefunctionarn",
			ctx: &RequestContext{
				lambda_SourceFunctionArn: "arn:aws:lambda:us-east-1:123456789012:function/my-func",
			},
			wantExists: true,
			wantValue:  "arn:aws:lambda:us-east-1:123456789012:function/my-func",
		},
		{
			name: "ssm:sourceinstancearn returns value",
			key:  "ssm:sourceinstancearn",
			ctx: &RequestContext{
				ssm_SourceInstanceArn: "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890",
			},
			wantExists: true,
			wantValue:  "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890",
		},
		{
			name: "identitystore:userid returns value",
			key:  "identitystore:userid",
			ctx: &RequestContext{
				identitystore_UserId: "user-id-12345",
			},
			wantExists: true,
			wantValue:  "user-id-12345",
		},
		{
			name: "aws:tagkeys aggregation from all tag maps",
			key:  "aws:TagKeys",
			ctx: &RequestContext{
				PrincipalTags: map[string]string{"PTag": "pval"},
				ResourceTags:  map[string]string{"RTag": "rval"},
				RequestTags:   map[string]string{"ReqTag": "reqval"},
			},
			wantExists: true,
			// We only check exists and length, value is []string with keys from all maps
		},
		{
			name: "aws:tagkeys with empty tag maps",
			key:  "aws:TagKeys",
			ctx: &RequestContext{
				PrincipalTags: map[string]string{},
				ResourceTags:  map[string]string{},
				RequestTags:   map[string]string{},
			},
			wantExists: false,
		},
		{
			name: "RequestParameters fallback",
			key:  "custom:SomeKey",
			ctx: &RequestContext{
				RequestParameters: map[string]string{
					"custom:SomeKey": "custom-value",
				},
			},
			wantExists: true,
			wantValue:  "custom-value",
		},
		{
			name: "nil tag maps for resource tag lookup",
			key:  "aws:ResourceTag/env",
			ctx: &RequestContext{
				ResourceTags: nil,
			},
			wantExists: false,
			wantValue:  nil,
		},
		{
			name: "nil tag maps for principal tag lookup",
			key:  "aws:PrincipalTag/team",
			ctx: &RequestContext{
				PrincipalTags: nil,
			},
			wantExists: false,
			wantValue:  nil,
		},
		{
			name: "nil tag maps for request tag lookup",
			key:  "aws:RequestTag/project",
			ctx: &RequestContext{
				RequestTags: nil,
			},
			wantExists: false,
			wantValue:  nil,
		},
		{
			name: "unknown key with nil RequestParameters",
			key:  "unknown:key",
			ctx: &RequestContext{
				RequestParameters: nil,
			},
			wantExists: false,
			wantValue:  nil,
		},
		// Role Session Properties
		{
			name: "aws:rolesessionname returns value",
			key:  "aws:RoleSessionName",
			ctx: &RequestContext{
				RoleSessionName: "my-session",
			},
			wantExists: true,
			wantValue:  "my-session",
		},
		{
			name:       "aws:rolesessionname empty returns false",
			key:        "aws:RoleSessionName",
			ctx:        &RequestContext{},
			wantExists: false,
			wantValue:  "",
		},
		{
			name: "aws:federatedprovider returns value",
			key:  "aws:FederatedProvider",
			ctx: &RequestContext{
				FederatedProvider: "cognito-identity.amazonaws.com",
			},
			wantExists: true,
			wantValue:  "cognito-identity.amazonaws.com",
		},
		{
			name: "aws:tokenissuetime returns value",
			key:  "aws:TokenIssueTime",
			ctx: &RequestContext{
				TokenIssueTime: time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC),
			},
			wantExists: true,
			wantValue:  time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			name:       "aws:tokenissuetime zero returns false",
			key:        "aws:TokenIssueTime",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:sourceidentity returns value",
			key:  "aws:SourceIdentity",
			ctx: &RequestContext{
				SourceIdentity: "my-identity",
			},
			wantExists: true,
			wantValue:  "my-identity",
		},
		{
			name: "aws:assumedroot returns value when set",
			key:  "aws:AssumedRoot",
			ctx: &RequestContext{
				AssumedRoot: Bool(true),
			},
			wantExists: true,
		},
		{
			name:       "aws:assumedroot returns false when nil",
			key:        "aws:AssumedRoot",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:multifactorauthpresent returns value",
			key:  "aws:MultiFactorAuthPresent",
			ctx: &RequestContext{
				MultiFactorAuthPresent: Bool(true),
			},
			wantExists: true,
		},
		{
			name: "aws:ec2instancesourcevpc returns value",
			key:  "aws:Ec2InstanceSourceVpc",
			ctx: &RequestContext{
				Ec2InstanceSourceVpc: "vpc-abc123",
			},
			wantExists: true,
			wantValue:  "vpc-abc123",
		},
		{
			name: "aws:ec2instancesourceprivateipv4 returns value",
			key:  "aws:Ec2InstanceSourcePrivateIPv4",
			ctx: &RequestContext{
				Ec2InstanceSourcePrivateIPv4: "10.0.0.5",
			},
			wantExists: true,
			wantValue:  "10.0.0.5",
		},
		{
			name: "ec2:roledelivery returns value",
			key:  "ec2:RoleDelivery",
			ctx: &RequestContext{
				ec2_RoleDelivery: "2.0",
			},
			wantExists: true,
			wantValue:  "2.0",
		},
		// Network Properties
		{
			name: "aws:sourcevpc returns value",
			key:  "aws:SourceVpc",
			ctx: &RequestContext{
				SourceVPC: "vpc-123",
			},
			wantExists: true,
			wantValue:  "vpc-123",
		},
		{
			name: "aws:sourcevpce returns value",
			key:  "aws:SourceVpce",
			ctx: &RequestContext{
				SourceVPCE: "vpce-abc",
			},
			wantExists: true,
			wantValue:  "vpce-abc",
		},
		{
			name: "aws:vpcsourceip returns value",
			key:  "aws:VpcSourceIp",
			ctx: &RequestContext{
				VPCSourceIP: "10.0.0.1",
			},
			wantExists: true,
			wantValue:  "10.0.0.1",
		},
		// Resource Properties
		{
			name: "aws:resourceaccount returns value",
			key:  "aws:ResourceAccount",
			ctx: &RequestContext{
				ResourceAccount: "111122223333",
			},
			wantExists: true,
			wantValue:  "111122223333",
		},
		{
			name: "aws:resourceorgid returns value",
			key:  "aws:ResourceOrgID",
			ctx: &RequestContext{
				ResourceOrgID: "o-abc123",
			},
			wantExists: true,
			wantValue:  "o-abc123",
		},
		{
			name: "aws:resourceorgpaths returns value",
			key:  "aws:ResourceOrgPaths",
			ctx: &RequestContext{
				ResourceOrgPaths: []string{"o-abc123/r-root/ou-abc"},
			},
			wantExists: true,
		},
		{
			name:       "aws:resourceorgpaths empty returns false",
			key:        "aws:ResourceOrgPaths",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		// Request Properties
		{
			name: "aws:requestedregion returns value",
			key:  "aws:RequestedRegion",
			ctx: &RequestContext{
				RequestedRegion: "us-west-2",
			},
			wantExists: true,
			wantValue:  "us-west-2",
		},
		{
			name: "aws:useragent returns value",
			key:  "aws:UserAgent",
			ctx: &RequestContext{
				UserAgent: "aws-cli/2.0",
			},
			wantExists: true,
			wantValue:  "aws-cli/2.0",
		},
		{
			name: "aws:referer returns value",
			key:  "aws:Referer",
			ctx: &RequestContext{
				Referer: "https://console.aws.amazon.com",
			},
			wantExists: true,
			wantValue:  "https://console.aws.amazon.com",
		},
		// Cross-service Properties
		{
			name: "aws:viaawsservice returns value when set",
			key:  "aws:ViaAWSService",
			ctx: &RequestContext{
				ViaAWSService: Bool(true),
			},
			wantExists: true,
		},
		{
			name:       "aws:viaawsservice returns false when nil",
			key:        "aws:ViaAWSService",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:calledvia returns value",
			key:  "aws:CalledVia",
			ctx: &RequestContext{
				CalledVia: []string{"cloudformation.amazonaws.com", "lambda.amazonaws.com"},
			},
			wantExists: true,
		},
		{
			name:       "aws:calledvia empty returns false",
			key:        "aws:CalledVia",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:calledviafirst returns first element",
			key:  "aws:CalledViaFirst",
			ctx: &RequestContext{
				CalledVia: []string{"cloudformation.amazonaws.com", "lambda.amazonaws.com"},
			},
			wantExists: true,
			wantValue:  "cloudformation.amazonaws.com",
		},
		{
			name:       "aws:calledviafirst empty calledvia returns false",
			key:        "aws:CalledViaFirst",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:calledvialast returns last element",
			key:  "aws:CalledViaLast",
			ctx: &RequestContext{
				CalledVia: []string{"cloudformation.amazonaws.com", "lambda.amazonaws.com"},
			},
			wantExists: true,
			wantValue:  "lambda.amazonaws.com",
		},
		{
			name:       "aws:calledvialast empty calledvia returns false",
			key:        "aws:CalledViaLast",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		{
			name: "aws:sourcearn returns value",
			key:  "aws:SourceArn",
			ctx: &RequestContext{
				SourceArn: "arn:aws:s3:::my-bucket",
			},
			wantExists: true,
			wantValue:  "arn:aws:s3:::my-bucket",
		},
		{
			name: "aws:sourceaccount returns value",
			key:  "aws:SourceAccount",
			ctx: &RequestContext{
				SourceAccount: "111122223333",
			},
			wantExists: true,
			wantValue:  "111122223333",
		},
		{
			name: "aws:sourceowner returns value",
			key:  "aws:SourceOwner",
			ctx: &RequestContext{
				SourceOwner: "111122223333",
			},
			wantExists: true,
			wantValue:  "111122223333",
		},
		{
			name: "aws:sourceorgid returns value",
			key:  "aws:SourceOrgID",
			ctx: &RequestContext{
				SourceOrgID: "o-abc123",
			},
			wantExists: true,
			wantValue:  "o-abc123",
		},
		{
			name: "aws:sourceorgpaths returns value",
			key:  "aws:SourceOrgPaths",
			ctx: &RequestContext{
				SourceOrgPaths: []string{"o-abc/r-root/ou-123"},
			},
			wantExists: true,
		},
		{
			name:       "aws:sourceorgpaths empty returns false",
			key:        "aws:SourceOrgPaths",
			ctx:        &RequestContext{},
			wantExists: false,
		},
		// Case-insensitive RequestParameters fallback
		{
			name: "RequestParameters case-insensitive fallback",
			key:  "Custom:SomeKey",
			ctx: &RequestContext{
				RequestParameters: map[string]string{
					"custom:somekey": "found-value",
				},
			},
			wantExists: true,
			wantValue:  "found-value",
		},
		{
			name: "glue:credentialissuingservice returns value",
			key:  "glue:CredentialIssuingService",
			ctx: &RequestContext{
				glue_CredentialIssuingService: "glue.amazonaws.com",
			},
			wantExists: true,
			wantValue:  "glue.amazonaws.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists, value := findContextKeyValue(tt.key, tt.ctx)
			assert.Equal(t, tt.wantExists, exists, "findContextKeyValue(%q) exists", tt.key)
			if tt.key == "aws:TagKeys" && tt.wantExists {
				// For TagKeys, verify we get a slice with the right number of keys
				keys, ok := value.([]string)
				assert.True(t, ok, "expected []string for TagKeys")
				assert.Equal(t, 3, len(keys), "expected 3 tag keys from all maps")
			} else if tt.wantValue != nil {
				assert.Equal(t, tt.wantValue, value, "findContextKeyValue(%q) value", tt.key)
			}
		})
	}
}

func TestEvaluateSetCondition_MapAndEmptyActual(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		key      string
		values   []string
		ctx      *RequestContext
		want     bool
	}{
		{
			name:     "ForAnyValue with map[string]string (RequestTags)",
			operator: "ForAnyValue:StringEquals",
			key:      "aws:TagKeys",
			values:   []string{"Environment"},
			ctx: &RequestContext{
				RequestTags: map[string]string{
					"Environment": "prod",
					"CostCenter":  "123",
				},
			},
			want: true,
		},
		{
			name:     "ForAllValues with empty actual values returns true (vacuously)",
			operator: "ForAllValues:StringEquals",
			key:      "aws:TagKeys",
			values:   []string{"Environment"},
			ctx: &RequestContext{
				PrincipalTags: map[string]string{},
				ResourceTags:  map[string]string{},
				RequestTags:   map[string]string{},
			},
			want: true, // empty actual set for ForAllValues vacuously returns true
		},
		{
			name:     "ForAnyValue with map[string]string no match",
			operator: "ForAnyValue:StringEquals",
			key:      "aws:TagKeys",
			values:   []string{"NonExistentKey"},
			ctx: &RequestContext{
				RequestTags: map[string]string{
					"Environment": "prod",
				},
			},
			want: false,
		},
		{
			name:     "evaluateSetCondition default type returns false",
			operator: "ForAnyValue:StringEquals",
			key:      "aws:MultiFactorAuthAge",
			values:   []string{"3600"},
			ctx: &RequestContext{
				MultiFactorAuthAge: 3600,
			},
			want: false, // int is not []string, map[string]string, or string
		},
		{
			name:     "ForAnyValue with nil actual returns false",
			operator: "ForAnyValue:StringEquals",
			key:      "aws:CalledVia",
			values:   []string{"something"},
			ctx:      &RequestContext{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateSetCondition(tt.operator, tt.key, tt.values, tt.ctx)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluateBoolCondition_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		actual interface{}
		want   bool
	}{
		{
			name:   "nil *bool returns false",
			values: []string{"true"},
			actual: (*bool)(nil),
			want:   false,
		},
		{
			name:   "raw bool true matches true",
			values: []string{"true"},
			actual: true,
			want:   true,
		},
		{
			name:   "raw bool false matches false",
			values: []string{"false"},
			actual: false,
			want:   true,
		},
		{
			name:   "raw bool true does not match false",
			values: []string{"false"},
			actual: true,
			want:   false,
		},
		{
			name:   "non-bool type returns false",
			values: []string{"true"},
			actual: "true",
			want:   false,
		},
		{
			name:   "*bool true matches true",
			values: []string{"true"},
			actual: Bool(true),
			want:   true,
		},
		{
			name:   "*bool false matches false",
			values: []string{"false"},
			actual: Bool(false),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateBoolCondition(tt.values, tt.actual)
			assert.Equal(t, tt.want, got)
		})
	}
}
