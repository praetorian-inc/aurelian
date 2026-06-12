package types

import "testing"

// TestBuildResourceARN locks the ARN grammar for CloudControl name/ID-identified
// resource types. CloudControl's ListResources returns a bare name or ID as the
// identifier for these types (not an ARN), and the resulting ImpactedResourceID
// on a finding must be a well-formed ARN. Each expected value below was validated
// against the live resource's real ARN (AWS describe-* / the resource's own ARN
// attribute). region/account are synthetic here; only the grammar is asserted.
func TestBuildResourceARN(t *testing.T) {
	const region = "us-east-1"
	const account = "123456789012"

	albARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123"

	cases := []struct {
		name       string
		identifier string
		typeName   string
		want       string
	}{
		// --- property-based types fixed in this change (bare name/ID identifier) ---
		{"eks", "my-cluster", "AWS::EKS::Cluster", "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster"},
		{"transfer", "s-abc123", "AWS::Transfer::Server", "arn:aws:transfer:us-east-1:123456789012:server/s-abc123"},
		{"cloudfront", "EDIST123", "AWS::CloudFront::Distribution", "arn:aws:cloudfront::123456789012:distribution/EDIST123"},
		{"appsync", "api123", "AWS::AppSync::GraphQLApi", "arn:aws:appsync:us-east-1:123456789012:apis/api123"},
		{"apigw-rest", "rest123", "AWS::ApiGateway::RestApi", "arn:aws:apigateway:us-east-1::/restapis/rest123"},
		{"apigw-v2", "http123", "AWS::ApiGatewayV2::Api", "arn:aws:apigateway:us-east-1::/apis/http123"},
		{"cognito", "us-east-1_ABC", "AWS::Cognito::UserPool", "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_ABC"},
		{"rds", "mydb", "AWS::RDS::DBInstance", "arn:aws:rds:us-east-1:123456789012:db:mydb"},

		// --- regression locks for existing/unchanged behavior ---
		{"ec2-instance", "i-0abc", "AWS::EC2::Instance", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc"},
		// Types whose CloudControl identifier is already an ARN must pass through unchanged.
		{"elbv2-arn-passthrough", albARN, "AWS::ElasticLoadBalancingV2::LoadBalancer", albARN},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildResourceARN(tc.identifier, tc.typeName, region, account).String()
			if got != tc.want {
				t.Errorf("BuildResourceARN(%q, %q)\n  got:  %s\n  want: %s", tc.identifier, tc.typeName, got, tc.want)
			}
		})
	}
}
