package enumeration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveARNTarget_ServiceMappedRegionKept(t *testing.T) {
	cc := &CloudControlEnumerator{}

	region, typ, id, err := cc.resolveARNTarget("arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0")
	require.NoError(t, err)
	require.Equal(t, "us-west-2", region)
	require.Equal(t, "AWS::EC2::Instance", typ)
	require.Equal(t, "i-1234567890abcdef0", id)
}

func TestResolveARNTarget_GlobalTypeForcesUsEast1(t *testing.T) {
	cc := &CloudControlEnumerator{}

	region, typ, _, err := cc.resolveARNTarget("arn:aws:iam::123456789012:role/Admin")
	require.NoError(t, err)
	require.Equal(t, "AWS::IAM::Role", typ)
	require.Equal(t, "us-east-1", region)
}

func TestResolveARNTarget_UnknownServiceFails(t *testing.T) {
	cc := &CloudControlEnumerator{}

	_, _, _, err := cc.resolveARNTarget("arn:aws:definitelynotreal:us-east-1:123456789012:thing/id")
	require.Error(t, err)
}

func TestResolveARNTarget_InvalidARNFails(t *testing.T) {
	cc := &CloudControlEnumerator{}

	_, _, _, err := cc.resolveARNTarget("not-an-arn")
	require.Error(t, err)
}

// TestResolveARNTarget_CloudFrontDistribution covers LAB-7805. A CloudFront
// distribution ARN must resolve to the Cloud Control type, force the global
// region, and hand Cloud Control the bare distribution ID — GetResource rejects
// the "distribution/" path prefix that the ARN carries.
func TestResolveARNTarget_CloudFrontDistribution(t *testing.T) {
	cc := &CloudControlEnumerator{}

	region, typ, id, err := cc.resolveARNTarget("arn:aws:cloudfront::123456789012:distribution/E124R3VALIF56C")
	require.NoError(t, err)
	require.Equal(t, "us-east-1", region, "CloudFront is global; the ARN carries no region")
	require.Equal(t, "AWS::CloudFront::Distribution", typ)
	require.Equal(t, "E124R3VALIF56C", id)
}

// TestResolveARNTarget_MeasuredFailureSet locks by-ARN resolution for every ARN
// service in LAB-7805's production measurement (34,941 failed
// aurelian-aws-public-resources jobs over 7 days across 35 tenants, all raising
// `unsupported arn service "<svc>"`).
//
// Each case asserts the two things the by-ARN path has to get right: the
// Cloud Control type, and the identifier grammar GetResource accepts. The
// identifier expectations were verified against live resources — some types
// take a bare name/ID and reject the ARN, others take only the ARN.
func TestResolveARNTarget_MeasuredFailureSet(t *testing.T) {
	cc := &CloudControlEnumerator{}

	cases := []struct {
		name       string
		arn        string
		wantType   string
		wantRegion string
		wantID     string
	}{
		{
			name:       "elasticloadbalancing/alb",
			arn:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/9b78a7940dbbae4b",
			wantType:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
			wantRegion: "us-east-1",
			wantID:     "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/9b78a7940dbbae4b",
		},
		{
			name:       "elasticloadbalancing/nlb",
			arn:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
			wantType:   "AWS::ElasticLoadBalancingV2::LoadBalancer",
			wantRegion: "us-east-1",
			wantID:     "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/my-nlb/abc123",
		},
		{
			// Classic ELB has no scheme segment. It must not be swallowed by the
			// v2 rules, and it routes to the native ClassicELBEnumerator.
			name:       "elasticloadbalancing/classic",
			arn:        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/my-classic-elb",
			wantType:   "AWS::ElasticLoadBalancing::LoadBalancer",
			wantRegion: "us-east-1",
			wantID:     "loadbalancer/my-classic-elb",
		},
		{
			name:       "cloudfront",
			arn:        "arn:aws:cloudfront::123456789012:distribution/E124R3VALIF56C",
			wantType:   "AWS::CloudFront::Distribution",
			wantRegion: "us-east-1",
			wantID:     "E124R3VALIF56C",
		},
		{
			name:       "efs",
			arn:        "arn:aws:efs:us-east-1:123456789012:file-system/fs-07481a2de3a2efe6c",
			wantType:   "AWS::EFS::FileSystem",
			wantRegion: "us-east-1",
			wantID:     "fs-07481a2de3a2efe6c",
		},
		{
			// The historical service segment on live EFS ARNs. It resolved before
			// this change, but handed Cloud Control "file-system/fs-..." and failed
			// one step later with an opaque ServiceInternalError.
			name:       "elasticfilesystem",
			arn:        "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-07481a2de3a2efe6c",
			wantType:   "AWS::EFS::FileSystem",
			wantRegion: "us-east-1",
			wantID:     "fs-07481a2de3a2efe6c",
		},
		{
			name:       "eks",
			arn:        "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
			wantType:   "AWS::EKS::Cluster",
			wantRegion: "us-east-1",
			wantID:     "my-cluster",
		},
		{
			name:       "appsync",
			arn:        "arn:aws:appsync:us-east-1:123456789012:apis/cyjhpg63xrdi3edxme2zqgaig4",
			wantType:   "AWS::AppSync::GraphQLApi",
			wantRegion: "us-east-1",
			wantID:     "cyjhpg63xrdi3edxme2zqgaig4",
		},
		{
			name:       "transfer",
			arn:        "arn:aws:transfer:us-east-1:123456789012:server/s-0f45a99798304c08a",
			wantType:   "AWS::Transfer::Server",
			wantRegion: "us-east-1",
			wantID:     "arn:aws:transfer:us-east-1:123456789012:server/s-0f45a99798304c08a",
		},
		{
			name:       "elasticbeanstalk",
			arn:        "arn:aws:elasticbeanstalk:us-east-1:123456789012:environment/my-app/my-env",
			wantType:   "AWS::ElasticBeanstalk::Environment",
			wantRegion: "us-east-1",
			wantID:     "my-env",
		},
		{
			// Global Accelerator ARNs carry no region and its control plane is
			// served only from us-west-2, not the us-east-1 every other global
			// service uses.
			name:       "globalaccelerator",
			arn:        "arn:aws:globalaccelerator::123456789012:accelerator/7bc71d33-8842-495e-9e1e-12aef9848de9",
			wantType:   "AWS::GlobalAccelerator::Accelerator",
			wantRegion: "us-west-2",
			wantID:     "arn:aws:globalaccelerator::123456789012:accelerator/7bc71d33-8842-495e-9e1e-12aef9848de9",
		},
		{
			name:       "redshift",
			arn:        "arn:aws:redshift:us-east-1:123456789012:cluster:my-cluster",
			wantType:   "AWS::Redshift::Cluster",
			wantRegion: "us-east-1",
			wantID:     "my-cluster",
		},
		{
			name:       "apprunner",
			arn:        "arn:aws:apprunner:us-east-1:123456789012:service/my-service/8fe1e10304f44bc8b2d6f1c1b1d3e0a1",
			wantType:   "AWS::AppRunner::Service",
			wantRegion: "us-east-1",
			wantID:     "arn:aws:apprunner:us-east-1:123456789012:service/my-service/8fe1e10304f44bc8b2d6f1c1b1d3e0a1",
		},
		{
			// Not in the measured failure set: an HTTP API ARN resolved, but to
			// the wrong type, so it failed later against the REST handler instead
			// of raising "unsupported arn service".
			name:       "apigateway/v1",
			arn:        "arn:aws:apigateway:us-east-1::/restapis/4kxpfe80a3",
			wantType:   "AWS::ApiGateway::RestApi",
			wantRegion: "us-east-1",
			wantID:     "4kxpfe80a3",
		},
		{
			name:       "apigateway/v2",
			arn:        "arn:aws:apigateway:us-east-1::/apis/2a9umg4khi",
			wantType:   "AWS::ApiGatewayV2::Api",
			wantRegion: "us-east-1",
			wantID:     "2a9umg4khi",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			region, typ, id, err := cc.resolveARNTarget(tc.arn)
			require.NoError(t, err)
			require.Equal(t, tc.wantType, typ, "resource type")
			require.Equal(t, tc.wantRegion, region, "region")
			require.Equal(t, tc.wantID, id, "cloud control identifier")
		})
	}
}
