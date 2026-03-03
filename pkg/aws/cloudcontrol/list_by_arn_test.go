package cloudcontrol

import (
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestResolveARNTarget_ServiceMappedRegionKept(t *testing.T) {
	cc := &CloudControlLister{}

	region, typ, id, err := cc.resolveARNTarget("arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0")
	require.NoError(t, err)
	require.Equal(t, "us-west-2", region)
	require.Equal(t, "AWS::EC2::Instance", typ)
	require.Equal(t, "instance/i-1234567890abcdef0", id)
}

func TestResolveARNTarget_GlobalTypeForcesUsEast1(t *testing.T) {
	cc := &CloudControlLister{}

	region, typ, _, err := cc.resolveARNTarget("arn:aws:iam::123456789012:role/Admin")
	require.NoError(t, err)
	require.Equal(t, "AWS::IAM::Role", typ)
	require.Equal(t, "us-east-1", region)
}

func TestResolveARNTarget_UnknownServiceFails(t *testing.T) {
	cc := &CloudControlLister{}

	_, _, _, err := cc.resolveARNTarget("arn:aws:definitelynotreal:us-east-1:123456789012:thing/id")
	require.Error(t, err)
}

func TestResolveARNTarget_InvalidARNFails(t *testing.T) {
	cc := &CloudControlLister{}

	_, _, _, err := cc.resolveARNTarget("not-an-arn")
	require.Error(t, err)
}

func TestListByARN_SkipsSkippableErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "access denied", err: fmt.Errorf("AccessDeniedException: denied")},
		{name: "type not found", err: fmt.Errorf("TypeNotFoundException: missing")},
		{name: "unsupported action", err: fmt.Errorf("UnsupportedActionException: unsupported")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &CloudControlLister{
				getInRegionByARNFn: func(region, resourceType, identifier string, out *pipeline.P[output.AWSResource]) error {
					return tt.err
				},
			}

			out := pipeline.New[output.AWSResource]()
			err := cc.ListByARN("arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0", out)
			require.NoError(t, err)
		})
	}
}

func TestListByARN_ResourceNotFoundReturnsError(t *testing.T) {
	cc := &CloudControlLister{
		getInRegionByARNFn: func(region, resourceType, identifier string, out *pipeline.P[output.AWSResource]) error {
			return fmt.Errorf("ResourceNotFoundException: not found")
		},
	}

	out := pipeline.New[output.AWSResource]()
	err := cc.ListByARN("arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0", out)
	require.Error(t, err)
}
