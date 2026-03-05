package enumeration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestS3Enumerator_ResourceType(t *testing.T) {
	l := &S3Enumerator{}
	require.Equal(t, "AWS::S3::Bucket", l.ResourceType())
}

func TestS3Enumerator_EnumerateByARN_ReturnsFallback(t *testing.T) {
	enumerator := &S3Enumerator{}
	err := enumerator.EnumerateByARN("arn:aws:s3:::my-bucket", nil)
	require.ErrorIs(t, err, errFallbackToCloudControl)
}
