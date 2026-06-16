package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A trailing-slash ARN passes the prefix check but yields an empty name; both
// native enumerators must reject it up front rather than calling the AWS API
// with an empty identifier and surfacing an opaque service error.
func TestClassicELBEnumerator_EnumerateByARN_EmptyName(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
	enum := NewClassicELBEnumerator(plugin.AWSCommonRecon{}, provider, NewSkipReport())
	out := pipeline.New[output.AWSResource]()

	err := enum.EnumerateByARN("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing load balancer name")
}

func TestOpenSearchDomainEnumerator_EnumerateByARN_EmptyName(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
	enum := NewOpenSearchDomainEnumerator(plugin.AWSCommonRecon{}, provider, NewSkipReport())
	out := pipeline.New[output.AWSResource]()

	err := enum.EnumerateByARN("arn:aws:es:us-east-1:123456789012:domain/", out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing domain name")
}
