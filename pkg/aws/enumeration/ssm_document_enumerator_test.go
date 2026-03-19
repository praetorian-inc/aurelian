package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestSSMDocumentEnumerator_ResourceType(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	})
	enum := NewSSMDocumentEnumerator(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	}, provider)

	assert.Equal(t, "AWS::SSM::Document", enum.ResourceType())
}
