//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCognitoUserPoolEnricherGroupRoles(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/cognito-enricher")
	fixture.Setup()

	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	require.NoError(t, err)

	poolID := fixture.Output("cognito_pool_id")
	expectedRoleArn := fixture.Output("cognito_group_role_arn")
	resource := &output.AWSResource{
		ResourceType: "AWS::Cognito::UserPool",
		ResourceID:   poolID,
		Region:       "us-east-1",
		Properties:   map[string]any{"UserPoolId": poolID},
	}

	client := cognitoidentityprovider.NewFromConfig(awsCfg)
	err = enrichers.EnrichCognitoUserPool(plugin.EnricherConfig{
		Context:   ctx,
		AWSConfig: awsCfg,
	}, resource, client)
	require.NoError(t, err)

	roles, ok := resource.Properties["Roles"].([]string)
	require.True(t, ok, "expected Cognito enricher to add Roles property")
	assert.Contains(t, roles, expectedRoleArn)
}
