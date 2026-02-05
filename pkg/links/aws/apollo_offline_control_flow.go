package aws

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type AwsApolloOfflineControlFlow struct {
	*base.NativeAWSLink
}

func NewAwsApolloOfflineControlFlow(args map[string]any) *AwsApolloOfflineControlFlow {
	return &AwsApolloOfflineControlFlow{
		NativeAWSLink: base.NewNativeAWSLink("AwsApolloOfflineControlFlow", args),
	}
}

func (a *AwsApolloOfflineControlFlow) Parameters() []plugin.Parameter {
	// TODO: Port options to plugin.Parameter format
	return []plugin.Parameter{}
}

// Process implements the plugin interface
func (a *AwsApolloOfflineControlFlow) Process(ctx context.Context, input any) ([]any, error) {
	// TODO: Port Janus chain logic to standalone implementation
	a.Logger().Info("AwsApolloOfflineControlFlow.Process not yet implemented - requires Janus removal")
	return a.Outputs(), nil
}
