package aws

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type ApolloQuery struct {
	*base.NativeAWSLink
}

func NewApolloQuery(args map[string]any) *ApolloQuery {
	return &ApolloQuery{
		NativeAWSLink: base.NewNativeAWSLink("ApolloQuery", args),
	}
}

func (a *ApolloQuery) Parameters() []plugin.Parameter {
	// TODO: Port options to plugin.Parameter format
	return []plugin.Parameter{}
}

// Process implements the plugin interface
func (a *ApolloQuery) Process(ctx context.Context, input any) ([]any, error) {
	// TODO: Port Janus chain logic to standalone implementation
	a.Logger().Info("ApolloQuery.Process not yet implemented - requires Janus removal")
	return a.Outputs(), nil
}
