package aws

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// AwsApolloOfflineBaseLink is a minimal base link for offline operations that doesn't require AWS credentials
type AwsApolloOfflineBaseLink struct {
	*base.NativeAWSLink
}

func NewAwsApolloOfflineBaseLink(args map[string]any) *AwsApolloOfflineBaseLink {
	return &AwsApolloOfflineBaseLink{
		NativeAWSLink: base.NewNativeAWSLink("apollo-offline-base", args),
	}
}

func (a *AwsApolloOfflineBaseLink) Process(ctx context.Context, input any) ([]any, error) {
	// Passthrough - just forwards input as output
	a.Send(input)
	return a.Outputs(), nil
}
