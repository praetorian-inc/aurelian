package aws

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

// AwsApolloOfflineBaseLink is a minimal base link for offline operations that doesn't require AWS credentials
type AwsApolloOfflineBaseLink struct {
	*chain.Base
}

func NewAwsApolloOfflineBaseLink(link chain.Link, configs ...cfg.Config) *AwsApolloOfflineBaseLink {
	a := &AwsApolloOfflineBaseLink{}
	a.Base = chain.NewBase(link, configs...)
	return a
}

func (a *AwsApolloOfflineBaseLink) Initialize() error {
	// Initialize the base chain without AWS-specific operations
	a.ContextHolder = cfg.NewContextHolder()
	return nil
}