package azure

import (
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// AzureSubscriptionGeneratorLink generates subscription IDs based on input
type AzureSubscriptionGeneratorLink struct {
	*chain.Base
}

func NewAzureSubscriptionGeneratorLink(configs ...cfg.Config) chain.Link {
	l := &AzureSubscriptionGeneratorLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureSubscriptionGeneratorLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureSubscriptionGeneratorLink) Process(input any) error {
	subscriptions, _ := cfg.As[[]string](l.Arg("subscription"))
	
	l.Logger.Info("Processing Azure subscription input", "subscriptions", subscriptions)
	
	// Handle the case where subscriptions is empty or contains "all"
	if len(subscriptions) == 0 || (len(subscriptions) == 1 && strings.EqualFold(subscriptions[0], "all")) {
		l.Logger.Info("Listing all subscriptions")
		
		// Get credentials
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			l.Logger.Error("Failed to get Azure credentials", "error", err)
			return err
		}
		
		// Create subscription client directly
		subClient, err := armsubscriptions.NewClient(cred, nil)
		if err != nil {
			l.Logger.Error("Failed to create subscription client", "error", err)
			return err
		}
		
		// List all subscriptions
		pager := subClient.NewListPager(nil)
		var allSubs []string
		
		for pager.More() {
			page, err := pager.NextPage(l.Context())
			if err != nil {
				l.Logger.Error("Failed to list subscriptions", "error", err)
				return err
			}
			
			for _, sub := range page.Value {
				if sub.SubscriptionID != nil {
					allSubs = append(allSubs, *sub.SubscriptionID)
				}
			}
		}
		
		l.Logger.Info("Found subscriptions", "count", len(allSubs))
		
		for _, sub := range allSubs {
			l.Logger.Debug("Sending subscription", "subscription", sub)
			l.Send(sub)
		}
	} else {
		// Use the provided subscriptions
		for _, subscription := range subscriptions {
			l.Logger.Info("Using subscription", "subscription", subscription)
			l.Send(subscription)
		}
	}
	
	return nil
}