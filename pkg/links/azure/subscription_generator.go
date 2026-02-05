package azure
import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"strings"
)
// AzureSubscriptionGeneratorLink generates subscription IDs based on input
type AzureSubscriptionGeneratorLink struct {
	*base.NativeAzureLink
}
func NewAzureSubscriptionGeneratorLink(args map[string]any) *AzureSubscriptionGeneratorLink {
	return &AzureSubscriptionGeneratorLink{
		NativeAzureLink: base.NewNativeAzureLink("subscription-generator", args),
	}
}
func (l *AzureSubscriptionGeneratorLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureSubscription(),
	}
}
func (l *AzureSubscriptionGeneratorLink) Process(ctx context.Context, input any) ([]any, error) {
	var subscriptions []string
	if subs, ok := l.Arg("subscription").([]string); ok {
		subscriptions = subs
	}
	l.Logger().Info("Processing Azure subscription input", "subscriptions", subscriptions)
	// Handle the case where subscriptions is empty or contains "all"
	if len(subscriptions) == 0 || (len(subscriptions) == 1 && strings.EqualFold(subscriptions[0], "all")) {
		l.Logger().Info("Listing all subscriptions")
		// Get credentials
		cred, err := helpers.NewAzureCredential()
		if err != nil {
			l.Logger().Error("Failed to get Azure credentials", "error", err)
			return nil, err
		}
		// Create subscription client directly
		subClient, err := armsubscriptions.NewClient(cred, nil)
		if err != nil {
			l.Logger().Error("Failed to create subscription client", "error", err)
			return nil, err
		}
		// List all subscriptions
		pager := subClient.NewListPager(nil)
		var allSubs []string
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				l.Logger().Error("Failed to list subscriptions", "error", err)
				return nil, err
			}
			for _, sub := range page.Value {
				if sub.SubscriptionID != nil {
					allSubs = append(allSubs, *sub.SubscriptionID)
				}
			}
		}
		l.Logger().Info("Found subscriptions", "count", len(allSubs))
		for _, sub := range allSubs {
			l.Logger().Debug("Sending subscription", "subscription", sub)
			l.Send(sub)
		}
	} else {
		// Use the provided subscriptions
		for _, subscription := range subscriptions {
			l.Logger().Info("Using subscription", "subscription", subscription)
			l.Send(subscription)
		}
	}
	return l.Outputs(), nil
}
