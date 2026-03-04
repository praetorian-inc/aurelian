package plugin

// AzureCommonRecon contains common parameters for Azure reconnaissance modules.
type AzureCommonRecon struct {
	SubscriptionID []string `param:"subscription-id" desc:"Azure subscription ID(s) or 'all' to enumerate all accessible subscriptions" default:"all" shortcode:"s"`
}
