package enrichers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/amplify"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.RegisterEnricher("AWS::Amplify::App", enrichAmplifyAppWrapper)
}

type AmplifyClient interface {
	ListBranches(ctx context.Context, params *amplify.ListBranchesInput, optFns ...func(*amplify.Options)) (*amplify.ListBranchesOutput, error)
}

func enrichAmplifyAppWrapper(cfg plugin.EnricherConfig, r *output.AWSResource) error {
	client := amplify.NewFromConfig(cfg.AWSConfig)
	return EnrichAmplifyApp(cfg, r, client)
}

// EnrichAmplifyApp fetches branches for an Amplify app and constructs public
// URLs from the default domain. Each active branch produces a URL of the form
// https://{branchName}.{defaultDomain}.
func EnrichAmplifyApp(cfg plugin.EnricherConfig, r *output.AWSResource, client AmplifyClient) error {
	appID, _ := r.Properties["AppId"].(string)
	if appID == "" {
		return nil
	}

	defaultDomain, _ := r.Properties["DefaultDomain"].(string)
	if defaultDomain == "" {
		return nil
	}

	out, err := client.ListBranches(cfg.Context, &amplify.ListBranchesInput{
		AppId: &appID,
	})
	if err != nil {
		slog.Warn("amplify enricher: failed to list branches",
			"app_id", appID,
			"error", err,
		)
		return fmt.Errorf("failed to list amplify branches: %w", err)
	}

	var branchNames []string
	for _, branch := range out.Branches {
		if branch.DisplayName != nil {
			branchNames = append(branchNames, *branch.DisplayName)
			r.URLs = append(r.URLs, fmt.Sprintf("https://%s.%s", *branch.DisplayName, defaultDomain))
		}
	}

	if len(branchNames) > 0 {
		r.Properties["BranchNames"] = branchNames
		r.Properties["BranchCount"] = len(branchNames)
	}

	return nil
}
