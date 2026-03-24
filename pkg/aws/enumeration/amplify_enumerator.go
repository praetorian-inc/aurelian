package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/amplify"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// AmplifyAppEnumerator enumerates Amplify apps using the native Amplify SDK
// because CloudControl does not support AWS::Amplify::App.
type AmplifyAppEnumerator struct {
	plugin.AWSCommonRecon
	provider *AWSConfigProvider
}

func NewAmplifyAppEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *AmplifyAppEnumerator {
	return &AmplifyAppEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

func (e *AmplifyAppEnumerator) ResourceType() string {
	return "AWS::Amplify::App"
}

func (e *AmplifyAppEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := e.provider.GetAccountID(e.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(e.Concurrency)
	return actor.ActInRegions(e.Regions, func(region string) error {
		return e.listAppsInRegion(region, accountID, out)
	})
}

func (e *AmplifyAppEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}

	appID, ok := strings.CutPrefix(parsed.Resource, "apps/")
	if !ok {
		return fmt.Errorf("invalid Amplify app ARN resource: %q", parsed.Resource)
	}

	if parsed.Region == "" {
		return fmt.Errorf("Amplify app ARN missing region: %q", arn)
	}

	cfg, err := e.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create Amplify client for %s: %w", parsed.Region, err)
	}
	client := amplify.NewFromConfig(*cfg)

	result, err := client.GetApp(context.Background(), &amplify.GetAppInput{
		AppId: aws.String(appID),
	})
	if err != nil {
		return fmt.Errorf("get amplify app %s: %w", appID, err)
	}

	app := result.App
	out.Send(output.AWSResource{
		ResourceType: "AWS::Amplify::App",
		ResourceID:   aws.ToString(app.AppId),
		ARN:          aws.ToString(app.AppArn),
		AccountRef:   parsed.AccountID,
		Region:       parsed.Region,
		DisplayName:  aws.ToString(app.Name),
		Properties: map[string]any{
			"AppId":         aws.ToString(app.AppId),
			"Name":          aws.ToString(app.Name),
			"DefaultDomain": aws.ToString(app.DefaultDomain),
			"Platform":      string(app.Platform),
			"Repository":    aws.ToString(app.Repository),
		},
	})
	return nil
}

func (e *AmplifyAppEnumerator) listAppsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Amplify client for %s: %w", region, err)
	}
	client := amplify.NewFromConfig(*cfg)

	var nextToken *string
	paginator := ratelimit.NewAWSPaginator()
	return paginator.Paginate(func() (bool, error) {
		result, err := client.ListApps(context.Background(), &amplify.ListAppsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return false, fmt.Errorf("list amplify apps in %s: %w", region, err)
		}

		for _, app := range result.Apps {
			appID := aws.ToString(app.AppId)
			out.Send(output.AWSResource{
				ResourceType: "AWS::Amplify::App",
				ResourceID:   appID,
				ARN:          aws.ToString(app.AppArn),
				AccountRef:   accountID,
				Region:       region,
				DisplayName:  aws.ToString(app.Name),
				Properties: map[string]any{
					"AppId":         appID,
					"Name":          aws.ToString(app.Name),
					"DefaultDomain": aws.ToString(app.DefaultDomain),
					"Platform":      string(app.Platform),
					"Repository":    aws.ToString(app.Repository),
				},
			})
		}

		nextToken = result.NextToken
		return nextToken != nil, nil
	})
}
