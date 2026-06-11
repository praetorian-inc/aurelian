package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// SSMParameterEnumerator enumerates SSM Parameter Store parameters, filtering to
// String and StringList types only. SecureString is intentionally excluded — it is
// the correct storage location for secrets and requires kms:Decrypt to read.
type SSMParameterEnumerator struct {
	plugin.AWSCommonRecon
	provider *AWSConfigProvider
}

func NewSSMParameterEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *SSMParameterEnumerator {
	return &SSMParameterEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

func (e *SSMParameterEnumerator) ResourceType() string {
	return "AWS::SSM::Parameter"
}

func (e *SSMParameterEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := e.provider.GetAccountID(e.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(e.Concurrency)
	return actor.ActInRegions(e.Regions, func(region string) error {
		return e.listParametersInRegion(region, accountID, out)
	})
}

func (e *SSMParameterEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}

	// ARN resource format: "parameter/name" or "parameter/path/to/name"
	paramPath, ok := strings.CutPrefix(parsed.Resource, "parameter/")
	if !ok {
		return fmt.Errorf("invalid SSM parameter ARN resource: %q", parsed.Resource)
	}
	// Restore leading slash for hierarchical parameter names.
	paramName := "/" + paramPath

	if parsed.Region == "" {
		return fmt.Errorf("SSM parameter ARN missing region: %q", arn)
	}

	cfg, err := e.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create SSM client for %s: %w", parsed.Region, err)
	}
	client := ssm.NewFromConfig(*cfg)

	result, err := client.DescribeParameters(context.Background(), &ssm.DescribeParametersInput{
		ParameterFilters: []ssmtypes.ParameterStringFilter{
			// Option "Equals" is required — the default is "BeginsWith", which would
			// return any parameter whose name starts with paramName.
			{Key: aws.String("Name"), Option: aws.String("Equals"), Values: []string{paramName}},
		},
	})
	if err != nil {
		return fmt.Errorf("describe parameter %s: %w", paramName, err)
	}

	for _, p := range result.Parameters {
		if p.Type == ssmtypes.ParameterTypeSecureString {
			continue
		}
		name := aws.ToString(p.Name)
		out.Send(output.AWSResource{
			ResourceType: "AWS::SSM::Parameter",
			ResourceID:   name,
			ARN:          fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/%s", parsed.Region, parsed.AccountID, strings.TrimPrefix(name, "/")),
			AccountRef:   parsed.AccountID,
			Region:       parsed.Region,
			DisplayName:  name,
			Properties: map[string]any{
				"Name": name,
				"Type": string(p.Type),
				"Tier": string(p.Tier),
			},
		})
	}
	return nil
}

func (e *SSMParameterEnumerator) listParametersInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create SSM client for %s: %w", region, err)
	}
	client := ssm.NewFromConfig(*cfg)

	paginator := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{
		ParameterFilters: []ssmtypes.ParameterStringFilter{
			{Key: aws.String("Type"), Values: []string{"String", "StringList"}},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return fmt.Errorf("describe parameters in %s: %w", region, err)
		}

		for _, p := range page.Parameters {
			name := aws.ToString(p.Name)
			out.Send(output.AWSResource{
				ResourceType: "AWS::SSM::Parameter",
				ResourceID:   name,
				ARN:          fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/%s", region, accountID, strings.TrimPrefix(name, "/")),
				AccountRef:   accountID,
				Region:       region,
				DisplayName:  name,
				Properties: map[string]any{
					"Name": name,
					"Type": string(p.Type),
					"Tier": string(p.Tier),
				},
			})
		}
	}
	return nil
}
