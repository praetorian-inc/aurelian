package enumeration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// LambdaFunctionEnumerator enumerates Lambda functions using the native Lambda SDK,
// independent of any resource-based policy. The resource-policy collector only emits a
// function node when a function policy exists, so plain functions (the common case) are
// dropped — leaving the lambda:UpdateFunctionCode / lambda:AddPermission takeover privesc
// methods with no node to match. This enumerator emits EVERY function as
// AWS::Lambda::Function carrying its execution Role, so resource_to_role.yaml builds the
// (Function)-[:HAS_ROLE]->(Role) edge those methods re-point CAN_PRIVESC at.
//
// ListFunctions summaries already include the execution role (FunctionConfiguration.Role),
// so no per-function describe is needed.
type LambdaFunctionEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewLambdaFunctionEnumerator creates a LambdaFunctionEnumerator that uses the native Lambda SDK.
func NewLambdaFunctionEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *LambdaFunctionEnumerator {
	return &LambdaFunctionEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Lambda functions.
func (l *LambdaFunctionEnumerator) ResourceType() string {
	return "AWS::Lambda::Function"
}

// EnumerateAll enumerates all Lambda functions owned by the account across configured regions.
func (l *LambdaFunctionEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listFunctionsInRegion(region, accountID, out)
	})
}

func (l *LambdaFunctionEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	if _, ok := strings.CutPrefix(parsed.Resource, "function:"); !ok {
		return fmt.Errorf("invalid Lambda function ARN resource: %q", parsed.Resource)
	}
	if parsed.Region == "" {
		return fmt.Errorf("lambda function ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create Lambda client for %s: %w", parsed.Region, err)
	}
	result, err := lambda.NewFromConfig(*cfg).GetFunction(context.Background(), &lambda.GetFunctionInput{
		FunctionName: aws.String(arn),
	})
	if err != nil {
		if op := ClassifySkippable(err, "lambda", "GetFunction", parsed.Region); op != nil {
			l.skipReport.Record(*op)
			return nil
		}
		return fmt.Errorf("get function %s: %w", arn, err)
	}
	if result.Configuration == nil {
		return fmt.Errorf("get function %s returned no configuration", arn)
	}

	out.Send(buildLambdaFunctionResource(*result.Configuration, parsed.AccountID, parsed.Region))
	return nil
}

func (l *LambdaFunctionEnumerator) listFunctionsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Lambda client for %s: %w", region, err)
	}
	client := lambda.NewFromConfig(*cfg)

	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "lambda", "ListFunctions", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list functions in %s: %w", region, err)
		}
		for _, fn := range page.Functions {
			if aws.ToString(fn.FunctionArn) == "" {
				continue
			}
			out.Send(buildLambdaFunctionResource(fn, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildLambdaFunctionResource(fn lambdatypes.FunctionConfiguration, accountID, region string) output.AWSResource {
	name := aws.ToString(fn.FunctionName)

	return output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   name,
		ARN:          aws.ToString(fn.FunctionArn),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		LastModified: parseLambdaLastModified(aws.ToString(fn.LastModified)),
		Properties: map[string]any{
			"FunctionName": name,
			// Role is the function's execution role; NodeFromAWSResource promotes it to a
			// top-level node property and resource_to_role.yaml matches resource.Role =
			// role.Arn to create the (Function)-[:HAS_ROLE]->(Role) edge.
			"Role": aws.ToString(fn.Role),
		},
	}
}

func parseLambdaLastModified(value string) *time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			parsed = parsed.UTC()
			return &parsed
		}
	}
	return nil
}
