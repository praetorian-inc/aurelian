package aws

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pinpointsmsvoice"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/timestreamquery"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

type AwsWhoami struct {
	*base.AwsReconBaseLink
	action string
}

func NewAwsWhoami(action string, args map[string]any) *AwsWhoami {
	return &AwsWhoami{
		AwsReconBaseLink: base.NewAwsReconBaseLink("AWS Covert Whoami", args),
		action:           action,
	}
}

func (l *AwsWhoami) Process(ctx context.Context, input any) ([]any, error) {
	// Get AWS config
	awsConfig, err := l.GetConfigWithRuntimeArgs(ctx, "us-east-1")
	if err != nil {
		l.Logger().Error("failed to get AWS config", "error", err)
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	var arnResult string

	switch strings.ToLower(l.action) {
	case "timestream":
		arnResult, err = l.timestreamDescribeEndpoints(ctx, awsConfig)
	case "pinpoint":
		arnResult, err = l.pinpointSendVoiceMessage(ctx, awsConfig)
	case "sqs":
		arnResult, err = l.sqsListQueues(ctx, awsConfig)
	case "all":
		// Try all methods in order until one succeeds
		methods := []struct {
			name string
			fn   func(context.Context, aws.Config) (string, error)
		}{
			{"timestream", l.timestreamDescribeEndpoints},
			{"pinpoint", l.pinpointSendVoiceMessage},
			{"sqs", l.sqsListQueues},
		}

		for _, method := range methods {
			l.Logger().Info("trying whoami method", "method", method.name)
			arnResult, err = method.fn(ctx, awsConfig)
			if err == nil && arnResult != "" {
				l.Logger().Info("successfully identified ARN", "method", method.name, "arn", arnResult)
				break
			}
			l.Logger().Debug("method failed or returned empty result", "method", method.name, "error", err)
		}
	default:
		return nil, fmt.Errorf("invalid action: %s. Valid actions are: timestream, pinpoint, sqs, all", l.action)
	}

	if err != nil {
		l.Logger().Error("failed to execute whoami", "action", l.action, "error", err)
		return nil, fmt.Errorf("failed to execute whoami: %w", err)
	}

	if arnResult == "" {
		l.Logger().Info("no ARN found in error messages - API calls may have succeeded due to sufficient permissions")
		// Instead of failing, send a message indicating the technique didn't work
		result := map[string]any{
			"status":  "no_error_found",
			"message": "API calls succeeded - covert whoami techniques require API calls to fail due to lack of permissions",
			"action":  l.action,
		}
		return []any{result}, nil
	}

	l.Logger().Info("successfully extracted ARN", "arn", arnResult)
	result := map[string]any{
		"status": "success",
		"arn":    arnResult,
		"action": l.action,
	}
	return []any{result}, nil
}

func (l *AwsWhoami) timestreamDescribeEndpoints(ctx context.Context, awsConfig aws.Config) (string, error) {
	client := timestreamquery.NewFromConfig(awsConfig)

	_, err := client.DescribeEndpoints(ctx, &timestreamquery.DescribeEndpointsInput{})
	if err != nil {
		l.Logger().Debug("timestream describe endpoints error", "error", err.Error())
		return l.extractARNFromError(err.Error()), nil
	}

	// If no error, we can't extract the ARN
	l.Logger().Debug("timestream describe endpoints succeeded - cannot extract ARN")
	return "", nil
}

func (l *AwsWhoami) pinpointSendVoiceMessage(ctx context.Context, awsConfig aws.Config) (string, error) {
	client := pinpointsmsvoice.NewFromConfig(awsConfig)

	_, err := client.SendVoiceMessage(ctx, &pinpointsmsvoice.SendVoiceMessageInput{})
	if err != nil {
		l.Logger().Debug("pinpoint send voice message error", "error", err.Error())
		return l.extractARNFromError(err.Error()), nil
	}

	// If no error, we can't extract the ARN
	l.Logger().Debug("pinpoint send voice message succeeded - cannot extract ARN")
	return "", nil
}

func (l *AwsWhoami) sqsListQueues(ctx context.Context, awsConfig aws.Config) (string, error) {
	client := sqs.NewFromConfig(awsConfig)

	_, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		l.Logger().Debug("sqs list queues error", "error", err.Error())
		return l.extractARNFromError(err.Error()), nil
	}

	// If no error, we can't extract the ARN
	l.Logger().Debug("sqs list queues succeeded - cannot extract ARN")
	return "", nil
}

func (l *AwsWhoami) extractARNFromError(errorMessage string) string {
	// Regex to extract ARN from error messages
	// Pattern matches: arn:aws:sts::123456789012:assumed-role/role-name/session-name
	// or: arn:aws:iam::123456789012:user/username
	// Updated regex to be more precise and stop at word boundaries
	arnRegex := regexp.MustCompile(`arn:aws:[a-zA-Z0-9-]+::[0-9]{12}:[a-zA-Z0-9-_/]+`)

	matches := arnRegex.FindStringSubmatch(errorMessage)
	if len(matches) > 0 {
		return matches[0]
	}

	l.Logger().Debug("no ARN found in error message", "error", errorMessage)
	return ""
}
