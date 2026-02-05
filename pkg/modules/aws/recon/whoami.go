package recon

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pinpointsmsvoice"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/timestreamquery"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSWhoamiModule{})
}

// AWSWhoamiModule performs covert whoami techniques using AWS APIs
// that don't log to CloudTrail
type AWSWhoamiModule struct{}

func (m *AWSWhoamiModule) ID() string {
	return "whoami"
}

func (m *AWSWhoamiModule) Name() string {
	return "AWS Covert Whoami"
}

func (m *AWSWhoamiModule) Description() string {
	return "Performs covert whoami techniques using AWS APIs that don't log to CloudTrail."
}

func (m *AWSWhoamiModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSWhoamiModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSWhoamiModule) OpsecLevel() string {
	return "stealth"
}

func (m *AWSWhoamiModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSWhoamiModule) References() []string {
	return []string{
		"https://hackingthe.cloud/aws/enumeration/whoami/",
		"https://twitter.com/SpenGietz/status/1283846678194221057",
	}
}

func (m *AWSWhoamiModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "action",
			Description: "Whoami action to perform: timestream, pinpoint, sqs, or all",
			Type:        "string",
			Default:     "all",
		},
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *AWSWhoamiModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get action parameter
	action, ok := cfg.Args["action"].(string)
	if !ok || action == "" {
		action = "all"
	}

	// Validate action
	validActions := []string{"timestream", "pinpoint", "sqs", "all"}
	isValid := false
	for _, valid := range validActions {
		if strings.EqualFold(action, valid) {
			isValid = true
			break
		}
	}
	if !isValid {
		return nil, fmt.Errorf("invalid action: %s. Valid: %v", action, validActions)
	}

	// Get AWS config
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "stealth")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	var arnResult string

	switch strings.ToLower(action) {
	case "timestream":
		arnResult, err = m.timestreamDescribeEndpoints(cfg.Context, awsCfg)
	case "pinpoint":
		arnResult, err = m.pinpointSendVoiceMessage(cfg.Context, awsCfg)
	case "sqs":
		arnResult, err = m.sqsListQueues(cfg.Context, awsCfg)
	case "all":
		arnResult, err = m.tryAllMethods(cfg.Context, awsCfg)
	}

	if err != nil {
		return nil, fmt.Errorf("whoami execution failed: %w", err)
	}

	// Build result
	data := map[string]any{
		"status": "success",
		"arn":    arnResult,
		"action": action,
	}
	if arnResult == "" {
		data["status"] = "no_error_found"
		data["message"] = "API calls succeeded - covert whoami requires API failures"
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "whoami",
				"platform":    "aws",
				"opsec_level": "stealth",
			},
		},
	}, nil
}

func (m *AWSWhoamiModule) tryAllMethods(ctx context.Context, awsCfg aws.Config) (string, error) {
	methods := []struct {
		name string
		fn   func(context.Context, aws.Config) (string, error)
	}{
		{"timestream", m.timestreamDescribeEndpoints},
		{"pinpoint", m.pinpointSendVoiceMessage},
		{"sqs", m.sqsListQueues},
	}

	for _, method := range methods {
		arn, err := method.fn(ctx, awsCfg)
		if err == nil && arn != "" {
			return arn, nil
		}
	}

	return "", nil
}

func (m *AWSWhoamiModule) timestreamDescribeEndpoints(ctx context.Context, awsCfg aws.Config) (string, error) {
	client := timestreamquery.NewFromConfig(awsCfg)
	_, err := client.DescribeEndpoints(ctx, &timestreamquery.DescribeEndpointsInput{})
	if err != nil {
		return m.extractARNFromError(err.Error()), nil
	}
	return "", nil
}

func (m *AWSWhoamiModule) pinpointSendVoiceMessage(ctx context.Context, awsCfg aws.Config) (string, error) {
	client := pinpointsmsvoice.NewFromConfig(awsCfg)
	_, err := client.SendVoiceMessage(ctx, &pinpointsmsvoice.SendVoiceMessageInput{})
	if err != nil {
		return m.extractARNFromError(err.Error()), nil
	}
	return "", nil
}

func (m *AWSWhoamiModule) sqsListQueues(ctx context.Context, awsCfg aws.Config) (string, error) {
	client := sqs.NewFromConfig(awsCfg)
	_, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return m.extractARNFromError(err.Error()), nil
	}
	return "", nil
}

func (m *AWSWhoamiModule) extractARNFromError(errorMessage string) string {
	arnRegex := regexp.MustCompile(`arn:aws:[a-zA-Z0-9-]+::[0-9]{12}:[a-zA-Z0-9-_/]+`)
	matches := arnRegex.FindStringSubmatch(errorMessage)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}
