package recon

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/pinpointsmsvoice"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/timestreamquery"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

var arnRegex = regexp.MustCompile(`arn:aws:[a-zA-Z0-9-]+::[0-9]{12}:[a-zA-Z0-9-_/.+=,@]+`)

func init() {
	plugin.Register(&AWSWhoamiModule{})
}

type WhoamiConfig struct {
	plugin.AWSReconBase
	Action string `param:"action" desc:"Whoami technique: timestream, pinpoint, sqs, or all" default:"all" enum:"timestream,pinpoint,sqs,all"`
}

type AWSWhoamiModule struct {
	WhoamiConfig
}

func (m *AWSWhoamiModule) ID() string                { return "whoami" }
func (m *AWSWhoamiModule) Name() string              { return "AWS Covert Whoami" }
func (m *AWSWhoamiModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSWhoamiModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSWhoamiModule) OpsecLevel() string        { return "stealth" }
func (m *AWSWhoamiModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSWhoamiModule) Description() string {
	return "Covert whoami using AWS APIs that leak the caller ARN in error messages without logging to CloudTrail. Supports timestream, pinpoint, and sqs techniques."
}

func (m *AWSWhoamiModule) References() []string {
	return []string{
		"https://hackingthe.cloud/aws/enumeration/whoami/",
		"https://twitter.com/SpenGietz/status/1283846678194221057",
	}
}

func (m *AWSWhoamiModule) SupportedResourceTypes() []string {
	return nil
}

func (m *AWSWhoamiModule) Parameters() any {
	return &m.WhoamiConfig
}

func (m *AWSWhoamiModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.WhoamiConfig

	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("whoami: load AWS config: %w", err)
	}

	ctx := cfg.Context
	action := strings.ToLower(c.Action)

	type technique struct {
		name string
		fn   func(context.Context, aws.Config, *plugin.Logger) string
	}

	techniques := []technique{
		{"timestream", timestreamDescribeEndpoints},
		{"pinpoint", pinpointSendVoiceMessage},
		{"sqs", sqsListQueues},
	}

	// Filter to a single technique if not "all"
	if action != "all" {
		for _, t := range techniques {
			if t.name == action {
				techniques = []technique{t}
				break
			}
		}
	}

	for _, t := range techniques {
		slog.Info("trying whoami method", "method", t.name)
		arn := t.fn(ctx, awsCfg, cfg.Log)
		if arn != "" {
			cfg.Log.Success("extracted ARN via %s: %s", t.name, arn)
			out.Send(&output.CallerIdentity{
				Status:  "success",
				ARN:     arn,
				Account: accountFromARN(arn),
			})
			return nil
		}
		slog.Debug("method returned no ARN", "method", t.name)
	}

	cfg.Log.Warn("no ARN extracted — all techniques returned non-IAM errors (caller likely has permissions for these APIs, or the APIs aren't enabled)")
	out.Send(&output.CallerIdentity{
		Status: "no_arn_found",
	})
	return nil
}

func timestreamDescribeEndpoints(ctx context.Context, cfg aws.Config, log *plugin.Logger) string {
	client := timestreamquery.NewFromConfig(cfg)
	_, err := client.DescribeEndpoints(ctx, &timestreamquery.DescribeEndpointsInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	log.Info("timestream: caller has timestream:DescribeEndpoints permission")
	return ""
}

func pinpointSendVoiceMessage(ctx context.Context, cfg aws.Config, log *plugin.Logger) string {
	client := pinpointsmsvoice.NewFromConfig(cfg)
	_, err := client.SendVoiceMessage(ctx, &pinpointsmsvoice.SendVoiceMessageInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	log.Info("pinpoint: caller has sms-voice:SendVoiceMessage permission")
	return ""
}

func sqsListQueues(ctx context.Context, cfg aws.Config, log *plugin.Logger) string {
	client := sqs.NewFromConfig(cfg)
	_, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	log.Info("sqs: caller has sqs:ListQueues permission")
	return ""
}

func extractARNFromError(errorMessage string) string {
	match := arnRegex.FindString(errorMessage)
	if match != "" {
		return match
	}
	slog.Debug("no ARN matched in error message", "regex", arnRegex.String(), "error_message", errorMessage)
	return ""
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
