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

var arnRegex = regexp.MustCompile(`arn:aws:[a-zA-Z0-9-]+::[0-9]{12}:[a-zA-Z0-9-_/]+`)

func init() {
	plugin.Register(&AWSWhoamiModule{})
}

// WhoamiConfig holds the typed parameters for the whoami module.
type WhoamiConfig struct {
	plugin.AWSReconBase
	Action string `param:"action" desc:"Whoami technique: timestream, pinpoint, sqs, or all" default:"all" enum:"timestream,pinpoint,sqs,all"`
}

// AWSWhoamiModule performs covert caller identity extraction using AWS APIs
// whose error messages leak the caller ARN without logging to CloudTrail.
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
	return []string{"AWS::IAM::User", "AWS::IAM::Role"}
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

	ctx := context.TODO()
	action := strings.ToLower(c.Action)

	type technique struct {
		name string
		fn   func(context.Context, aws.Config) string
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
		arn := t.fn(ctx, awsCfg)
		if arn != "" {
			slog.Info("extracted ARN", "method", t.name, "arn", arn)
			out.Send(&output.CallerIdentity{
				Status:  "success",
				ARN:     arn,
				Account: accountFromARN(arn),
				Method:  t.name,
			})
			return nil
		}
		slog.Debug("method returned no ARN", "method", t.name)
	}

	// All techniques failed to extract an ARN — the APIs succeeded (caller has permissions)
	out.Send(&output.CallerIdentity{
		Status: "no_arn_found",
	})
	return nil
}

func timestreamDescribeEndpoints(ctx context.Context, cfg aws.Config) string {
	client := timestreamquery.NewFromConfig(cfg)
	_, err := client.DescribeEndpoints(ctx, &timestreamquery.DescribeEndpointsInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	return ""
}

func pinpointSendVoiceMessage(ctx context.Context, cfg aws.Config) string {
	client := pinpointsmsvoice.NewFromConfig(cfg)
	_, err := client.SendVoiceMessage(ctx, &pinpointsmsvoice.SendVoiceMessageInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	return ""
}

func sqsListQueues(ctx context.Context, cfg aws.Config) string {
	client := sqs.NewFromConfig(cfg)
	_, err := client.ListQueues(ctx, &sqs.ListQueuesInput{})
	if err != nil {
		return extractARNFromError(err.Error())
	}
	return ""
}

func extractARNFromError(errorMessage string) string {
	match := arnRegex.FindString(errorMessage)
	if match != "" {
		return match
	}
	slog.Debug("no ARN in error message", "error", errorMessage)
	return ""
}

func accountFromARN(arn string) string {
	// ARN format: arn:aws:<service>::<account>:<resource>
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
