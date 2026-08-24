package extraction

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// ModifiedSinceFilter skips extraction when AWS provides trustworthy resource
// modification metadata and that timestamp is not newer than the caller's last
// successful scan. Unsupported resource types and metadata lookup failures fail
// open: the resource is scanned.
type ModifiedSinceFilter struct {
	opts    plugin.AWSCommonRecon
	since   time.Time
	mu      sync.Mutex
	configs map[string]aws.Config
}

// NewModifiedSinceFilter creates an incremental resource filter.
func NewModifiedSinceFilter(opts plugin.AWSCommonRecon, since time.Time) *ModifiedSinceFilter {
	return &ModifiedSinceFilter{
		opts:    opts,
		since:   since,
		configs: make(map[string]aws.Config),
	}
}

// Filter is pipeline-compatible. A resource is omitted only when its last
// modification time is known and is not newer than the checkpoint.
func (f *ModifiedSinceFilter) Filter(resource output.AWSResource, out *pipeline.P[output.AWSResource]) error {
	modifiedAt, known, err := f.lastModified(context.Background(), resource)
	if err != nil {
		slog.Warn("failed to determine AWS resource modification time; rescanning",
			"type", resource.ResourceType,
			"resource", resource.ResourceID,
			"error", err,
		)
		out.Send(resource)
		return nil
	}

	if !known || modifiedAt.After(f.since) {
		out.Send(resource)
		return nil
	}

	slog.Info("skipping unchanged AWS resource",
		"type", resource.ResourceType,
		"resource", resource.ResourceID,
		"modified_at", modifiedAt,
		"modified_since", f.since,
	)
	return nil
}

func (f *ModifiedSinceFilter) lastModified(ctx context.Context, resource output.AWSResource) (time.Time, bool, error) {
	switch resource.ResourceType {
	case "AWS::Lambda::Function":
		cfg, err := f.configFor(resource.Region)
		if err != nil {
			return time.Time{}, false, err
		}
		name := propertyString(resource.Properties, "FunctionName", resource.ResourceID)
		result, err := lambda.NewFromConfig(cfg).GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{
			FunctionName: aws.String(name),
		})
		if err != nil {
			return time.Time{}, false, fmt.Errorf("get Lambda configuration: %w", err)
		}
		if result.LastModified == nil || *result.LastModified == "" {
			return time.Time{}, false, nil
		}
		modifiedAt, err := parseAWSTimestamp(*result.LastModified)
		if err != nil {
			return time.Time{}, false, fmt.Errorf("parse Lambda LastModified: %w", err)
		}
		return modifiedAt, true, nil

	case "AWS::CloudFormation::Stack":
		cfg, err := f.configFor(resource.Region)
		if err != nil {
			return time.Time{}, false, err
		}
		name := propertyString(resource.Properties, "StackName", resource.ResourceID)
		result, err := cloudformation.NewFromConfig(cfg).DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
			StackName: aws.String(name),
		})
		if err != nil {
			return time.Time{}, false, fmt.Errorf("describe CloudFormation stack: %w", err)
		}
		if len(result.Stacks) == 0 {
			return time.Time{}, false, nil
		}
		stack := result.Stacks[0]
		if stack.LastUpdatedTime != nil {
			return stack.LastUpdatedTime.UTC(), true, nil
		}
		if stack.CreationTime != nil {
			return stack.CreationTime.UTC(), true, nil
		}
		return time.Time{}, false, nil

	case "AWS::ECS::TaskDefinition":
		cfg, err := f.configFor(resource.Region)
		if err != nil {
			return time.Time{}, false, err
		}
		identifier := resource.ARN
		if identifier == "" {
			identifier = resource.ResourceID
		}
		result, err := ecs.NewFromConfig(cfg).DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(identifier),
		})
		if err != nil {
			return time.Time{}, false, fmt.Errorf("describe ECS task definition: %w", err)
		}
		if result.TaskDefinition == nil || result.TaskDefinition.RegisteredAt == nil {
			return time.Time{}, false, nil
		}
		return result.TaskDefinition.RegisteredAt.UTC(), true, nil

	case "AWS::SSM::Parameter":
		modifiedAt, ok := propertyTime(resource.Properties, "LastModifiedDate")
		return modifiedAt, ok, nil

	// EC2 user data has no modification timestamp. CloudWatch Logs and Step
	// Functions executions are append-only/dynamic inputs. SSM document version
	// dates are not present in the enumerated resource. Rescan these types rather
	// than risk suppressing new content.
	default:
		return time.Time{}, false, nil
	}
}

func (f *ModifiedSinceFilter) configFor(region string) (aws.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cfg, ok := f.configs[region]; ok {
		return cfg, nil
	}

	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    f.opts.Profile,
		ProfileDir: f.opts.ProfileDir,
	})
	if err != nil {
		return aws.Config{}, fmt.Errorf("create AWS config for change detection: %w", err)
	}
	f.configs[region] = cfg
	return cfg, nil
}

func propertyString(properties map[string]any, key, fallback string) string {
	if value, ok := properties[key].(string); ok && value != "" {
		return value
	}
	return fallback
}

func propertyTime(properties map[string]any, key string) (time.Time, bool) {
	value, ok := properties[key]
	if !ok || value == nil {
		return time.Time{}, false
	}
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), true
	case *time.Time:
		if typed != nil {
			return typed.UTC(), true
		}
	case string:
		if typed == "" {
			return time.Time{}, false
		}
		parsed, err := parseAWSTimestamp(typed)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func parseAWSTimestamp(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000-0700",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported AWS timestamp %q", value)
}
