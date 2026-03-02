package secrets

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Extractor defines the interface for extracting scannable content from AWS resources.
type Extractor interface {
	Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, opts ScanOptions) ([]ExtractedContent, error)
}

// SupportedResourceTypes returns the list of resource types that have extractors.
func SupportedResourceTypes() []string {
	types := make([]string, 0, len(extractorRegistry))
	for t := range extractorRegistry {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// GetExtractor returns the extractor for a given resource type, or nil if unsupported.
func GetExtractor(resourceType string) Extractor {
	return extractorRegistry[resourceType]
}

// extractorRegistry maps resource type strings to their extractors.
var extractorRegistry = map[string]Extractor{
	"AWS::EC2::Instance":               &ec2UserDataExtractor{},
	"AWS::Lambda::Function":            &lambdaCodeExtractor{},
	"AWS::CloudFormation::Stack":       &cloudFormationTemplateExtractor{},
	"AWS::Logs::LogGroup":              &cloudWatchLogsExtractor{},
	"AWS::ECS::TaskDefinition":         &cloudControlPropertiesExtractor{label: "ECS TaskDefinition"},
	"AWS::SSM::Document":               &cloudControlPropertiesExtractor{label: "SSM Document"},
	"AWS::StepFunctions::StateMachine": &stepFunctionsExtractor{},
}

// isSkippableError returns true for errors that should be logged and skipped.
func isSkippableError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "AccessDenied") ||
		strings.Contains(s, "NotFound") ||
		strings.Contains(s, "NoSuchEntity") ||
		strings.Contains(s, "ResourceNotFoundException") ||
		strings.Contains(s, "InvalidInstanceID") ||
		strings.Contains(s, "does not exist")
}

// --- EC2 Instance UserData Extractor ---

type ec2UserDataExtractor struct{}

func (e *ec2UserDataExtractor) Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, _ ScanOptions) ([]ExtractedContent, error) {
	client := ec2.NewFromConfig(cfg)

	resp, err := client.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: aws.String(resource.ResourceID),
		Attribute:  ec2types.InstanceAttributeNameUserData,
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping EC2 instance", "id", resource.ResourceID, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("describe instance attribute %s: %w", resource.ResourceID, err)
	}

	if resp.UserData == nil || resp.UserData.Value == nil || *resp.UserData.Value == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*resp.UserData.Value)
	if err != nil {
		slog.Warn("failed to decode EC2 userdata base64", "id", resource.ResourceID, "error", err)
		return nil, nil
	}

	if len(decoded) == 0 {
		return nil, nil
	}

	return []ExtractedContent{
		{
			Content: decoded,
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/userdata", resource.ResourceID),
			},
		},
	}, nil
}

// --- Lambda Function Code Extractor ---

type lambdaCodeExtractor struct{}

func (e *lambdaCodeExtractor) Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, _ ScanOptions) ([]ExtractedContent, error) {
	client := lambda.NewFromConfig(cfg)

	resp, err := client.GetFunction(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(resource.ResourceID),
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping Lambda function", "id", resource.ResourceID, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("get function %s: %w", resource.ResourceID, err)
	}

	if resp.Code == nil || resp.Code.Location == nil || *resp.Code.Location == "" {
		return nil, nil
	}

	// Download the function code ZIP from the presigned URL
	zipData, err := downloadURL(ctx, *resp.Code.Location)
	if err != nil {
		slog.Warn("failed to download Lambda code", "id", resource.ResourceID, "error", err)
		return nil, nil
	}

	return extractZipContents(zipData, resource)
}

// extractZipContents reads a ZIP archive and returns ExtractedContent for each file.
func extractZipContents(zipData []byte, resource output.AWSResource) ([]ExtractedContent, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		slog.Warn("failed to open Lambda ZIP", "id", resource.ResourceID, "error", err)
		return nil, nil
	}

	var results []ExtractedContent
	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			slog.Debug("skipping ZIP entry", "file", f.Name, "error", err)
			continue
		}

		content, err := io.ReadAll(io.LimitReader(rc, 10*1024*1024)) // 10MB limit per file
		rc.Close()
		if err != nil {
			slog.Debug("error reading ZIP entry", "file", f.Name, "error", err)
			continue
		}

		if len(content) == 0 {
			continue
		}

		results = append(results, ExtractedContent{
			Content: content,
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/%s", resource.ResourceID, f.Name),
			},
		})
	}

	return results, nil
}

// --- CloudFormation Stack Template Extractor ---

type cloudFormationTemplateExtractor struct{}

func (e *cloudFormationTemplateExtractor) Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, _ ScanOptions) ([]ExtractedContent, error) {
	client := cloudformation.NewFromConfig(cfg)

	resp, err := client.GetTemplate(ctx, &cloudformation.GetTemplateInput{
		StackName: aws.String(resource.ResourceID),
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping CloudFormation stack", "id", resource.ResourceID, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("get template %s: %w", resource.ResourceID, err)
	}

	if resp.TemplateBody == nil || *resp.TemplateBody == "" {
		return nil, nil
	}

	content := []byte(*resp.TemplateBody)
	return []ExtractedContent{
		{
			Content: content,
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/template", resource.ResourceID),
			},
		},
	}, nil
}

// --- CloudWatch Logs Extractor ---

type cloudWatchLogsExtractor struct{}

func (e *cloudWatchLogsExtractor) Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, opts ScanOptions) ([]ExtractedContent, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)
	logGroupName := resource.ResourceID

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	maxStreams := opts.MaxStreams
	if maxStreams <= 0 {
		maxStreams = 10
	}

	// List log streams to respect maxStreams
	streamsResp, err := client.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: aws.String(logGroupName),
		OrderBy:      cwltypes.OrderByLastEventTime,
		Descending:   aws.Bool(opts.NewestFirst),
		Limit:        aws.Int32(int32(maxStreams)),
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping CloudWatch log group", "id", logGroupName, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("describe log streams %s: %w", logGroupName, err)
	}

	if len(streamsResp.LogStreams) == 0 {
		return nil, nil
	}

	// Collect log stream names for filtering
	streamNames := make([]string, 0, len(streamsResp.LogStreams))
	for _, s := range streamsResp.LogStreams {
		if s.LogStreamName != nil {
			streamNames = append(streamNames, *s.LogStreamName)
		}
	}

	// Use FilterLogEvents with pagination to get events across streams
	var allMessages []string
	totalEvents := 0
	var nextToken *string

	for {
		if totalEvents >= maxEvents {
			break
		}

		input := &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName:   aws.String(logGroupName),
			LogStreamNames: streamNames,
		}
		if nextToken != nil {
			input.NextToken = nextToken
		}

		resp, err := client.FilterLogEvents(ctx, input)
		if err != nil {
			if isSkippableError(err) {
				slog.Debug("skipping CloudWatch filter", "id", logGroupName, "error", err)
				break
			}
			return nil, fmt.Errorf("filter log events %s: %w", logGroupName, err)
		}

		for _, event := range resp.Events {
			if totalEvents >= maxEvents {
				break
			}
			if event.Message != nil {
				allMessages = append(allMessages, *event.Message)
				totalEvents++
			}
		}

		nextToken = resp.NextToken
		if nextToken == nil {
			break
		}
	}

	if len(allMessages) == 0 {
		return nil, nil
	}

	combined := []byte(strings.Join(allMessages, "\n"))
	return []ExtractedContent{
		{
			Content: combined,
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/events", logGroupName),
			},
		},
	}, nil
}

// --- CloudControl Properties Extractor (ECS TaskDefinition, SSM Document) ---

type cloudControlPropertiesExtractor struct {
	label string
}

func (e *cloudControlPropertiesExtractor) Extract(_ context.Context, _ aws.Config, resource output.AWSResource, _ ScanOptions) ([]ExtractedContent, error) {
	if resource.Properties == nil || len(resource.Properties) == 0 {
		return nil, nil
	}

	// Serialize the CloudControl properties JSON as scannable content
	content, err := json.MarshalIndent(resource.Properties, "", "  ")
	if err != nil {
		slog.Warn("failed to marshal properties", "type", e.label, "id", resource.ResourceID, "error", err)
		return nil, nil
	}

	if len(content) == 0 {
		return nil, nil
	}

	return []ExtractedContent{
		{
			Content: content,
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/properties.json", resource.ResourceID),
			},
		},
	}, nil
}

// --- Step Functions State Machine Extractor ---

type stepFunctionsExtractor struct{}

func (e *stepFunctionsExtractor) Extract(ctx context.Context, cfg aws.Config, resource output.AWSResource, _ ScanOptions) ([]ExtractedContent, error) {
	client := sfn.NewFromConfig(cfg)

	// Get the state machine definition
	descResp, err := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: aws.String(resource.ResourceID),
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping Step Functions state machine", "id", resource.ResourceID, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("describe state machine %s: %w", resource.ResourceID, err)
	}

	var results []ExtractedContent

	// Include the state machine definition itself
	if descResp.Definition != nil && *descResp.Definition != "" {
		results = append(results, ExtractedContent{
			Content: []byte(*descResp.Definition),
			Provenance: Provenance{
				Platform:     "aws",
				ResourceType: resource.ResourceType,
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    resource.AccountRef,
				FilePath:     fmt.Sprintf("%s/definition.json", resource.ResourceID),
			},
		})
	}

	// List recent executions and get their input/output
	listResp, err := client.ListExecutions(ctx, &sfn.ListExecutionsInput{
		StateMachineArn: aws.String(resource.ResourceID),
		MaxResults:      10,
	})
	if err != nil {
		if isSkippableError(err) {
			slog.Debug("skipping Step Functions executions list", "id", resource.ResourceID, "error", err)
			return results, nil
		}
		slog.Warn("failed to list executions", "id", resource.ResourceID, "error", err)
		return results, nil
	}

	for _, exec := range listResp.Executions {
		if exec.ExecutionArn == nil {
			continue
		}

		execResp, err := client.DescribeExecution(ctx, &sfn.DescribeExecutionInput{
			ExecutionArn: exec.ExecutionArn,
		})
		if err != nil {
			slog.Debug("skipping execution", "arn", *exec.ExecutionArn, "error", err)
			continue
		}

		// Scan execution input
		if execResp.Input != nil && *execResp.Input != "" {
			results = append(results, ExtractedContent{
				Content: []byte(*execResp.Input),
				Provenance: Provenance{
					Platform:     "aws",
					ResourceType: resource.ResourceType,
					ResourceID:   resource.ResourceID,
					Region:       resource.Region,
					AccountID:    resource.AccountRef,
					FilePath:     fmt.Sprintf("%s/executions/%s/input.json", resource.ResourceID, *exec.ExecutionArn),
				},
			})
		}

		// Scan execution output
		if execResp.Output != nil && *execResp.Output != "" {
			results = append(results, ExtractedContent{
				Content: []byte(*execResp.Output),
				Provenance: Provenance{
					Platform:     "aws",
					ResourceType: resource.ResourceType,
					ResourceID:   resource.ResourceID,
					Region:       resource.Region,
					AccountID:    resource.AccountRef,
					FilePath:     fmt.Sprintf("%s/executions/%s/output.json", resource.ResourceID, *exec.ExecutionArn),
				},
			})
		}
	}

	return results, nil
}
