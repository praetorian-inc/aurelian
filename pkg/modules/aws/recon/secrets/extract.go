package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// ExtractorConfig holds shared configuration for content extractors.
type ExtractorConfig struct {
	AWSConfigFactory func(region string) (aws.Config, error)
	MaxEvents        int
	MaxStreams       int
	NewestFirst      bool
}

// ExtractContent is a pipeline-compatible function that dispatches to per-type extractors.
// It switches on the AWSResource's ResourceType and calls the appropriate extractor.
// Unsupported resource types are silently skipped.
func ExtractContent(cfg ExtractorConfig) func(output.AWSResource, *pipeline.P[ScanInput]) error {
	return func(r output.AWSResource, out *pipeline.P[ScanInput]) error {
		var err error

		switch r.ResourceType {
		case "AWS::EC2::Instance":
			err = extractEC2(cfg, r, out)
		case "AWS::Lambda::Function":
			err = extractLambda(cfg, r, out)
		case "AWS::CloudFormation::Stack":
			err = extractCFN(cfg, r, out)
		case "AWS::Logs::LogGroup":
			err = extractLogs(cfg, r, out)
		case "AWS::ECS::TaskDefinition":
			err = extractProperties(r, out, "TaskDefinition")
		case "AWS::SSM::Document":
			err = extractProperties(r, out, "Document")
		case "AWS::StepFunctions::StateMachine":
			err = extractSFN(cfg, r, out)
		default:
			slog.Debug("find-secrets: unsupported resource type, skipping", "type", r.ResourceType)
			return nil
		}

		if err != nil {
			slog.Warn("find-secrets: extraction failed, skipping resource",
				"type", r.ResourceType, "resource", r.ResourceID, "error", err)
			return nil // Don't fail the pipeline for individual extraction errors
		}
		return nil
	}
}

// extractProperties serializes the AWSResource's Properties map as JSON and emits it.
// Used for resource types where Cloud Control already returns all relevant content
// (e.g. ECS TaskDefinition, SSM Document).
func extractProperties(r output.AWSResource, out *pipeline.P[ScanInput], label string) error {
	if len(r.Properties) == 0 {
		return nil
	}

	data, err := json.Marshal(r.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	out.Send(ScanInput{
		Content:      data,
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Label:        label,
	})
	return nil
}
