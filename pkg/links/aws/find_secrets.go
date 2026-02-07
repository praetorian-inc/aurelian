package aws

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/cloudwatchlogs"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/ec2"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/ecr"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/lambda"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/stepfunctions"
	"github.com/praetorian-inc/aurelian/pkg/scanner"
	"github.com/praetorian-inc/aurelian/pkg/types"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

type AWSFindSecrets struct {
	*base.NativeAWSLink
	clientMap   map[string]interface{} // map key is type-region
}

func NewAWSFindSecrets(args map[string]any) *AWSFindSecrets {
	return &AWSFindSecrets{
		NativeAWSLink: base.NewNativeAWSLink("aws-find-secrets", args),
	}
}


func (fs *AWSFindSecrets) SupportedResourceTypes() []string {
	return []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::Logs::MetricFilter",
		"AWS::Logs::SubscriptionFilter",
		"AWS::Logs::Destination",
		"AWS::ECR::Repository",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
	}
}

func (fs *AWSFindSecrets) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	slog.Debug("Dispatching resource for processing", "resource_type", resource.TypeName, "resource_id", resource.Identifier)

	// Log max-events parameter tracking
	maxEvents := fs.ArgInt("max-events", 0)
	if maxEvents > 0 {
		message.Info("AWSFindSecrets passing max-events: resource_type=%s max_events_value=%d",
			resource.TypeName,
			maxEvents)
	}

	// Create args map for passing to sub-links
	// Include known parameters that sub-links may need
	args := map[string]any{
		"profile":     fs.Profile,
		"profile-dir": fs.ProfileDir,
		"regions":     fs.Regions,
		"max-events":  maxEvents,
	}

	// Process resource based on type and collect outputs
	// Each case represents the chain of operations that would have been in ResourceMap
	var subLinkOutputs []any
	var err error

	switch resource.TypeName {
	case "AWS::EC2::Instance":
		subLinkOutputs, err = ec2.NewAWSEC2UserData(args).Process(ctx, resource)

	case "AWS::Lambda::Function":
		subLinkOutputs, err = lambda.NewAWSLambdaFunctionCode(args).Process(ctx, resource)

	case "AWS::CloudFormation::Stack":
		subLinkOutputs, err = cloudformation.NewAWSCloudFormationTemplates(args).Process(ctx, resource)

	case "AWS::Logs::LogGroup", "AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter", "AWS::Logs::Destination":
		subLinkOutputs, err = cloudwatchlogs.NewAWSCloudWatchLogsEvents(args).Process(ctx, resource)

	case "AWS::ECR::Repository":
		// ECR processing chain: list images -> login -> download -> convert
		subLinkOutputs, err = ecr.NewAWSECRListImages(args).Process(ctx, resource)

	case "AWS::ECS::TaskDefinition", "AWS::SSM::Document":
		// Direct noseyparker conversion (when noseyparker link is migrated)
		// Note: AWS-managed SSM documents are now filtered at listing time (Owner=Self)
		slog.Debug("Resource type needs noseyparker conversion", "type", resource.TypeName)
		subLinkOutputs = nil

	case "AWS::StepFunctions::StateMachine":
		// Step Functions chain: list executions -> get details -> convert
		subLinkOutputs, err = stepfunctions.NewAWSListExecutions(args).Process(ctx, resource)

	default:
		slog.Error("Unsupported resource type", "resource", resource)
		subLinkOutputs = nil
	}

	if err != nil {
		return nil, err
	}

	// Transfer NpInput objects from sub-link outputs to our queue for scanning
	for _, output := range subLinkOutputs {
		if npInput, ok := output.(types.NpInput); ok {
			fs.Send(npInput)
		} else {
			// Keep non-NpInput outputs as-is
			fs.Send(output)
		}
	}

	// Now scan all NpInput objects through Titus
	return fs.scanNpInputs(ctx)
}

// scanNpInputs processes NpInput objects from the outputs queue through Titus scanner
func (fs *AWSFindSecrets) scanNpInputs(ctx context.Context) ([]any, error) {
	outputs := fs.Outputs()

	// If no outputs, return empty slice (not nil)
	if len(outputs) == 0 {
		return []any{}, nil
	}

	// Find NpInput objects in outputs
	var npInputs []types.NpInput
	var otherOutputs []any

	for _, output := range outputs {
		if npInput, ok := output.(types.NpInput); ok {
			npInputs = append(npInputs, npInput)
		} else {
			// Keep non-NpInput outputs
			otherOutputs = append(otherOutputs, output)
		}
	}

	// If no NpInput objects found, return outputs as-is
	if len(npInputs) == 0 {
		return outputs, nil
	}

	// Get datastore path from args (defaults to aurelian-output/titus.db if empty)
	datastore := fs.ArgString("datastore", "aurelian-output/titus.db")

	// Create PersistentScanner with custom datastore path
	persistentScanner, err := scanner.NewPersistentScanner(datastore)
	if err != nil {
		slog.Error("Failed to create Titus scanner", "error", err)
		return outputs, fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if err := persistentScanner.Close(); err != nil {
			slog.Error("Failed to close Titus scanner", "error", err)
		}
	}()

	// Extract verify flag
	verify := fs.ArgBool("verify", false)

	// Initialize validation engine if verify is enabled
	var validationEngine *validator.Engine
	if verify {
		var validators []validator.Validator

		// Add AWS validator
		validators = append(validators, validator.NewAWSValidator())

		// Add embedded YAML validators
		embedded, err := validator.LoadEmbeddedValidators()
		if err == nil {
			validators = append(validators, embedded...)
		} else {
			slog.Warn("Failed to load embedded validators", "error", err)
		}

		validationEngine = validator.NewEngine(4, validators...) // 4 workers
	}

	slog.Info("Scanning NpInput objects through Titus", "count", len(npInputs))

	// Process each NpInput
	var allMatches []*titustypes.Match
	for i, npInput := range npInputs {
		// Get content bytes
		var content []byte
		if npInput.Content != "" {
			content = []byte(npInput.Content)
		} else if npInput.ContentBase64 != "" {
			// Decode base64 content if present
			decoded, err := base64.StdEncoding.DecodeString(npInput.ContentBase64)
			if err != nil {
				slog.Error("Failed to decode base64 content", "error", err, "index", i)
				continue
			}
			content = decoded
		} else {
			// No content to scan
			continue
		}

		// Compute BlobID using Titus types
		blobID := titustypes.ComputeBlobID(content)

		// Convert NpProvenance to Titus Provenance
		// Using ExtendedProvenance to preserve all NpProvenance fields
		provenance := titustypes.ExtendedProvenance{
			Payload: map[string]interface{}{
				"kind":          npInput.Provenance.Kind,
				"platform":      npInput.Provenance.Platform,
				"resource_type": npInput.Provenance.ResourceType,
				"resource_id":   npInput.Provenance.ResourceID,
				"region":        npInput.Provenance.Region,
				"account_id":    npInput.Provenance.AccountID,
				"file_path":     npInput.Provenance.FilePath,
				"repo_path":     npInput.Provenance.RepoPath,
			},
		}

		// Scan content through Titus
		matches, err := persistentScanner.ScanContent(content, blobID, provenance)
		if err != nil {
			slog.Error("Failed to scan content", "error", err, "blob_id", blobID.Hex())
			continue
		}

		if len(matches) > 0 {
			slog.Info("Found secret matches", "blob_id", blobID.Hex(), "match_count", len(matches))
			allMatches = append(allMatches, matches...)
		}
	}

	// Validate matches if verification is enabled
	if validationEngine != nil && len(allMatches) > 0 {
		slog.Info("Validating detected secrets", "count", len(allMatches))

		// Submit all matches for async validation
		results := make([]<-chan *titustypes.ValidationResult, len(allMatches))
		for i := range allMatches {
			results[i] = validationEngine.ValidateAsync(ctx, allMatches[i])
		}

		// Wait for all validations and attach results
		for i, ch := range results {
			result := <-ch
			allMatches[i].ValidationResult = result
		}
	}

	// Build final outputs: original non-NpInput outputs + match results
	finalOutputs := make([]any, 0, len(otherOutputs)+len(allMatches))
	finalOutputs = append(finalOutputs, otherOutputs...)

	// Add matches to outputs
	for _, match := range allMatches {
		finalOutputs = append(finalOutputs, match)
	}

	slog.Info("Completed Titus scanning",
		"np_inputs_scanned", len(npInputs),
		"total_matches", len(allMatches),
		"total_outputs", len(finalOutputs))

	return finalOutputs, nil
}
