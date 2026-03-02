package secrets

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// CFNClient is the subset of the CloudFormation API needed by the CFN extractor.
type CFNClient interface {
	GetTemplate(
		ctx context.Context,
		input *cloudformation.GetTemplateInput,
		opts ...func(*cloudformation.Options),
	) (*cloudformation.GetTemplateOutput, error)
}

// extractCFN fetches a CloudFormation stack's template and emits it as a ScanInput.
func extractCFN(cfg ExtractorConfig, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	awsCfg, err := cfg.AWSConfigFactory(r.Region)
	if err != nil {
		return fmt.Errorf("failed to create AWS config: %w", err)
	}
	client := cloudformation.NewFromConfig(awsCfg)
	return extractCFNWithClient(client, r, out)
}

// extractCFNWithClient is the testable core of the CFN extractor.
func extractCFNWithClient(client CFNClient, r output.AWSResource, out *pipeline.P[ScanInput]) error {
	stackName := r.ResourceID
	if name, ok := r.Properties["StackName"].(string); ok && name != "" {
		stackName = name
	}

	resp, err := client.GetTemplate(context.Background(), &cloudformation.GetTemplateInput{
		StackName: &stackName,
	})
	if err != nil {
		return fmt.Errorf("GetTemplate failed for %s: %w", stackName, err)
	}

	if resp.TemplateBody == nil || *resp.TemplateBody == "" {
		return nil
	}

	out.Send(ScanInput{
		Content:      []byte(*resp.TemplateBody),
		ResourceID:   r.ResourceID,
		ResourceType: r.ResourceType,
		Region:       r.Region,
		AccountID:    r.AccountRef,
		Label:        "template.yaml",
	})

	return nil
}
