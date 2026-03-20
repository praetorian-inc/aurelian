package extraction

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::CloudFormation::Stack", "cfn-template", extractCFN)
}

func extractCFN(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	client := cloudformation.NewFromConfig(ctx.AWSConfig)
	stackName := r.ResourceID
	if name, ok := r.Properties["StackName"].(string); ok && name != "" {
		stackName = name
	}

	resp, err := client.GetTemplate(ctx.Context, &cloudformation.GetTemplateInput{StackName: &stackName})
	if err != nil {
		return fmt.Errorf("GetTemplate failed for %s: %w", stackName, err)
	}

	missingTemplate := resp.TemplateBody == nil || *resp.TemplateBody == ""
	if missingTemplate {
		return nil
	}

	out.Send(output.ScanInputFromAWSResource(r, "template.yaml", []byte(*resp.TemplateBody)))
	return nil
}
