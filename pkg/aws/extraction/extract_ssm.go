package extraction

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::SSM::Document", "ssm-document", extractSSM)
}

func extractSSM(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	docName := r.ResourceID
	if name, ok := r.Properties["Name"].(string); ok && name != "" {
		docName = name
	}

	client := ssm.NewFromConfig(ctx.AWSConfig)
	resp, err := client.GetDocument(ctx.Context, &ssm.GetDocumentInput{
		Name: aws.String(docName),
	})
	if err != nil {
		return fmt.Errorf("GetDocument failed for %s: %w", docName, err)
	}

	if resp.Content == nil || *resp.Content == "" {
		return nil
	}

	out.Send(output.ScanInputFromAWSResource(r, "Document", []byte(*resp.Content)))
	return nil
}
