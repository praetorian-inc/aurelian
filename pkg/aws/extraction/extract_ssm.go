package extraction

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
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

func init() {
	mustRegister("AWS::SSM::Parameter", "ssm-parameter", extractSSMParameter)
}

func extractSSMParameter(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	// Only scan String and StringList parameters. SecureString values are KMS-encrypted;
	// reading plaintext requires both ssm:GetParameter and kms:Decrypt on the key — they
	// represent intentionally secured secrets, not plaintext misuse. Skip anything whose
	// type is unknown or missing: the enumerator always sets Type, so absence signals an
	// unexpected code path that should not proceed to GetParameter.
	t, ok := r.Properties["Type"].(string)
	if !ok || (t != "String" && t != "StringList") {
		return nil
	}

	paramName := r.ResourceID
	if name, ok := r.Properties["Name"].(string); ok && name != "" {
		paramName = name
	}

	client := ssm.NewFromConfig(ctx.AWSConfig)
	resp, err := client.GetParameter(ctx.Context, &ssm.GetParameterInput{
		Name: aws.String(paramName),
	})
	if err != nil {
		return fmt.Errorf("GetParameter failed for %s: %w", paramName, err)
	}

	if resp.Parameter == nil ||
		resp.Parameter.Type == ssmtypes.ParameterTypeSecureString ||
		resp.Parameter.Value == nil ||
		*resp.Parameter.Value == "" {
		return nil
	}

	out.Send(output.ScanInputFromAWSResource(r, "Parameter", []byte(*resp.Parameter.Value)))
	return nil
}
