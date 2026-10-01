package extraction

import (
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("AWS::SSM::Document", "ssm-document", extractSSM)
}

// extractSSM scans every version of an SSM document, not only the default:
// any version is readable with GetDocument, so a secret removed from the
// default can still be exposed by an older or newer one. Each version is
// emitted with ResourceID "<document ARN>:<version>" so findings record which
// version holds the secret. A version whose GetDocument fails is logged and
// skipped; a ListDocumentVersions failure fails the extractor.
func extractSSM(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	docName := r.ResourceID
	if name, ok := r.Properties["Name"].(string); ok && name != "" {
		docName = name
	}

	client := ssm.NewFromConfig(ctx.AWSConfig)
	paginator := ssm.NewListDocumentVersionsPaginator(client, &ssm.ListDocumentVersionsInput{
		Name: aws.String(docName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx.Context)
		if err != nil {
			return fmt.Errorf("ListDocumentVersions failed for %s: %w", docName, err)
		}
		for _, v := range page.DocumentVersions {
			extractSSMDocumentVersion(ctx, client, r, docName, aws.ToString(v.DocumentVersion), out)
		}
	}
	return nil
}

func extractSSMDocumentVersion(ctx extractContext, client *ssm.Client, r output.AWSResource, docName, version string, out *pipeline.P[output.ScanInput]) {
	resp, err := client.GetDocument(ctx.Context, &ssm.GetDocumentInput{
		Name:            aws.String(docName),
		DocumentVersion: aws.String(version),
	})
	if err != nil {
		slog.Warn("GetDocument failed for document version, skipping version", "arn", r.ARN, "version", version, "error", err)
		return
	}

	if resp.Content == nil || *resp.Content == "" {
		return
	}

	in := output.ScanInputFromAWSResource(r, "Document version "+version, []byte(*resp.Content))
	in.ResourceID = r.ARN + ":" + version
	out.Send(in)
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
