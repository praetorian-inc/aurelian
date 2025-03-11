package lambda

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSLambdaFunctionCode struct {
	*base.AwsReconLink
}

func NewAWSLambdaFunctionCode(configs ...cfg.Config) chain.Link {
	lambda := &AWSLambdaFunctionCode{}
	lambda.AwsReconLink = base.NewAwsReconLink(lambda, configs...)
	return lambda
}

func (l *AWSLambdaFunctionCode) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::Lambda::Function" {
		slog.Debug("Skipping non-Lambda function code", "resource", resource.TypeName)
		return nil
	}

	codeReader, err := l.downloadCode(resource)
	if err != nil {
		slog.Error("Failed to download code", "error", err)
		return nil
	}

	for _, file := range codeReader.File {
		err := l.processFile(resource, file)
		if err != nil {
			slog.Error("Failed to process file", "error", err)
			return nil
		}
	}

	return nil
}

func (l *AWSLambdaFunctionCode) downloadCode(resource *types.EnrichedResourceDescription) (*zip.Reader, error) {
	config, err := l.GetConfig(resource.Region, options.JanusParamAdapter(l.Params()))
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", resource.Region, err)
	}

	lambdaClient := lambda.NewFromConfig(config)

	getFuncInput := &lambda.GetFunctionInput{
		FunctionName: aws.String(resource.Identifier),
	}

	funcOutput, err := lambdaClient.GetFunction(l.Context(), getFuncInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get function %s: %w", resource.Identifier, err)
	}

	if funcOutput.Code == nil || funcOutput.Code.Location == nil {
		return nil, fmt.Errorf("no code found for function %s", resource.Identifier)
	}

	resp, err := http.Get(*funcOutput.Code.Location)
	if err != nil {
		return nil, fmt.Errorf("failed to download code for function %s: %w", resource.Identifier, err)
	}
	defer resp.Body.Close()

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read code for function %s: %w", resource.Identifier, err)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip for function %s: %w", resource.Identifier, err)
	}

	return zipReader, nil
}

func (l *AWSLambdaFunctionCode) processFile(resource *types.EnrichedResourceDescription, file *zip.File) error {
	if file.FileInfo().IsDir() {
		return nil
	}

	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file %s in function %s: %w", file.Name, resource.Identifier, err)
	}

	content, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return fmt.Errorf("failed to read file %s in function %s: %w", file.Name, resource.Identifier, err)
	}

	if len(content) == 0 {
		slog.Debug("Skipping empty file", "file", file.Name, "resource", resource.Identifier)
		return nil
	}

	return l.Send(&jtypes.NPInput{
		ContentBase64: base64.StdEncoding.EncodeToString(content),
		Provenance: jtypes.NPProvenance{
			Platform:     "aws",
			ResourceType: fmt.Sprintf("%s::Code", resource.TypeName),
			ResourceID:   resource.Arn.String(),
		},
	})
}
