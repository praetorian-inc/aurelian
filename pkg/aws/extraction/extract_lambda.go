package extraction

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"golang.org/x/sync/errgroup"
)

const maxLambdaZipSize = 250 * 1024 * 1024

var httpClient = &http.Client{Timeout: 10 * time.Minute}

func init() {
	mustRegister("AWS::Lambda::Function", "lambda-code", extractLambda)
}

func extractLambda(ctx extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
	client := lambda.NewFromConfig(ctx.AWSConfig)
	functionName := r.ResourceID
	if name, ok := r.Properties["FunctionName"].(string); ok && name != "" {
		functionName = name
	}

	resp, err := client.GetFunction(ctx.Context, &lambda.GetFunctionInput{FunctionName: &functionName})
	if err != nil {
		return fmt.Errorf("GetFunction failed for %s: %w", functionName, err)
	}

	missingCodeLocation := resp.Code == nil || resp.Code.Location == nil || *resp.Code.Location == ""
	if missingCodeLocation {
		return nil
	}

	httpResp, err := httpClient.Get(*resp.Code.Location)
	if err != nil {
		return fmt.Errorf("failed to download Lambda code for %s: %w", functionName, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxLambdaZipSize))
	if err != nil {
		return fmt.Errorf("failed to read Lambda code zip for %s: %w", functionName, err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("failed to open Lambda code zip for %s: %w", functionName, err)
	}

	g := new(errgroup.Group)
	g.SetLimit(ctx.Concurrency)

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		f := f
		g.Go(func() error {
			rc, err := f.Open()
			if err != nil {
				return nil
			}

			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil
			}

			if len(content) == 0 {
				return nil
			}

			si := output.ScanInputFromAWSResource(r, f.Name, content)
			si.PathFilterable = true
			out.Send(si)
			return nil
		})
	}

	return g.Wait()
}
