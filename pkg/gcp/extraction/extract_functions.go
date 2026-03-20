package extraction

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/api/cloudfunctions/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const maxFunctionZipSize = 250 * 1024 * 1024

var httpClient = &http.Client{Timeout: 10 * time.Minute}

func init() {
	mustRegister("cloudfunctions.googleapis.com/Function", "source", extractFunctionSource)
	mustRegister("cloudfunctions.googleapis.com/Function", "env-vars", extractFunctionEnvVars)
}

// extractFunctionSource downloads the function's source archive, extracts each file,
// and emits individual files for scanning.
func extractFunctionSource(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := cloudfunctions.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloudfunctions client: %w", err)
	}

	resp, err := svc.Projects.Locations.Functions.GenerateDownloadUrl(r.ResourceID, &cloudfunctions.GenerateDownloadUrlRequest{}).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("generating download URL for %s: %w", r.ResourceID, err)
	}

	if resp.DownloadUrl == "" {
		return nil
	}

	return downloadAndExtractZip(r, resp.DownloadUrl, out)
}

// downloadAndExtractZip downloads a zip from the given URL and emits each file as a ScanInput.
func downloadAndExtractZip(r output.GCPResource, downloadURL string, out *pipeline.P[output.ScanInput]) error {
	httpResp, err := httpClient.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("downloading source for %s: %w", r.ResourceID, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxFunctionZipSize))
	if err != nil {
		return fmt.Errorf("reading source for %s: %w", r.ResourceID, err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("opening source zip for %s: %w", r.ResourceID, err)
	}

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || len(content) == 0 {
			continue
		}

		out.Send(output.ScanInputFromGCPResource(r, f.Name, content))
	}
	return nil
}

// extractFunctionEnvVars extracts environment variables from a Gen 1 Cloud Function.
func extractFunctionEnvVars(ctx extractContext, r output.GCPResource, out *pipeline.P[output.ScanInput]) error {
	svc, err := cloudfunctions.NewService(ctx.Context, ctx.ClientOptions...)
	if err != nil {
		return fmt.Errorf("creating cloudfunctions client: %w", err)
	}

	fn, err := svc.Projects.Locations.Functions.Get(r.ResourceID).Context(ctx.Context).Do()
	if err != nil {
		return fmt.Errorf("getting function %s: %w", r.ResourceID, err)
	}

	if len(fn.EnvironmentVariables) == 0 {
		return nil
	}

	var envContent []byte
	for k, v := range fn.EnvironmentVariables {
		envContent = fmt.Appendf(envContent, "%s=%s\n", k, v)
	}
	out.Send(output.ScanInputFromGCPResource(r, "env-vars", envContent))
	return nil
}
