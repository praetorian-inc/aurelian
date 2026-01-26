package applications

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/cloudfunctions/v1"
)

// FILE INFO:
// GcpFunctionInfoLink - get info of a single cloud function, Process(functionName string); needs project and region
// GcpFunctionListLink - list all cloud functions in a project, Process(resource tab.GCPResource)
// GcpFunctionSecretsLink - extract secrets from a cloud function, Process(input tab.GCPResource)

type GcpFunctionInfoLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
	ProjectId        string
	Region           string
}

// creates a link to get info of a single cloud function
func NewGcpFunctionInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpFunctionInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFunctionInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		options.GcpRegion(),
	)
	return params
}

func (g *GcpFunctionInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.functionsService, err = cloudfunctions.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud functions service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	region, err := cfg.As[string](g.Arg("region"))
	if err != nil {
		return fmt.Errorf("failed to get region: %w", err)
	}
	g.Region = region
	return nil
}

func (g *GcpFunctionInfoLink) Process(functionName string) error {
	functionPath := fmt.Sprintf("projects/%s/locations/%s/functions/%s", g.ProjectId, g.Region, functionName)
	function, err := g.functionsService.Projects.Locations.Functions.Get(functionPath).Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to get function")
	}
	gcpFunction, err := tab.NewGCPResource(
		function.Name,                     // resource name
		g.ProjectId,                       // accountRef (project ID)
		tab.GCPResourceFunction,           // resource type
		linkPostProcessFunction(function), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP function resource: %w", err)
	}
	gcpFunction.DisplayName = function.Name
	g.Send(gcpFunction)
	return nil
}

type GcpFunctionListLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
}

// creates a link to list all cloud functions in a project
func NewGcpFunctionListLink(configs ...cfg.Config) chain.Link {
	g := &GcpFunctionListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFunctionListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.functionsService, err = cloudfunctions.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud functions service: %w", err)
	}
	return nil
}

func (g *GcpFunctionListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	parent := fmt.Sprintf("projects/%s/locations/%s", resource.Name, "-")
	listReq := g.functionsService.Projects.Locations.Functions.List(parent)
	err := listReq.Pages(context.Background(), func(page *cloudfunctions.ListFunctionsResponse) error {
		for _, function := range page.Functions {
			slog.Debug("Found function", "function", function.Name)
			properties := linkPostProcessFunction(function)

			// Check IAM policy for anonymous access
			policy, policyErr := g.functionsService.Projects.Locations.Functions.GetIamPolicy(function.Name).Do()
			if policyErr == nil && policy != nil {
				anonymousInfo := checkFunctionAnonymousAccess(policy)
				if anonymousInfo.TotalPublicBindings > 0 {
					properties["anonymousAccessInfo"] = anonymousInfo
					properties["riskLevel"] = calculateRiskLevel(anonymousInfo)
				}
			} else {
				slog.Debug("Failed to get IAM policy for function", "function", function.Name, "error", policyErr)
			}

			gcpFunction, err := tab.NewGCPResource(
				function.Name,           // resource name
				resource.Name,           // accountRef (project ID)
				tab.GCPResourceFunction, // resource type
				properties,              // properties (with anonymous access info)
			)
			if err != nil {
				slog.Error("Failed to create GCP function resource", "error", err, "function", function.Name)
				continue
			}
			gcpFunction.DisplayName = function.Name
			g.Send(gcpFunction)
		}
		return nil
	})
	return common.HandleGcpError(err, "failed to list functions in location")
}

type GcpFunctionSecretsLink struct {
	*base.GcpBaseLink
	functionsService *cloudfunctions.Service
}

// creates a link to scan cloud function for secrets
func NewGcpFunctionSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpFunctionSecretsLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpFunctionSecretsLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.functionsService, err = cloudfunctions.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud functions service: %w", err)
	}
	return nil
}

func (g *GcpFunctionSecretsLink) Process(input tab.GCPResource) error {
	if input.ResourceType != tab.GCPResourceFunction {
		return nil
	}
	fn, err := g.functionsService.Projects.Locations.Functions.Get(input.Name).Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to get cloud function for secrets extraction")
	}
	if len(fn.EnvironmentVariables) > 0 {
		if content, err := json.Marshal(fn.EnvironmentVariables); err == nil {
			g.Send(jtypes.NPInput{
				Content: string(content),
				Provenance: jtypes.NPProvenance{
					Platform:     "gcp",
					ResourceType: fmt.Sprintf("%s::EnvVariables", tab.GCPResourceFunction.String()),
					ResourceID:   input.Name,
					Region:       input.Region,
					AccountID:    input.AccountRef,
				},
			})
		}
	}
	if fn.SourceArchiveUrl != "" {
		if err := g.scanFunctionSourceCode(fn.SourceArchiveUrl, input); err != nil {
			slog.Error("Failed to scan function source code", "error", err, "function", input.Name)
		}
	}
	return nil
}

func (g *GcpFunctionSecretsLink) scanFunctionSourceCode(sourceArchiveUrl string, input tab.GCPResource) error {
	resp, err := http.Get(sourceArchiveUrl)
	if err != nil {
		return fmt.Errorf("failed to download source archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download source archive: status %d", resp.StatusCode)
	}
	archiveData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read archive data: %w", err)
	}
	if err := g.extractAndScanZipFiles(archiveData, input); err != nil {
		return fmt.Errorf("failed to extract and scan files: %w", err)
	}
	return nil
}

func (g *GcpFunctionSecretsLink) extractAndScanZipFiles(archiveData []byte, input tab.GCPResource) error {
	reader, err := zip.NewReader(bytes.NewReader(archiveData), int64(len(archiveData)))
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() || g.isSkippableFile(file.Name) {
			continue
		}
		if file.UncompressedSize64 > 1*1024*1024 {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			slog.Error("Failed to open file in archive", "file", file.Name, "error", err)
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			slog.Error("Failed to read file content", "file", file.Name, "error", err)
			continue
		}
		g.Send(jtypes.NPInput{
			Content: string(content),
			Provenance: jtypes.NPProvenance{
				Platform:     "gcp",
				ResourceType: fmt.Sprintf("%s::SourceCode", tab.GCPResourceFunction.String()),
				ResourceID:   fmt.Sprintf("%s/%s", input.Name, file.Name),
				Region:       input.Region,
				AccountID:    input.AccountRef,
			},
		})
	}

	return nil
}

// doing this for heurestic purposes, np might already be removing
func (g *GcpFunctionSecretsLink) isSkippableFile(filename string) bool {
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".jar", ".war", ".ear",
		".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp",
		".mp3", ".wav", ".mp4", ".avi", ".mov", ".mkv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".pyc", ".pyo", ".class", ".o", ".obj",
	}
	lowerFilename := strings.ToLower(filename)
	for _, ext := range binaryExtensions {
		if strings.HasSuffix(lowerFilename, ext) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------------------------------------
// helper functions

// checkFunctionAnonymousAccess checks if a Cloud Function has anonymous access via IAM
func checkFunctionAnonymousAccess(policy *cloudfunctions.Policy) AnonymousAccessInfo {
	info := AnonymousAccessInfo{
		AllUsersRoles:              []string{},
		AllAuthenticatedUsersRoles: []string{},
		AccessMethods:              []string{},
	}

	if policy == nil || len(policy.Bindings) == 0 {
		return info
	}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == "allUsers" {
				info.HasAllUsers = true
				info.AllUsersRoles = append(info.AllUsersRoles, binding.Role)
				info.TotalPublicBindings++
			} else if member == "allAuthenticatedUsers" {
				info.HasAllAuthenticatedUsers = true
				info.AllAuthenticatedUsersRoles = append(info.AllAuthenticatedUsersRoles, binding.Role)
				info.TotalPublicBindings++
			}
		}
	}

	if info.TotalPublicBindings > 0 {
		info.AccessMethods = append(info.AccessMethods, "IAM")
	}

	return info
}

func linkPostProcessFunction(function *cloudfunctions.CloudFunction) map[string]any {
	properties := map[string]any{
		"name":                 function.Name,
		"description":          function.Description,
		"status":               function.Status,
		"version":              strconv.FormatInt(function.VersionId, 10),
		"entryPoint":           function.EntryPoint,
		"runtime":              function.Runtime,
		"serviceAccountEmail":  function.ServiceAccountEmail,
		"labels":               function.Labels,
		"environmentVariables": function.EnvironmentVariables,
		"maxInstances":         function.MaxInstances,
		"minInstances":         function.MinInstances,
		"vpcConnector":         function.VpcConnector,
		"ingressSettings":      function.IngressSettings,
	}
	if function.HttpsTrigger != nil && function.HttpsTrigger.Url != "" {
		properties["publicURL"] = function.HttpsTrigger.Url
	}
	return properties
}
