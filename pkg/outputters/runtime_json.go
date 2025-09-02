package outputters

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type NamedOutputData struct {
	OutputFilename string
	Data           any
}

func NewNamedOutputData(data any, filename string) NamedOutputData {
	return NamedOutputData{
		OutputFilename: filename,
		Data:           data,
	}
}

const defaultOutfile = "out.json"

type RuntimeJSONOutputter struct {
	*BaseFileOutputter
	indent  int
	output  []any
	outfile string
}

func NewRuntimeJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &RuntimeJSONOutputter{}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

func (j *RuntimeJSONOutputter) Initialize() error {
	outputDir, err := cfg.As[string](j.Arg("output"))
	if err != nil {
		outputDir = "nebula-output"
	}

	outfile, err := cfg.As[string](j.Arg("outfile"))
	if err != nil {
		outfile = defaultOutfile
	}

	if outfile != defaultOutfile {
		enhancedFilename := j.enhanceFilenameWithPlatformInfo(outfile)
		outfile = filepath.Join(outputDir, enhancedFilename)
		slog.Debug("using enhanced filename with output directory", "original", filepath.Base(enhancedFilename), "enhanced", enhancedFilename)
	} else {
		contextualName := j.generateContextualFilename()
		if contextualName != "" {
			outfile = filepath.Join(outputDir, contextualName)
			slog.Debug("using contextual filename", "filename", outfile)
		} else {
			outfile = filepath.Join(outputDir, outfile)
		}
	}

	j.outfile = outfile

	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 0
	}
	j.indent = indent

	slog.Debug("initialized runtime JSON outputter", "default_file", j.outfile, "indent", j.indent)
	return nil
}

func (j *RuntimeJSONOutputter) Output(val any) error {
	if outputData, ok := val.(NamedOutputData); ok {
		if outputData.OutputFilename != "" && j.outfile == defaultOutfile {
			j.SetOutputFile(outputData.OutputFilename)
		}
		j.output = append(j.output, outputData.Data)
	} else {
		j.output = append(j.output, val)
	}
	return nil
}

func (j *RuntimeJSONOutputter) SetOutputFile(filename string) {
	j.outfile = filename
	if err := j.EnsureOutputPath(filename); err != nil {
		slog.Error("failed to create directory for new output file", "filename", filename, "error", err)
	}
	slog.Debug("changed JSON output file", "filename", filename)
}

func (j *RuntimeJSONOutputter) Complete() error {
	// Check if we should try to improve the filename with more specific naming
	shouldUpdateFilename := filepath.Base(j.outfile) == defaultOutfile || 
		strings.Contains(j.outfile, "out-") ||
		strings.Contains(filepath.Base(j.outfile), "20") // timestamp-based filename pattern
	
	if shouldUpdateFilename {
		outputDir, err := cfg.As[string](j.Arg("output"))
		if err != nil {
			outputDir = "nebula-output"
		}

		// First try tenant-based filename (highest priority)
		tenantFilename := j.generateTenantBasedFilename(outputDir)
		if tenantFilename != "" {
			j.outfile = tenantFilename
			slog.Debug("updated to tenant-based filename at completion", "filename", j.outfile)
		} else {
			// Fall back to contextual filename
			contextualName := j.generateContextualFilename()
			if contextualName != "" && !strings.Contains(contextualName, "out-") {
				j.outfile = filepath.Join(outputDir, contextualName)
				slog.Debug("updated to module-specific filename at completion", "filename", j.outfile)
			}
		}
	}

	slog.Debug("writing JSON output", "filename", j.outfile, "entries", len(j.output))

	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("error creating directory for JSON file %s: %w", j.outfile, err)
	}

	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating JSON file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	err = encoder.Encode(j.output)
	if err != nil {
		return err
	}

	message.Success("JSON output written to: %s", j.outfile)
	return nil
}

func (j *RuntimeJSONOutputter) generateContextualFilename() string {
	timestamp := time.Now().Format("20060102-150405")

	slog.Debug("generateContextualFilename: checking available parameters", "allArgs", j.Args())

	moduleName, moduleErr := cfg.As[string](j.Arg("module-name"))
	if moduleErr != nil || moduleName == "" {
		moduleName = "recon"
		slog.Debug("module-name not found or empty, using fallback", "fallback", moduleName, "error", moduleErr)
	} else {
		slog.Debug("found module-name parameter", "moduleName", moduleName)
	}

	if _, err := cfg.As[string](j.Arg("profile")); err == nil {
		slog.Debug("Found AWS profile parameter, generating AWS filename", "moduleName", moduleName)
		return j.generateAWSFilename(moduleName)
	}

	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 && subscriptions[0] != "" {
		slog.Debug("Found Azure subscription, generating Azure filename", "subscription", subscriptions[0], "moduleName", moduleName)
		return j.generateAzureFilename(moduleName)
	}

	if project, err := cfg.As[string](j.Arg("project")); err == nil && project != "" {
		slog.Debug("Found GCP project, generating GCP filename", "project", project, "moduleName", moduleName)
		return j.generateGCPFilename(moduleName)
	}

	slog.Debug("No platform parameters found, using timestamp fallback")
	return fmt.Sprintf("%s-%s.json", moduleName, timestamp)
}

func (j *RuntimeJSONOutputter) generateAWSFilename(moduleName string) string {
	profile, err := cfg.As[string](j.Arg("profile"))
	if err != nil {
		profile = ""
	}

	cacheKey := profile
	if cacheKey == "" {
		cacheKey = "default"
	}

	if accountID := j.getAWSAccountFromCache(cacheKey); accountID != "" {
		slog.Debug("using account ID for filename", "accountID", accountID, "profile", profile, "cacheKey", cacheKey)
		return fmt.Sprintf("%s-%s.json", moduleName, accountID)
	}

	slog.Debug("account ID not found in cache", "profile", profile, "cacheKey", cacheKey)

	if profile != "" {
		return fmt.Sprintf("%s-%s.json", moduleName, profile)
	}

	slog.Debug("using module name only for filename")
	return fmt.Sprintf("%s.json", moduleName)
}

func (j *RuntimeJSONOutputter) getAWSAccountFromCache(profile string) string {
	slog.Debug("looking up profile in cache", "profile", profile)
	if value, ok := helpers.ProfileIdentity.Load(profile); ok {
		slog.Debug("found profile in cache", "profile", profile)
		if principal, ok := value.(sts.GetCallerIdentityOutput); ok && principal.Account != nil {
			accountID := *principal.Account
			slog.Debug("extracted account ID from cache", "accountID", accountID, "profile", profile)
			return accountID
		} else {
			slog.Debug("failed to extract account ID from cached principal", "profile", profile)
		}
	} else {
		slog.Debug("profile not found in cache", "profile", profile)
	}
	return ""
}

func (j *RuntimeJSONOutputter) generateAzureFilename(moduleName string) string {
	if devopsOrg, orgErr := cfg.As[string](j.Arg("devops-org")); orgErr == nil && devopsOrg != "" {
		if devopsProject, projErr := cfg.As[string](j.Arg("devops-project")); projErr == nil && devopsProject != "" {
			return fmt.Sprintf("%s-%s-%s.json", moduleName, devopsOrg, devopsProject)
		}
		return fmt.Sprintf("%s-%s.json", moduleName, devopsOrg)
	}

	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 {
		subscription := subscriptions[0]
		if subscription == "all" {
			return fmt.Sprintf("%s-all-subscriptions.json", moduleName)
		}
		return fmt.Sprintf("%s-%s.json", moduleName, subscription)
	}

	return fmt.Sprintf("%s.json", moduleName)
}

func (j *RuntimeJSONOutputter) generateTenantBasedFilename(outputDir string) string {
	// Get module name
	moduleName, err := cfg.As[string](j.Arg("module-name"))
	if err != nil || moduleName == "" {
		return ""
	}

	// Check if we have any output data
	if len(j.output) == 0 {
		return ""
	}

	// Check if the first output item has metadata with tenant ID
	firstOutput := j.output[0]
	outputMap, ok := firstOutput.(map[string]any)
	if !ok {
		return ""
	}

	metadata, ok := outputMap["metadata"].(map[string]any)
	if !ok {
		return ""
	}

	tenantID, ok := metadata["tenantId"].(string)
	if !ok || tenantID == "" {
		// No tenant ID in metadata, return empty to fall back to other naming
		return ""
	}

	// Generate tenant-based filename automatically when tenant ID is present
	filename := fmt.Sprintf("%s-%s.json", moduleName, tenantID)
	fullPath := filepath.Join(outputDir, filename)

	slog.Debug("generated tenant-based filename", "moduleName", moduleName, "tenantId", tenantID, "filename", filename)
	return fullPath
}

func (j *RuntimeJSONOutputter) generateGCPFilename(moduleName string) string {
	if projectId, err := cfg.As[string](j.Arg("project")); err == nil && projectId != "" {
		return fmt.Sprintf("%s-%s.json", moduleName, projectId)
	}

	return fmt.Sprintf("%s.json", moduleName)
}

func (j *RuntimeJSONOutputter) enhanceFilenameWithPlatformInfo(filename string) string {
	ext := filepath.Ext(filename)
	baseName := strings.TrimSuffix(filename, ext)

	if profile, err := cfg.As[string](j.Arg("profile")); err == nil {
		cacheKey := profile
		if cacheKey == "" {
			cacheKey = "default"
		}

		if accountID := j.getAWSAccountFromCache(cacheKey); accountID != "" {
			return fmt.Sprintf("%s-%s%s", baseName, accountID, ext)
		}

		if profile != "" {
			return fmt.Sprintf("%s-%s%s", baseName, profile, ext)
		}
	}

	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 && subscriptions[0] != "" {
		subscription := subscriptions[0]
		if subscription == "all" {
			return fmt.Sprintf("%s-all-subscriptions%s", baseName, ext)
		}

		if len(subscription) > 8 && strings.Contains(subscription, "-") {
			subscription = strings.Split(subscription, "-")[0]
		}
		return fmt.Sprintf("%s-%s%s", baseName, subscription, ext)
	}

	return filename
}

func (j *RuntimeJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("outfile", "the default file to write the JSON to (can be changed at runtime)").WithDefault(defaultOutfile),
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(0),
		cfg.NewParam[string]("module-name", "the name of the module for dynamic file naming"),
		options.OutputDir(),
	}
}
