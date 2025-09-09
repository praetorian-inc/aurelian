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

// NamedOutputData represents the structure that should be sent to the RuntimeJSONOutputter
// It contains both the data to be output and the filename to write it to
type NamedOutputData struct {
	OutputFilename string
	Data           any
}

// NewNamedOutputData creates a new NamedOutputData instance
func NewNamedOutputData(data any, filename string) NamedOutputData {
	return NamedOutputData{
		OutputFilename: filename,
		Data:           data,
	}
}

const defaultOutfile = "out.json"

// RuntimeJSONOutputter allows specifying the output file at runtime
// rather than at initialization time
type RuntimeJSONOutputter struct {
	*BaseFileOutputter
	indent  int
	output  []any
	outfile string
}

// NewRuntimeJSONOutputter creates a new RuntimeJSONOutputter
func NewRuntimeJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &RuntimeJSONOutputter{}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter but doesn't open a file yet
func (j *RuntimeJSONOutputter) Initialize() error {
	// Get output directory
	outputDir, err := cfg.As[string](j.Arg("output"))
	if err != nil {
		outputDir = "nebula-output" // Fallback default
	}

	// Get default output file (can be overridden at runtime)
	outfile, err := cfg.As[string](j.Arg("outfile"))
	if err != nil {
		outfile = defaultOutfile // Fallback default
	}

	// If custom filename provided, prepend with output directory
	if outfile != defaultOutfile {
		// Apply platform-specific enhancement to the filename
		enhancedFilename := j.enhanceFilenameWithPlatformInfo(outfile)
		outfile = filepath.Join(outputDir, enhancedFilename)
		slog.Debug("using enhanced filename with output directory", "original", filepath.Base(enhancedFilename), "enhanced", enhancedFilename)
	} else {
		// Create context-rich filename based on available parameters
		contextualName := j.generateContextualFilename()
		if contextualName != "" {
			outfile = filepath.Join(outputDir, contextualName)
			slog.Debug("using contextual filename", "filename", outfile)
		} else {
			outfile = filepath.Join(outputDir, outfile)
		}
	}

	j.outfile = outfile

	// Ensure output directory exists early to prevent runtime errors
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Get indentation setting
	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 0
	}
	j.indent = indent

	slog.Debug("initialized runtime JSON outputter", "default_file", j.outfile, "indent", j.indent)
	return nil
}

// Output stores a value in memory for later writing
func (j *RuntimeJSONOutputter) Output(val any) error {
	// Check if we received an OutputData structure
	if outputData, ok := val.(NamedOutputData); ok {
		// If filename is provided, update the output file
		if outputData.OutputFilename != "" && j.outfile == defaultOutfile {
			j.SetOutputFile(outputData.OutputFilename)
		}
		// Add the actual data to our output list
		j.output = append(j.output, outputData.Data)
	} else {
		// Handle the original case where just data is provided
		j.output = append(j.output, val)
	}
	return nil
}

// SetOutputFile allows changing the output file at runtime
func (j *RuntimeJSONOutputter) SetOutputFile(filename string) {
	j.outfile = filename
	// Ensure the new path's directory exists
	if err := j.EnsureOutputPath(filename); err != nil {
		slog.Error("failed to create directory for new output file", "filename", filename, "error", err)
	}
	slog.Debug("changed JSON output file", "filename", filename)
}

// Complete writes all stored outputs to the specified file
func (j *RuntimeJSONOutputter) Complete() error {
	// Check for module-specific parameters one more time at completion
	// in case they're available now but weren't during initialization
	if filepath.Base(j.outfile) == defaultOutfile || strings.Contains(j.outfile, "out-") {
		// Get output directory
		outputDir, err := cfg.As[string](j.Arg("output"))
		if err != nil {
			outputDir = "nebula-output" // Fallback default
		}

		// Try to generate a contextual filename now that all parameters are available
		contextualName := j.generateContextualFilename()
		if contextualName != "" && !strings.Contains(contextualName, "out-") {
			j.outfile = filepath.Join(outputDir, contextualName)
			slog.Debug("updated to module-specific filename at completion", "filename", j.outfile)
		}
	}

	slog.Debug("writing JSON output", "filename", j.outfile, "entries", len(j.output))

	// Ensure the directory exists (using base functionality)
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

// generateContextualFilename creates a filename with appropriate context to avoid overwrites
func (j *RuntimeJSONOutputter) generateContextualFilename() string {
	timestamp := time.Now().Format("20060102-150405")

	// Debug all available parameters
	slog.Debug("generateContextualFilename: checking available parameters", "allArgs", j.Args())

	// Get module name if provided by the module
	moduleName, moduleErr := cfg.As[string](j.Arg("module-name"))
	if moduleErr != nil || moduleName == "" {
		moduleName = "recon" // fallback for missing or empty module name
		slog.Debug("module-name not found or empty, using fallback", "fallback", moduleName, "error", moduleErr)
	} else {
		slog.Debug("found module-name parameter", "moduleName", moduleName)
	}

	// Try to infer platform from available parameters
	// AWS parameters - check if profile parameter exists (even if empty)
	if _, err := cfg.As[string](j.Arg("profile")); err == nil {
		// Profile parameter exists (might be empty for env vars), this is an AWS command
		slog.Debug("Found AWS profile parameter, generating AWS filename", "moduleName", moduleName)
		return j.generateAWSFilename(moduleName)
	}

	// Azure parameters - check for tenant ID in output metadata first, then subscription
	if tenantID := j.extractTenantFromMetadata(); tenantID != "" {
		slog.Debug("Found tenant ID in metadata, generating Azure filename", "tenantID", tenantID, "moduleName", moduleName)
		return fmt.Sprintf("%s-%s.json", moduleName, tenantID)
	}
	
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 && subscriptions[0] != "" {
		slog.Debug("Found Azure subscription, generating Azure filename", "subscription", subscriptions[0], "moduleName", moduleName)
		// This is an Azure command
		return j.generateAzureFilename(moduleName)
	}

	// GCP parameters
	if project, err := cfg.As[string](j.Arg("project")); err == nil && project != "" {
		slog.Debug("Found GCP project, generating GCP filename", "project", project, "moduleName", moduleName)
		// This is a GCP command
		return j.generateGCPFilename(moduleName)
	}

	// Fallback to timestamp
	slog.Debug("No platform parameters found, using timestamp fallback")
	return fmt.Sprintf("out-%s.json", timestamp)
}

// generateAWSFilename creates AWS-specific filenames in format: {module-name}-{account}.json
func (j *RuntimeJSONOutputter) generateAWSFilename(moduleName string) string {
	// Get profile name - might be empty when using environment variables
	profile, err := cfg.As[string](j.Arg("profile"))
	if err != nil {
		profile = "" // No profile specified
	}

	// Use consistent cache key logic - empty profile uses "default" as cache key
	cacheKey := profile
	if cacheKey == "" {
		cacheKey = "default"
	}

	// Always try to get account ID from the cached authentication data first
	if accountID := j.getAWSAccountFromCache(cacheKey); accountID != "" {
		slog.Debug("using account ID for filename", "accountID", accountID, "profile", profile, "cacheKey", cacheKey)
		return fmt.Sprintf("%s-%s.json", moduleName, accountID)
	}

	slog.Debug("account ID not found in cache", "profile", profile, "cacheKey", cacheKey)

	// Only use profile name if it's explicitly set (not empty)
	if profile != "" {
		return fmt.Sprintf("%s-%s.json", moduleName, profile)
	}

	// Fallback to module name only when no profile and no account ID
	slog.Debug("using module name only for filename")
	return fmt.Sprintf("%s.json", moduleName)
}

// getAWSAccountFromCache retrieves the AWS account ID from the cached authentication data
func (j *RuntimeJSONOutputter) getAWSAccountFromCache(profile string) string {
	// Access the same ProfileIdentity cache used during authentication
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

// generateAzureFilename creates Azure-specific filenames in format: {module-name}-{subscription}.json
func (j *RuntimeJSONOutputter) generateAzureFilename(moduleName string) string {
	// Handle special DevOps case first
	if devopsOrg, orgErr := cfg.As[string](j.Arg("devops-org")); orgErr == nil && devopsOrg != "" {
		if devopsProject, projErr := cfg.As[string](j.Arg("devops-project")); projErr == nil && devopsProject != "" {
			return fmt.Sprintf("%s-%s-%s.json", moduleName, devopsOrg, devopsProject)
		}
		return fmt.Sprintf("%s-%s.json", moduleName, devopsOrg)
	}

	// Standard Azure subscription format
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 {
		subscription := subscriptions[0]
		if subscription == "all" {
			return fmt.Sprintf("%s-all-subscriptions.json", moduleName)
		}
		return fmt.Sprintf("%s-%s.json", moduleName, subscription)
	}

	// Fallback to module name only
	return fmt.Sprintf("%s.json", moduleName)
}

// generateGCPFilename creates GCP-specific filenames in format: {module-name}-{project}.json
func (j *RuntimeJSONOutputter) generateGCPFilename(moduleName string) string {
	// Try to get GCP project ID
	if projectId, err := cfg.As[string](j.Arg("project")); err == nil && projectId != "" {
		return fmt.Sprintf("%s-%s.json", moduleName, projectId)
	}

	// Fallback to module name only
	return fmt.Sprintf("%s.json", moduleName)
}

// enhanceFilenameWithPlatformInfo adds platform-specific identifiers to the filename before the extension
// Examples: "find-secrets.json" -> "find-secrets-terraform.json", "report.json" -> "report-my-subscription.json"
func (j *RuntimeJSONOutputter) enhanceFilenameWithPlatformInfo(filename string) string {
	// Get the file extension and base name
	ext := filepath.Ext(filename)
	baseName := strings.TrimSuffix(filename, ext)

	// Check for AWS profile parameter (should be available from module's WithInputParam)
	if profile, err := cfg.As[string](j.Arg("profile")); err == nil {
		// Use consistent cache key logic
		cacheKey := profile
		if cacheKey == "" {
			cacheKey = "default"
		}

		// Try to get account ID from the cached authentication data
		if accountID := j.getAWSAccountFromCache(cacheKey); accountID != "" {
			return fmt.Sprintf("%s-%s%s", baseName, accountID, ext)
		}

		// Fallback to profile name if explicitly set and account ID not available
		if profile != "" {
			return fmt.Sprintf("%s-%s%s", baseName, profile, ext)
		}
	}

	// Check for Azure subscription (it's a []string, so get the first one)
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 && subscriptions[0] != "" {
		subscription := subscriptions[0]
		// Handle "all" case or long subscription IDs by truncating/cleaning
		if subscription == "all" {
			return fmt.Sprintf("%s-all-subscriptions%s", baseName, ext)
		}
		// If it looks like a GUID, take just the first part
		if len(subscription) > 8 && strings.Contains(subscription, "-") {
			subscription = strings.Split(subscription, "-")[0]
		}
		return fmt.Sprintf("%s-%s%s", baseName, subscription, ext)
	}

	// TODO: Add GCP project support when available
	// if project, err := cfg.As[string](j.Arg("project")); err == nil && project != "" {
	//     return fmt.Sprintf("%s-%s%s", baseName, project, ext)
	// }

	// No platform info found, return original filename
	return filename
}

// extractTenantFromMetadata looks for tenant ID in the output data metadata
func (j *RuntimeJSONOutputter) extractTenantFromMetadata() string {
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
	if !ok || tenantID == "" || tenantID == "unknown" {
		return ""
	}

	return tenantID
}

// Params defines the parameters accepted by this outputter
func (j *RuntimeJSONOutputter) Params() []cfg.Param {
	// Note: Platform parameters (profile, subscription, project) are passed from modules
	// and accessed via j.Arg() but not declared here to avoid conflicts
	return []cfg.Param{
		cfg.NewParam[string]("outfile", "the default file to write the JSON to (can be changed at runtime)").WithDefault(defaultOutfile),
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(0),
		cfg.NewParam[string]("module-name", "the name of the module for dynamic file naming"),
		options.OutputDir(),
	}
}
