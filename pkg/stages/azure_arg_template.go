// pkg/stages/azure_arg_template.go
package stages

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"encoding/json"
	"path/filepath"
	"time"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"gopkg.in/yaml.v3"
	
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/internal/message"
    "github.com/praetorian-inc/nebula/pkg/templates"
)

// LoadARGTemplates loads ARG query templates from a directory
func LoadARGTemplates(templateDir string) (*types.ARGTemplateLoader, error) {
	loader := &types.ARGTemplateLoader{}

	// If the path is not absolute, make it relative to current directory
	if !filepath.IsAbs(templateDir) {
		currentDir, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %v", err)
		}
		templateDir = filepath.Join(currentDir, templateDir)
	}

	// Check if directory exists
	dirInfo, err := os.Stat(templateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("template directory '%s' does not exist", templateDir)
		}
		return nil, fmt.Errorf("failed to access template directory: %v", err)
	}

	if !dirInfo.IsDir() {
		return nil, fmt.Errorf("'%s' is not a directory", templateDir)
	}
	
	// Find all .yaml files in template directory
	files, err := filepath.Glob(filepath.Join(templateDir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to list template files: %v", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no template files (*.yaml) found in directory '%s'", templateDir)
	}

	// Load each template file
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file %s: %v", file, err)
		}

		var template types.ARGQueryTemplate
		if err := yaml.Unmarshal(data, &template); err != nil {
			return nil, fmt.Errorf("failed to parse template file %s: %v", file, err)
		}

		// Validate template
		if err := validateTemplate(&template); err != nil {
			return nil, fmt.Errorf("invalid template %s: %v", file, err)
		}

		loader.Templates = append(loader.Templates, &template)
	}

	return loader, nil
}

// validateTemplate performs basic validation of a template
func validateTemplate(template *types.ARGQueryTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Query == "" {
		return fmt.Errorf("template query is required")
	}
	return nil
}

// AzureARGTemplateStage executes ARG queries from templates
func AzureARGTemplateStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *types.ARGQueryResult {
    logger := logs.NewStageLogger(ctx, opts, "AzureARGTemplateStage")
    out := make(chan *types.ARGQueryResult)

    go func() {
        defer close(out)

        // Initialize ARG client
        argClient, err := helpers.NewARGClient(ctx)
        if err != nil {
            logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
            return
        }

        // Initialize template loader with embedded templates
        loader, err := templates.NewTemplateLoader()
        if err != nil {
            logger.Error("Failed to initialize template loader", slog.String("error", err.Error()))
            return
        }

        // Load user-supplied templates if directory is provided
        userTemplateDir := options.GetOptionByName(options.AzureARGTemplatesDirOpt.Name, opts).Value
        if userTemplateDir != "" {
            if err := loader.LoadUserTemplates(userTemplateDir); err != nil {
                logger.Error("Failed to load user templates", 
                    slog.String("directory", userTemplateDir),
                    slog.String("error", err.Error()))
                return
            }
        }

        templateList := loader.GetTemplates()
        if len(templateList) == 0 {
            logger.Error("No templates found")
            return
        }

        for subscription := range in {
            message.Info("Processing subscription %s", subscription)

            // Execute each template
            for _, template := range templateList {
                message.Info("Executing template %s: %s", template.ID, template.Name)

                queryOpts := &helpers.ARGQueryOptions{
                    Subscriptions: []string{subscription},
                }

                err = argClient.ExecutePaginatedQuery(ctx, template.Query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
                    if response == nil || response.Data == nil {
                        return nil
                    }

                    rows, ok := response.Data.([]interface{})
                    if !ok {
                        return fmt.Errorf("unexpected response data type")
                    }

                    for _, row := range rows {
                        item, ok := row.(map[string]interface{})
                        if !ok {
                            continue
                        }

                        // Create standardized result
                        result := &types.ARGQueryResult{
                            TemplateID:      template.ID,
                            TemplateDetails: template,
                            ResourceID:      helpers.SafeGetString(item, "id"),
                            ResourceName:    helpers.SafeGetString(item, "name"),
                            ResourceType:    helpers.SafeGetString(item, "type"),
                            Location:        helpers.SafeGetString(item, "location"),
                            SubscriptionID:  subscription,
                        }

                        // Extract additional properties
                        result.Properties = make(map[string]interface{})
                        for k, v := range item {
                            if k != "id" && k != "name" && k != "type" && k != "location" {
                                result.Properties[k] = v
                            }
                        }

                        select {
                        case out <- result:
                        case <-ctx.Done():
                            return nil
                        }
                    }
                    return nil
                })

                if err != nil {
                    logger.Error("Failed to execute template",
                        slog.String("template_id", template.ID),
                        slog.String("error", err.Error()))
                }
            }
        }
    }()

    return out
}


func FormatARGReconOutput(ctx context.Context, opts []*types.Option, in <-chan *types.ARGQueryResult) <-chan types.Result {
    out := make(chan types.Result)

    go func() {
        defer close(out)

        // Group results by template
        resultsByTemplate := make(map[string][]*types.ARGQueryResult)
        for result := range in {
            resultsByTemplate[result.TemplateID] = append(resultsByTemplate[result.TemplateID], result)
        }

        // Generate base filename
        baseFilename := ""
        providedFilename := options.GetOptionByName(options.FileNameOpt.Name, opts).Value
        if len(providedFilename) == 0 {
            timestamp := strconv.FormatInt(time.Now().Unix(), 10)
            baseFilename = fmt.Sprintf("arg-findings-%s", timestamp)
        } else {
            baseFilename = providedFilename
        }

        // Output JSON format - simplified template details
        jsonOutput := make(map[string]interface{})
        for templateID, results := range resultsByTemplate {
            if len(results) == 0 || results[0].TemplateDetails == nil {
                continue
            }

            jsonOutput[templateID] = map[string]interface{}{
                "templateName": results[0].TemplateDetails.Name,
                "templateDescription": results[0].TemplateDetails.Description,
                "findings": results,
            }
        }

        out <- types.NewResult(
            modules.Azure,
            "arg-scan",
            jsonOutput,
            types.WithFilename(baseFilename+".json"),
        )

        // Create markdown report
        var mdContent strings.Builder
        mdContent.WriteString("Azure Resource Graph Scan Results\n---\n")
        
        foundIssues := false
        for templateID, results := range resultsByTemplate {
            if len(results) == 0 || results[0].TemplateDetails == nil {
                continue
            }

            template := results[0].TemplateDetails
            
            // Only create section if there are findings
            if len(results) > 0 {
                foundIssues = true
                mdContent.WriteString(fmt.Sprintf("## %s\n\n", template.Name))
                mdContent.WriteString(fmt.Sprintf("**Description:** %s\n\n", template.Description))
                mdContent.WriteString(fmt.Sprintf("**Severity:** %s\n\n", template.Severity))
				mdContent.WriteString(fmt.Sprintf("**Template ID:** %s\n\n", templateID))
                
                // Create findings table
                mdContent.WriteString("### Findings\n\n")
                mdContent.WriteString("| Resource Name | Resource Type | Location | Details |\n")
                mdContent.WriteString("|--------------|---------------|----------|----------|\n")
                
                for _, result := range results {
                    details := formatResultDetails(result.Properties)
                    mdContent.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
                        result.ResourceName,
                        result.ResourceType,
                        result.Location,
                        details,
                    ))
                }
                mdContent.WriteString("\n")

                // Add triage notes after table if they exist
                if template.TriageNotes != "" {
                    mdContent.WriteString("### Triage Guide\n\n")
                    mdContent.WriteString("```\n")
                    mdContent.WriteString(template.TriageNotes)
                    mdContent.WriteString("\n```\n\n")
                }

                // Add references if they exist
                if len(template.References) > 0 {
                    mdContent.WriteString("### References\n\n")
                    for _, ref := range template.References {
                        mdContent.WriteString(fmt.Sprintf("- %s\n", ref))
                    }
                    mdContent.WriteString("\n")
                }

				mdContent.WriteString("---\n")
            }
        }

        if !foundIssues {
            mdContent.WriteString("No issues found.\n")
        }

        out <- types.NewResult(
            modules.Azure,
            "arg-scan",
            types.MarkdownTable{
                TableHeading: mdContent.String(),
                Headers:     []string{},
                Rows:       [][]string{},
            },
            types.WithFilename(baseFilename+".md"),
        )
    }()

    return out
}

// Helper function to format result details
func formatResultDetails(properties map[string]interface{}) string {
    var details []string
    for k, v := range properties {
        // Format values based on type
        var valueStr string
        switch val := v.(type) {
        case []interface{}, map[string]interface{}:
            // Convert complex types to JSON
            if jsonBytes, err := json.Marshal(val); err == nil {
                valueStr = string(jsonBytes)
            } else {
                valueStr = fmt.Sprintf("%v", val)
            }
        default:
            valueStr = fmt.Sprintf("%v", val)
        }
        details = append(details, fmt.Sprintf("%s: %s", k, valueStr))
    }
    return strings.Join(details, "; ")
}

// formatMarkdownTable converts a MarkdownTable struct into a string representation
func formatMarkdownTable(table *types.MarkdownTable) string {
    var sb strings.Builder

    // Write headers
    sb.WriteString("| ")
    sb.WriteString(strings.Join(table.Headers, " | "))
    sb.WriteString(" |\n")

    // Write separator
    sb.WriteString("| ")
    for range table.Headers {
        sb.WriteString("--- | ")
    }
    sb.WriteString("\n")

    // Write rows
    for _, row := range table.Rows {
        sb.WriteString("| ")
        sb.WriteString(strings.Join(row, " | "))
        sb.WriteString(" |\n")
    }

    return sb.String()
}