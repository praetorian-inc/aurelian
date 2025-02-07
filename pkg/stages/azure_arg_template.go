// pkg/stages/azure_arg_template.go
package stages

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"gopkg.in/yaml.v3"
	
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
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

		// Load templates
		templateDir := options.GetOptionByName(options.AzureARGTemplatesDirOpt.Name, opts).Value
		loader, err := LoadARGTemplates(templateDir)
		if err != nil {
			logger.Error("Failed to load templates", slog.String("error", err.Error()))
			return
		}

		for subscription := range in {
			logger.Info("Processing subscription", slog.String("subscription", subscription))

			// Execute each template
			for _, template := range loader.Templates {
				logger.Debug("Executing template",
					slog.String("template_id", template.ID),
					slog.String("template_name", template.Name))

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
							TemplateID:     template.ID,
							Name:           template.Name,
							ResourceID:     helpers.SafeGetString(item, "id"),
							ResourceName:   helpers.SafeGetString(item, "name"),
							ResourceType:   helpers.SafeGetString(item, "type"),
							Location:       helpers.SafeGetString(item, "location"),
							SubscriptionID: subscription,
						}

						// Extract any additional properties specified in the query
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