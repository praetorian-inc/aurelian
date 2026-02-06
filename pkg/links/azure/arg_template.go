package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ARGTemplateQueryInput is the input struct for the query link
// Contains a template and a subscription

type ARGTemplateQueryInput struct {
	Template     *templates.ARGQueryTemplate
	Subscription string
}

// ARGTemplateLoaderLink loads and filters ARG templates by category
type ARGTemplateLoaderLink struct {
	TemplateDir  string
	Category     string
	Subscription string
}

func NewARGTemplateLoaderLink(templateDir, category, subscription string) *ARGTemplateLoaderLink {
	return &ARGTemplateLoaderLink{
		TemplateDir:  templateDir,
		Category:     category,
		Subscription: subscription,
	}
}

func (l *ARGTemplateLoaderLink) Process(ctx context.Context, input any) ([]any, error) {
	// This link can receive different types of input:
	// - For modules with ResourceTypePreprocessor: model.CloudResourceType
	// - For modules with WithChainInputParam: string (subscription ID)
	// - For modules with AzureSubscriptionGeneratorLink: string (subscription ID from generator)

	subscription := l.Subscription

	// If input is a string, it's a subscription ID from the chain
	if inputStr, ok := input.(string); ok {
		subscription = inputStr
	}

	var loader *templates.TemplateLoader
	var err error

	if l.TemplateDir != "" {
		// User specified directory - use ONLY user templates
		loader, err = templates.NewTemplateLoader(templates.UserTemplatesOnly)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize template loader: %v", err)
		}
		if err := loader.LoadUserTemplates(l.TemplateDir); err != nil {
			return nil, fmt.Errorf("failed to load user templates: %v", err)
		}
	} else {
		// No template directory specified - use embedded templates
		loader, err = templates.NewTemplateLoader(templates.LoadEmbedded)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize template loader: %v", err)
		}
	}
	templatesList := loader.GetTemplates()

	var results []any
	for _, t := range templatesList {
		if l.Category == "" || slices.Contains(t.Category, l.Category) {
			results = append(results, ARGTemplateQueryInput{Template: t, Subscription: subscription})
		}
	}
	return results, nil
}

// ARGTemplateQueryLink executes ARG queries from templates for a subscription
type ARGTemplateQueryLink struct {
	OutputDir string
}

func NewARGTemplateQueryLink(outputDir string) *ARGTemplateQueryLink {
	return &ARGTemplateQueryLink{
		OutputDir: outputDir,
	}
}

type ARGTemplateQueryOutput struct {
	Resource *model.AzureResource
	Filename string
}

func (l *ARGTemplateQueryLink) Process(ctx context.Context, input any) ([]any, error) {
	queryInput, ok := input.(ARGTemplateQueryInput)
	if !ok {
		return nil, fmt.Errorf("expected ARGTemplateQueryInput, got %T", input)
	}

	argClient, err := helpers.NewARGClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARG client: %w", err)
	}

	template := queryInput.Template
	queryOpts := &helpers.ARGQueryOptions{
		Subscriptions: []string{queryInput.Subscription},
	}

	message.Info("Executing ARG query for template %s", template.ID)

	var results []any
	err = argClient.ExecutePaginatedQuery(ctx, template.Query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
		if response == nil || response.Data == nil {
			return nil
		}
		rows, ok := response.Data.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response data type")
		}

		for _, row := range rows {
			item, ok := row.(map[string]any)
			if !ok {
				continue
			}

			properties := make(map[string]any)
			for k, v := range item {
				if k != "id" && k != "name" && k != "type" && k != "location" && k != "subscriptionId" {
					properties[k] = v
				}
			}
			properties["templateID"] = template.ID

			ar, err := model.NewAzureResource(
				helpers.SafeGetString(item, "id"),
				queryInput.Subscription,
				model.CloudResourceType(helpers.SafeGetString(item, "type")),
				properties,
			)
			if err != nil {
				continue
			}
			ar.Region = helpers.SafeGetString(item, "location")
			ar.Name = helpers.SafeGetString(item, "name")
			ar.ResourceType = model.CloudResourceType(helpers.SafeGetString(item, "type"))
			ar.Properties = properties

			// Attempt to unmarshal any string value that looks like JSON
			for k, v := range ar.Properties {
				str, ok := v.(string)
				if !ok {
					continue
				}
				// Try to unmarshal if it looks like JSON
				if len(str) > 0 && (str[0] == '[' || str[0] == '{') {
					var unmarshalled any
					if err := json.Unmarshal([]byte(str), &unmarshalled); err == nil {
						ar.Properties[k] = unmarshalled
					}
				}
			}

			// Clean subscription for filename
			cleanSub := strings.ReplaceAll(queryInput.Subscription, " ", "-")
			cleanSub = strings.ReplaceAll(cleanSub, "/", "-")
			cleanSub = strings.ReplaceAll(cleanSub, "\\", "-")

			filename := filepath.Join(l.OutputDir, fmt.Sprintf("public-resources-%s.json", cleanSub))
			results = append(results, ARGTemplateQueryOutput{
				Resource: &ar,
				Filename: filename,
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute template %s: %w", template.ID, err)
	}

	return results, nil
}
