package azure

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// containsCategory checks if a category exists in the list of categories
func containsCategory(categories []string, target string) bool {
	for _, cat := range categories {
		if cat == target {
			return true
		}
	}
	return false
}

// ARGTemplateQueryInput is the input struct for the query link
// Contains a template and a subscription

type ARGTemplateQueryInput struct {
	Template     *templates.ARGQueryTemplate
	Subscription string
}

// ARGTemplateLoaderLink loads and filters ARG templates by category
type ARGTemplateLoaderLink struct {
	*chain.Base
}

func NewARGTemplateLoaderLink(configs ...cfg.Config) chain.Link {
	l := &ARGTemplateLoaderLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *ARGTemplateLoaderLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureTemplateDir(),
		options.AzureArgCategory(),
		options.AzureSubscription(),
	}
}

func (l *ARGTemplateLoaderLink) Process(input interface{}) error {
	// This link can receive different types of input:
	// - For modules with ResourceTypePreprocessor: model.CloudResourceType
	// - For modules with WithChainInputParam: string (subscription ID)
	// - For modules with AzureSubscriptionGeneratorLink: string (subscription ID from generator)
	l.Logger.Debug("ARGTemplateLoaderLink received input", "input", input, "type", fmt.Sprintf("%T", input))

	subscription := ""

	// If input is a string, it's a subscription ID from the chain
	if inputStr, ok := input.(string); ok {
		subscription = inputStr
		l.Logger.Debug("Using subscription from chain input", "subscription", subscription)
	} else {
		// Fallback: get subscription from parameters for backward compatibility
		subscriptions, err := cfg.As[[]string](l.Arg("subscription"))
		l.Logger.Debug("subscription lookup", "subscriptions", subscriptions, "error", err, "all_args", l.Args())

		if len(subscriptions) > 0 {
			subscription = subscriptions[0]
		}
		l.Logger.Debug("Using subscription from parameters", "subscription", subscription)
	}

	l.Logger.Info("ARGTemplateLoaderLink starting", "subscription", subscription)

	directory := ""
	category := ""
	if l.HasParam("template-dir") {
		directory, _ = cfg.As[string](l.Arg("template-dir"))
	}
	if l.HasParam("category") {
		category, _ = cfg.As[string](l.Arg("category"))
	}

	loader, err := templates.NewTemplateLoader()
	if err != nil {
		return fmt.Errorf("failed to initialize template loader: %v", err)
	}
	if directory != "" {
		if err := loader.LoadUserTemplates(directory); err != nil {
			return fmt.Errorf("failed to load user templates: %v", err)
		}
	}
	templatesList := loader.GetTemplates()
	l.Logger.Info("Templates loaded, filtering by category", "template_count", len(templatesList), "category", category)

	for _, t := range templatesList {
		if category == "" || containsCategory(t.Category, category) {
			l.Logger.Debug("Matched template", "template_id", t.ID, "template_category", t.Category)
			l.Send(ARGTemplateQueryInput{Template: t, Subscription: subscription})
		}
	}
	return nil
}

// ARGTemplateQueryLink executes ARG queries from templates for a subscription

type ARGTemplateQueryLink struct {
	*chain.Base
}

func NewARGTemplateQueryLink(configs ...cfg.Config) chain.Link {
	l := &ARGTemplateQueryLink{}
	l.Base = chain.NewBase(l, configs...)
	l.Base.SetName("Executes ARG queries for a template/subscription pair")
	return l
}

func (l *ARGTemplateQueryLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
		options.AzureTemplateDir(),
		options.AzureArgCategory(),
		options.OutputDir(),
	}
}

func (l *ARGTemplateQueryLink) Process(input ARGTemplateQueryInput) error {
	argClient, err := helpers.NewARGClient(l.Context())
	if err != nil {
		l.Logger.Error("Failed to create ARG client", "error", err)
		return err
	}
	template := input.Template
	queryOpts := &helpers.ARGQueryOptions{
		Subscriptions: []string{input.Subscription},
	}
	message.Info("Executing ARG query for template %s", template.ID)
	l.Logger.Debug("ARG query", "template_id", template.ID, "query", template.Query)
	err = argClient.ExecutePaginatedQuery(l.Context(), template.Query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
		if response == nil || response.Data == nil {
			l.Logger.Debug("ARG query returned no data", "template_id", template.ID)
			return nil
		}
		rows, ok := response.Data.([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response data type")
		}
		l.Logger.Debug("ARG query found resources", "template_id", template.ID, "count", len(rows))
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

			ar, err := model.NewAzureResource(helpers.SafeGetString(item, "id"), input.Subscription, model.CloudResourceType(helpers.SafeGetString(item, "type")), properties)
			if err != nil {
				l.Logger.Error("Failed to create Azure resource", "error", err)
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
			cleanSub := strings.ReplaceAll(input.Subscription, " ", "-")
			cleanSub = strings.ReplaceAll(cleanSub, "/", "-")
			cleanSub = strings.ReplaceAll(cleanSub, "\\", "-")

			outputDir, _ := cfg.As[string](l.Arg("output"))
			filename := filepath.Join(outputDir, fmt.Sprintf("public-resources-%s.json", cleanSub))
			l.Logger.Debug("Sending resource to next link", "template_id", template.ID, "resource_id", ar.Key, "resource_type", ar.ResourceType, "filename", filename)
			l.Send(outputters.NewNamedOutputData(ar, filename))
		}
		return nil
	})
	if err != nil {
		l.Logger.Error("Failed to execute template", "template_id", template.ID, "error", err)
		return err
	}
	return nil
}
