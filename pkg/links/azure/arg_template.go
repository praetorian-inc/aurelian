package azure

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ARGTemplateQueryInput is the input struct for the query link
// Contains a template and a subscription

type ARGTemplateQueryInput struct {
	Template     *templates.ARGQueryTemplate
	Subscription string
}

// NewARGTemplateLoaderLink returns an ad-hoc link that loads templates from a directory, filters by category, and emits ARGTemplateQueryInput for each template and subscription.
// Params: directory (string), category (string)
func NewARGTemplateLoaderLink() func(...cfg.Config) chain.Link {
	return jlinks.ConstructAdHocLink(func(self chain.Link, subscription string) error {
		directory := ""
		category := ""
		if self.HasParam("template-dir") {
			directory, _ = self.Param("template-dir").Value().(string)
		}
		if self.HasParam("category") {
			category, _ = self.Param("category").Value().(string)
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
		for _, t := range templatesList {
			if category == "" || t.Category == category {
				self.Send(ARGTemplateQueryInput{Template: t, Subscription: subscription})
			}
		}
		return nil
	})
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
	err = argClient.ExecutePaginatedQuery(l.Context(), template.Query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
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

			l.Send(ar)
		}
		return nil
	})
	if err != nil {
		l.Logger.Error("Failed to execute template", "template_id", template.ID, "error", err)
		return err
	}
	return nil
}
