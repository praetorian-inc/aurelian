package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

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

// ARGTemplateQueryInput is the input struct for the query link
// Contains a template and a subscription

type ARGTemplateQueryInput struct {
	Template     *templates.ARGQueryTemplate
	Subscription string
}

// Command represents the input and output of a command that requires manual triage
type Command struct {
	Command                   string `json:"command"`
	Description               string `json:"description"`
	ExpectedOutputDescription string `json:"expected_output_description"`
	ActualOutput              string `json:"actual_output"`
	ExitCode                  int    `json:"exit_code"`
	Error                     string `json:"error,omitempty"`
}

// ResourceEnricher interface for extensible resource enrichment
type ResourceEnricher interface {
	CanEnrich(templateID string) bool
	Enrich(ctx context.Context, resource *model.AzureResource) []Command
}

// StorageAccountEnricher implements enrichment for storage accounts
type StorageAccountEnricher struct{}

func (s *StorageAccountEnricher) CanEnrich(templateID string) bool {
	return templateID == "storage_accounts_public_access"
}

func (s *StorageAccountEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract storage account name from resource
	storageAccountName := resource.Name
	if storageAccountName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "No storage account name found",
			ActualOutput: "Error: storage account name is empty",
		})
		return commands
	}

	// Sanitize the storage account name for URL encoding
	storageAccountNameForURL := url.QueryEscape(strings.TrimSpace(storageAccountName))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test anonymous access via HTTP request
	testURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", storageAccountNameForURL)

	resp, err := client.Get(testURL)

	command := fmt.Sprintf("curl -w \"\\n===== Status Code =====\\n%%{http_code}\\n\" \"%s\" --max-time 10", testURL)
	curlCommand := Command{
		Command:                   command,
		Description:               "Test anonymous access to storage account container listing",
		ExpectedOutputDescription: "anonymous access enabled 404 | anonymous access disabled = 401/403 | public access disabled = 409",
	}

	if err != nil {
		curlCommand.Error = err.Error()
		curlCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		curlCommand.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		curlCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, curlCommand)
	return commands
}

// EnrichmentRegistry holds all available enrichers
type EnrichmentRegistry struct {
	enrichers []ResourceEnricher
}

func NewEnrichmentRegistry() *EnrichmentRegistry {
	return &EnrichmentRegistry{
		enrichers: []ResourceEnricher{
			&StorageAccountEnricher{},
			&VirtualMachineEnricher{}, // Example of additional enricher
			// Add more enrichers here as needed
		},
	}
}

// VirtualMachineEnricher implements enrichment for virtual machines
type VirtualMachineEnricher struct{}

func (v *VirtualMachineEnricher) CanEnrich(templateID string) bool {
	return templateID == "virtual_machines_public" || templateID == "virtual_machines_all"
}

func (v *VirtualMachineEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract VM name and location
	vmName := resource.Name
	location := resource.Region

	if vmName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "No VM name found",
			ActualOutput: "Error: VM name is empty",
		})
		return commands
	}

	// Add nmap command for network scanning
	nmapCommand := Command{
		Command:                   fmt.Sprintf("nmap -sS -O -A %s", vmName),
		Description:               "Network scan of the virtual machine",
		ExpectedOutputDescription: "Open ports and services running on the VM",
		ActualOutput:              "Manual execution required",
	}
	commands = append(commands, nmapCommand)

	// Add SSH connection test if applicable
	if location != "" {
		sshCommand := Command{
			Command:                   fmt.Sprintf("ssh -o ConnectTimeout=10 azureuser@%s.%s.cloudapp.azure.com", vmName, location),
			Description:               "Test SSH connectivity to the VM",
			ExpectedOutputDescription: "Connection success/failure, authentication method",
			ActualOutput:              "Manual execution required",
		}
		commands = append(commands, sshCommand)
	}

	return commands
}

func (r *EnrichmentRegistry) EnrichResource(ctx context.Context, templateID string, resource *model.AzureResource) []Command {
	var allCommands []Command

	for _, enricher := range r.enrichers {
		if enricher.CanEnrich(templateID) {
			commands := enricher.Enrich(ctx, resource)
			allCommands = append(allCommands, commands...)
		}
	}

	return allCommands
}

// ARGEnrichmentLink enriches Azure resources with additional security testing commands
type ARGEnrichmentLink struct {
	*chain.Base
	registry *EnrichmentRegistry
}

func NewARGEnrichmentLink(configs ...cfg.Config) chain.Link {
	l := &ARGEnrichmentLink{
		registry: NewEnrichmentRegistry(),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *ARGEnrichmentLink) Params() []cfg.Param {
	return []cfg.Param{}
}

func (l *ARGEnrichmentLink) Process(data outputters.NamedOutputData) error {
	// Extract the Azure resource from the data
	resource, ok := data.Data.(*model.AzureResource)
	if !ok {
		l.Logger.Debug("Skipping non-AzureResource data in enrichment", "data_type", fmt.Sprintf("%T", data.Data))
		l.Send(data)
		return nil
	}

	// Get template ID from resource properties
	templateID, exists := resource.Properties["templateID"].(string)
	if !exists {
		l.Logger.Debug("No templateID found in resource properties, skipping enrichment", "resource_id", resource.Key)
		l.Send(data)
		return nil
	}

	// Enrich the resource with security testing commands
	commands := l.registry.EnrichResource(l.Context(), templateID, resource)

	if len(commands) > 0 {
		l.Logger.Debug("Enriched resource with commands", "resource_id", resource.Key, "template_id", templateID, "command_count", len(commands))

		// Add commands to resource properties
		if resource.Properties == nil {
			resource.Properties = make(map[string]any)
		}
		resource.Properties["commands"] = commands
	}

	// Send the enriched resource
	l.Send(data)
	return nil
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
	// We ignore the input and get subscription from parameters
	l.Logger.Debug("ARGTemplateLoaderLink received input", "input", input, "type", fmt.Sprintf("%T", input))
	
	// Get subscription from parameters (works for both cases)
	subscriptions, err := cfg.As[[]string](l.Arg("subscription"))
	l.Logger.Debug("subscription lookup", "subscriptions", subscriptions, "error", err, "all_args", l.Args())

	subscription := ""
	if len(subscriptions) > 0 {
		subscription = subscriptions[0]
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
		if category == "" || t.Category == category {
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
