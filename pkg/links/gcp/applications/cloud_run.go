package applications

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/common"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/run/v2"
)

// FILE INFO:
// GcpCloudRunServiceInfoLink - get info of a single Cloud Run service, Process(serviceName string); needs project and region
// GcpCloudRunServiceListLink - list all Cloud Run services in a project, Process(resource tab.GCPResource)
// GcpCloudRunSecretsLink - extract secrets from a Cloud Run service, Process(input tab.GCPResource)

type GcpCloudRunServiceInfoLink struct {
	*base.GcpBaseLink
	runService *run.Service
	ProjectId  string
	Region     string
}

// creates a link to get info of a single Cloud Run service
func NewGcpCloudRunServiceInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpCloudRunServiceInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpCloudRunServiceInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		options.GcpRegion(),
	)
	return params
}

func (g *GcpCloudRunServiceInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud run service: %w", err)
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

func (g *GcpCloudRunServiceInfoLink) Process(serviceName string) error {
	name := fmt.Sprintf("projects/%s/locations/%s/services/%s", g.ProjectId, g.Region, serviceName)
	service, err := g.runService.Projects.Locations.Services.Get(name).Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to get Cloud Run service")
	}
	gcpCloudRunService, err := tab.NewGCPResource(
		service.Name,                            // resource name
		g.ProjectId,                             // accountRef (project ID)
		tab.GCPResourceCloudRunService,          // resource type
		linkPostProcessCloudRunService(service), // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP Cloud Run service resource: %w", err)
	}
	gcpCloudRunService.DisplayName = gcpCloudRunService.Name
	g.Send(gcpCloudRunService)
	return nil
}

type GcpCloudRunServiceListLink struct {
	*base.GcpBaseLink
	runService    *run.Service
	regionService *compute.Service
	iamService    *iam.Service
}

// creates a link to list all Cloud Run services in a project
func NewGcpCloudRunServiceListLink(configs ...cfg.Config) chain.Link {
	g := &GcpCloudRunServiceListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpCloudRunServiceListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud run service: %w", err)
	}
	g.regionService, err = compute.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create compute service: %w", err)
	}
	g.iamService, err = iam.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create iam service: %w", err)
	}
	return nil
}

func (g *GcpCloudRunServiceListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	regionsCall := g.regionService.Regions.List(projectId)
	regionsResp, err := regionsCall.Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to list regions in project")
	}
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, region := range regionsResp.Items {
		wg.Add(1)
		sem <- struct{}{}
		go func(regionId string) {
			defer wg.Done()
			defer func() { <-sem }()
			parent := fmt.Sprintf("projects/%s/locations/%s", projectId, regionId)
			servicesCall := g.runService.Projects.Locations.Services.List(parent)
			servicesResp, err := servicesCall.Do()
			if err == nil && servicesResp != nil {
				for _, service := range servicesResp.Services {
					properties := linkPostProcessCloudRunService(service)

					// Check IAM policy for anonymous access
					policy, policyErr := g.runService.Projects.Locations.Services.GetIamPolicy(service.Name).Do()
					if policyErr == nil && policy != nil {
						anonymousInfo := checkCloudRunAnonymousAccess(policy)
						if anonymousInfo.TotalPublicBindings > 0 {
							properties["anonymousAccessInfo"] = anonymousInfo
							properties["riskLevel"] = calculateRiskLevel(anonymousInfo)
						}
					} else {
						slog.Debug("Failed to get IAM policy for Cloud Run service", "service", service.Name, "error", policyErr)
					}

					gcpCloudRunService, err := tab.NewGCPResource(
						service.Name,                   // resource name
						projectId,                      // accountRef (project ID)
						tab.GCPResourceCloudRunService, // resource type
						properties,                     // properties (with anonymous access info)
					)
					if err != nil {
						slog.Error("Failed to create GCP Cloud Run service resource", "error", err, "service", service.Name)
						continue
					}
					gcpCloudRunService.DisplayName = gcpCloudRunService.Name
					g.Send(gcpCloudRunService)
				}
			} else if err != nil {
				slog.Error("Failed to list Cloud Run services in region", "error", err, "region", regionId)
			}
		}(region.Name)
	}
	wg.Wait()
	return nil
}

type GcpCloudRunSecretsLink struct {
	*base.GcpBaseLink
	runService *run.Service
}

// creates a link to scan Cloud Run service for secrets
func NewGcpCloudRunSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpCloudRunSecretsLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpCloudRunSecretsLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.runService, err = run.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create cloud run service: %w", err)
	}
	return nil
}

func (g *GcpCloudRunSecretsLink) Process(input tab.GCPResource) error {
	if input.ResourceType != tab.GCPResourceCloudRunService {
		return nil
	}
	svc, err := g.runService.Projects.Locations.Services.Get(input.Name).Do()
	if err != nil {
		return common.HandleGcpError(err, "failed to get cloud run service for secrets extraction")
	}
	if svc.Template != nil {
		for _, container := range svc.Template.Containers {
			if container == nil {
				continue
			}
			if len(container.Env) > 0 {
				if envContent, err := json.Marshal(container.Env); err == nil {
					g.Send(jtypes.NPInput{
						Content: string(envContent),
						Provenance: jtypes.NPProvenance{
							Platform:     "gcp",
							ResourceType: fmt.Sprintf("%s::EnvVariables", tab.GCPResourceCloudRunService.String()),
							ResourceID:   input.Name,
							Region:       input.Region,
							AccountID:    input.AccountRef,
						},
					})
				}
			}
			var commandContent strings.Builder
			if len(container.Command) > 0 {
				commandContent.WriteString(strings.Join(container.Command, " "))
			}
			if len(container.Args) > 0 {
				if commandContent.Len() > 0 {
					commandContent.WriteString(" ")
				}
				commandContent.WriteString(strings.Join(container.Args, " "))
			}
			if commandContent.Len() > 0 {
				g.Send(jtypes.NPInput{
					Content: commandContent.String(),
					Provenance: jtypes.NPProvenance{
						Platform:     "gcp",
						ResourceType: fmt.Sprintf("%s::Command", tab.GCPResourceCloudRunService.String()),
						ResourceID:   input.Name,
						Region:       input.Region,
						AccountID:    input.AccountRef,
					},
				})
			}
		}
	}
	return nil
}

// ------------------------------------------------------------------------------------------------
// helper functions

// AnonymousAccessInfo represents anonymous access configuration for a resource
type AnonymousAccessInfo struct {
	HasAllUsers                bool     `json:"hasAllUsers"`
	HasAllAuthenticatedUsers   bool     `json:"hasAllAuthenticatedUsers"`
	AllUsersRoles              []string `json:"allUsersRoles"`
	AllAuthenticatedUsersRoles []string `json:"allAuthenticatedUsersRoles"`
	TotalPublicBindings        int      `json:"totalPublicBindings"`
	AccessMethods              []string `json:"accessMethods"`
}

// checkCloudRunAnonymousAccess checks if a Cloud Run service has anonymous access via IAM
func checkCloudRunAnonymousAccess(policy *run.GoogleIamV1Policy) AnonymousAccessInfo {
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

// calculateRiskLevel determines risk level based on anonymous access info
func calculateRiskLevel(info AnonymousAccessInfo) string {
	if info.HasAllUsers {
		return "critical"
	} else if info.HasAllAuthenticatedUsers {
		return "high"
	}
	return "low"
}

func linkPostProcessCloudRunService(service *run.GoogleCloudRunV2Service) map[string]any {
	properties := map[string]any{
		"name":      service.Name,
		"namespace": service.Annotations["cloud.googleapis.com/namespace"],
		"labels":    service.Labels,
	}
	properties["uid"] = service.Annotations["cloud.googleapis.com/uid"]
	properties["publicURLs"] = service.Urls
	if service.Template != nil {
		properties["serviceAccountName"] = service.Template.ServiceAccount
		if len(service.Template.Containers) > 0 {
			container := service.Template.Containers[0]
			properties["image"] = container.Image
			properties["command"] = container.Command
			properties["args"] = container.Args
			properties["workingDir"] = container.WorkingDir
		}
	}
	return properties
}
