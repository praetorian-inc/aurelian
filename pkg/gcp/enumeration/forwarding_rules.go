package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"
	computeapi "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// ForwardingRuleLister enumerates global and regional forwarding rules in a GCP project.
type ForwardingRuleLister struct {
	clientOptions []option.ClientOption
}

// NewForwardingRuleLister creates a ForwardingRuleLister with the given client options.
func NewForwardingRuleLister(clientOptions []option.ClientOption) *ForwardingRuleLister {
	return &ForwardingRuleLister{clientOptions: clientOptions}
}

// List enumerates all forwarding rules (global and regional) for the given project.
func (l *ForwardingRuleLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// Global forwarding rules.
	err = svc.GlobalForwardingRules.List(projectID).Pages(context.Background(), func(resp *computeapi.ForwardingRuleList) error {
		for _, rule := range resp.Items {
			sendForwardingRule(projectID, "compute.googleapis.com/GlobalForwardingRule", "global", rule, out)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping global forwarding rules", "project", projectID, "reason", err)
		} else {
			return fmt.Errorf("listing global forwarding rules: %w", err)
		}
	}

	// List regions for regional forwarding rules.
	var regions []string
	err = svc.Regions.List(projectID).Pages(context.Background(), func(resp *computeapi.RegionList) error {
		for _, region := range resp.Items {
			regions = append(regions, region.Name)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping regional forwarding rules", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing regions: %w", err)
	}

	// Fan out per region with bounded concurrency.
	g := errgroup.Group{}
	g.SetLimit(10)

	for _, region := range regions {
		g.Go(func() error {
			err := svc.ForwardingRules.List(projectID, region).Pages(context.Background(), func(resp *computeapi.ForwardingRuleList) error {
				for _, rule := range resp.Items {
					sendForwardingRule(projectID, "compute.googleapis.com/ForwardingRule", region, rule, out)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping forwarding rules in region", "project", projectID, "region", region, "reason", err)
					return nil
				}
				return fmt.Errorf("listing forwarding rules in region %s: %w", region, err)
			}
			return nil
		})
	}

	return g.Wait()
}

func (l *ForwardingRuleLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	name, ok := pathSegment(input.ResourceID, "forwardingRules")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing forwardingRules/{name}")
	}

	if input.ResourceType == "compute.googleapis.com/GlobalForwardingRule" {
		rule, err := svc.GlobalForwardingRules.Get(input.ProjectID, name).Do()
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				slog.Debug("skipping global forwarding rule", "project", input.ProjectID, "name", name, "reason", err)
				return nil
			}
			return fmt.Errorf("getting global forwarding rule %s: %w", name, err)
		}
		sendForwardingRule(input.ProjectID, input.ResourceType, "global", rule, out)
		return nil
	}

	region, ok := pathSegment(input.ResourceID, "regions")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing regions/{region}/forwardingRules/{name}")
	}
	rule, err := svc.ForwardingRules.Get(input.ProjectID, region, name).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping forwarding rule", "project", input.ProjectID, "region", region, "name", name, "reason", err)
			return nil
		}
		return fmt.Errorf("getting forwarding rule %s in region %s: %w", name, region, err)
	}
	sendForwardingRule(input.ProjectID, input.ResourceType, region, rule, out)
	return nil
}

func (l *ForwardingRuleLister) ResourceTypes() []string {
	return []string{"compute.googleapis.com/ForwardingRule", "compute.googleapis.com/GlobalForwardingRule"}
}

func sendForwardingRule(projectID, resourceType, location string, rule *computeapi.ForwardingRule, out *pipeline.P[output.GCPResource]) {
	resourceID := relativeGCPResourceID(rule.SelfLink)
	if resourceID == "" {
		resourceID = forwardingRuleResourceID(projectID, location, rule.Name)
	}
	r := output.NewGCPResource(projectID, resourceType, resourceID)
	r.DisplayName = rule.Name
	r.Location = location
	r.Labels = rule.Labels
	if rule.IPAddress != "" {
		r.IPs = []string{rule.IPAddress}
	}
	r.Properties = map[string]any{
		"id":     fmt.Sprintf("%d", rule.Id),
		"target": rule.Target,
	}
	out.Send(r)
}

func forwardingRuleResourceID(projectID, location, name string) string {
	if location == "global" {
		return fmt.Sprintf("projects/%s/global/forwardingRules/%s", projectID, name)
	}
	return fmt.Sprintf("projects/%s/regions/%s/forwardingRules/%s", projectID, location, name)
}
