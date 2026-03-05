package networking

import (
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"
	"google.golang.org/api/option"
	computeapi "google.golang.org/api/compute/v1"

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
	svc, err := computeapi.NewService(nil, l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// Global forwarding rules.
	err = svc.GlobalForwardingRules.List(projectID).Pages(nil, func(resp *computeapi.ForwardingRuleList) error {
		for _, rule := range resp.Items {
			r := output.NewGCPResource(projectID, "compute.googleapis.com/GlobalForwardingRule", fmt.Sprintf("%d", rule.Id))
			r.DisplayName = rule.Name
			r.Location = "global"
			r.Labels = rule.Labels
			if rule.IPAddress != "" {
				r.IPs = []string{rule.IPAddress}
			}
			r.Properties = map[string]any{
				"target": rule.Target,
			}
			out.Send(r)
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
	err = svc.Regions.List(projectID).Pages(nil, func(resp *computeapi.RegionList) error {
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
			err := svc.ForwardingRules.List(projectID, region).Pages(nil, func(resp *computeapi.ForwardingRuleList) error {
				for _, rule := range resp.Items {
					r := output.NewGCPResource(projectID, "compute.googleapis.com/ForwardingRule", fmt.Sprintf("%d", rule.Id))
					r.DisplayName = rule.Name
					r.Location = region
					r.Labels = rule.Labels
					if rule.IPAddress != "" {
						r.IPs = []string{rule.IPAddress}
					}
					r.Properties = map[string]any{
						"target": rule.Target,
					}
					out.Send(r)
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
