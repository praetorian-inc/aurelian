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

// InstanceLister enumerates Compute Engine instances across all zones in a GCP project.
type InstanceLister struct {
	clientOptions []option.ClientOption
}

// NewInstanceLister creates an InstanceLister with the given client options.
func NewInstanceLister(clientOptions []option.ClientOption) *InstanceLister {
	return &InstanceLister{clientOptions: clientOptions}
}

// List enumerates all Compute Engine instances for the given project.
func (l *InstanceLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}

	// List all zones.
	var zones []string
	err = svc.Zones.List(projectID).Pages(context.Background(), func(resp *computeapi.ZoneList) error {
		for _, z := range resp.Items {
			zones = append(zones, z.Name)
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping compute instances", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing compute zones: %w", err)
	}

	// Fan out per zone with bounded concurrency.
	g := errgroup.Group{}
	g.SetLimit(10)

	for _, zone := range zones {
		g.Go(func() error {
			err := svc.Instances.List(projectID, zone).Pages(context.Background(), func(resp *computeapi.InstanceList) error {
				for _, inst := range resp.Items {
					sendInstance(projectID, zone, inst, out)
				}
				return nil
			})
			if err != nil {
				if gcperrors.ShouldSkip(err) {
					slog.Debug("skipping compute instances in zone", "project", projectID, "zone", zone, "reason", err)
					return nil
				}
				return fmt.Errorf("listing instances in zone %s: %w", zone, err)
			}
			return nil
		})
	}

	return g.Wait()
}

func (l *InstanceLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	zone, ok := pathSegment(input.ResourceID, "zones")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing zones/{zone}/instances/{name}")
	}
	name, ok := pathSegment(input.ResourceID, "instances")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing zones/{zone}/instances/{name}")
	}

	svc, err := computeapi.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating compute client: %w", err)
	}
	inst, err := svc.Instances.Get(input.ProjectID, zone, name).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping compute instance", "project", input.ProjectID, "zone", zone, "name", name, "reason", err)
			return nil
		}
		return fmt.Errorf("getting instance %s in zone %s: %w", name, zone, err)
	}
	sendInstance(input.ProjectID, zone, inst, out)
	return nil
}

func (l *InstanceLister) ResourceTypes() []string { return []string{"compute.googleapis.com/Instance"} }

func sendInstance(projectID, zone string, inst *computeapi.Instance, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "compute.googleapis.com/Instance", fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectID, zone, inst.Name))
	r.DisplayName = inst.Name
	r.Location = zone
	r.Labels = inst.Labels

	var ips []string
	for _, iface := range inst.NetworkInterfaces {
		for _, ac := range iface.AccessConfigs {
			if ac.NatIP != "" {
				ips = append(ips, ac.NatIP)
			}
		}
	}
	r.IPs = ips

	r.Properties = map[string]any{
		"status":      inst.Status,
		"machineType": inst.MachineType,
	}
	out.Send(r)
}
