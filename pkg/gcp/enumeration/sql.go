package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// SQLInstanceLister enumerates Cloud SQL instances in a GCP project.
type SQLInstanceLister struct {
	clientOptions []option.ClientOption
}

// NewSQLInstanceLister creates a SQLInstanceLister with the given client options.
func NewSQLInstanceLister(clientOptions []option.ClientOption) *SQLInstanceLister {
	return &SQLInstanceLister{clientOptions: clientOptions}
}

// List enumerates all Cloud SQL instances for the given project.
func (l *SQLInstanceLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := sqladmin.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating sqladmin client: %w", err)
	}

	resp, err := svc.Instances.List(projectID).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping cloud sql instances", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing cloud sql instances: %w", err)
	}

	for _, inst := range resp.Items {
		sendSQLInstance(projectID, inst, out)
	}

	return nil
}

func (l *SQLInstanceLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := sqladmin.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating sqladmin client: %w", err)
	}
	name := lastPathPart(input.ResourceID)
	inst, err := svc.Instances.Get(input.ProjectID, name).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping cloud sql instance", "project", input.ProjectID, "instance", name, "reason", err)
			return nil
		}
		return fmt.Errorf("getting cloud sql instance %s: %w", name, err)
	}
	sendSQLInstance(input.ProjectID, inst, out)
	return nil
}

func (l *SQLInstanceLister) ResourceTypes() []string {
	return []string{"sqladmin.googleapis.com/Instance"}
}

func sendSQLInstance(projectID string, inst *sqladmin.DatabaseInstance, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "sqladmin.googleapis.com/Instance", inst.Name)
	r.DisplayName = inst.Name
	r.Location = inst.Region

	var ips []string
	for _, addr := range inst.IpAddresses {
		if addr.Type == "PRIMARY" {
			ips = append(ips, addr.IpAddress)
		}
	}
	r.IPs = ips

	var authorizedNetworks []string
	ipv4Enabled := false
	if inst.Settings != nil && inst.Settings.IpConfiguration != nil {
		ipv4Enabled = inst.Settings.IpConfiguration.Ipv4Enabled
		for _, acl := range inst.Settings.IpConfiguration.AuthorizedNetworks {
			authorizedNetworks = append(authorizedNetworks, acl.Value)
		}
	}

	r.Properties = map[string]any{
		"databaseVersion":    inst.DatabaseVersion,
		"state":              inst.State,
		"instanceType":       inst.InstanceType,
		"ipv4Enabled":        ipv4Enabled,
		"authorizedNetworks": authorizedNetworks,
	}

	if inst.Settings != nil {
		r.Labels = inst.Settings.UserLabels
	}

	out.Send(r)
}
