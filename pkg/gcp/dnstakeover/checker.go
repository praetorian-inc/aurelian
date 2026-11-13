package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
	runv2 "google.golang.org/api/run/v2"
	"google.golang.org/api/storage/v1"
)

// Checker evaluates DNS records for subdomain takeover vulnerabilities.
type Checker struct {
	storageSvc   *storage.Service
	runSvc       *runv2.Service
	appengineSvc *appengine.APIService
	computeSvc   *compute.Service
	dnsSvc       *dns.Service

	// projectIDs are the projects resolved for this scan. Cloud DNS zone
	// ownership is looked up across all of them, because a delegated child
	// zone frequently lives in a different project than its parent zone.
	projectIDs []string
}

// NewChecker creates a Checker with all required GCP service clients.
// projectIDs are the projects resolved for this scan; Cloud DNS zone ownership
// is looked up across all of them.
func NewChecker(clientOptions []option.ClientOption, projectIDs []string) (*Checker, error) {
	ctx := context.Background()

	storageSvc, err := storage.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating storage client: %w", err)
	}
	runSvc, err := runv2.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating cloud run client: %w", err)
	}
	appengineSvc, err := appengine.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating app engine client: %w", err)
	}
	computeSvc, err := compute.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating compute client: %w", err)
	}
	dnsSvc, err := dns.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("creating dns client: %w", err)
	}

	return &Checker{
		storageSvc:   storageSvc,
		runSvc:       runSvc,
		appengineSvc: appengineSvc,
		computeSvc:   computeSvc,
		dnsSvc:       dnsSvc,
		projectIDs:   slices.Clone(projectIDs),
	}, nil
}

// Check evaluates a DNS record for takeover vulnerabilities.
// Pipeline signature: DNSRecord -> model.AurelianModel.
func (c *Checker) Check(rec DNSRecord, out *pipeline.P[model.AurelianModel]) error {
	slog.Info("checking record", "record", rec)
	switch rec.Type {
	case "CNAME":
		c.checkCNAME(rec, out)
	case "A", "AAAA":
		c.checkA(rec, out)
	case "NS":
		c.checkNS(rec, out)
	default:
		slog.Debug("skipping unsupported record type", "type", rec.Type)
	}
	return nil
}
