package dnstakeover

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

type servicePattern struct {
	patterns    []string
	service     string
	severity    output.RiskSeverity
	description func(rdata string) string
	remediation string
	checker     func(c *Checker, projectID, rdata string) bool
}

var cnamePatterns = []servicePattern{
	{
		patterns: []string{".storage.googleapis.com", ".c.storage.googleapis.com"},
		service:  "Cloud Storage",
		severity: output.RiskSeverityCritical,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to non-existent Cloud Storage bucket: %s", extractBucketName(rdata))
		},
		remediation: "Delete the CNAME record or create the bucket with appropriate permissions",
		checker:     func(c *Checker, _, rdata string) bool { return c.bucketExists(extractBucketName(rdata)) },
	},
	{
		patterns: []string{".run.app"},
		service:  "Cloud Run",
		severity: output.RiskSeverityHigh,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to potentially deleted Cloud Run service: %s", rdata)
		},
		remediation: "Delete the CNAME record or verify the Cloud Run service exists",
		checker:     func(c *Checker, projectID, rdata string) bool { return c.cloudRunServiceExists(projectID, rdata) },
	},
	{
		patterns: []string{".appspot.com", "ghs.googlehosted.com"},
		service:  "App Engine",
		severity: output.RiskSeverityHigh,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to potentially deleted App Engine application: %s", rdata)
		},
		remediation: "Delete the CNAME record or verify the App Engine application exists",
		checker:     func(c *Checker, projectID, _ string) bool { return c.appEngineExists(projectID) },
	},
	{
		patterns: []string{".firebaseapp.com", ".web.app"},
		service:  "Firebase Hosting",
		severity: output.RiskSeverityInfo,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to Firebase Hosting site: %s — manual verification required (TXT ownership check)", rdata)
		},
		remediation: "Verify Firebase site ownership via TXT record validation or remove the CNAME if site is abandoned",
	},
	{
		patterns: []string{".cloudfunctions.net"},
		service:  "Cloud Functions",
		severity: output.RiskSeverityInfo,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to Cloud Function: %s — manual verification required", rdata)
		},
		remediation: "Delete the CNAME record or verify the Cloud Function exists",
	},
	{
		patterns: []string{".endpoints.", ".cloud.goog"},
		service:  "Cloud Endpoints",
		severity: output.RiskSeverityInfo,
		description: func(rdata string) string {
			return fmt.Sprintf("CNAME points to Cloud Endpoints service: %s — manual verification required", rdata)
		},
		remediation: "Delete the CNAME record or verify the backend service exists",
	},
}

func (c *Checker) checkCNAME(rec DNSRecord, out *pipeline.P[model.AurelianModel]) {
	for _, rdata := range rec.Values {
		rdata = strings.TrimSuffix(rdata, ".")

		for _, pat := range cnamePatterns {
			if !matchesAny(rdata, pat.patterns) {
				continue
			}

			// Cloud Endpoints requires both patterns to match
			if pat.service == "Cloud Endpoints" {
				if !strings.Contains(rdata, ".endpoints.") || !strings.Contains(rdata, ".cloud.goog") {
					continue
				}
			}

			// If a checker exists and the resource exists, skip
			if pat.checker != nil && pat.checker(c, rec.ProjectID, rdata) {
				continue
			}

			slog.Debug("dangling CNAME detected",
				"domain", rec.RecordName, "target", rdata, "service", pat.service)

			out.Send(newTakeoverRisk(
				fmt.Sprintf("GCP Subdomain Takeover: Dangling %s CNAME", pat.service),
				pat.severity,
				rec,
				map[string]any{
					"service":     pat.service,
					"target":      rdata,
					"description": pat.description(rdata),
					"remediation": pat.remediation,
				},
			))
			break
		}
	}
}

func matchesAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func extractBucketName(rdata string) string {
	name := strings.TrimSuffix(rdata, ".storage.googleapis.com")
	name = strings.TrimSuffix(name, ".c.storage.googleapis.com")
	return name
}

func (c *Checker) bucketExists(bucketName string) bool {
	_, err := c.storageSvc.Buckets.Get(bucketName).Do()
	return err == nil
}

func (c *Checker) cloudRunServiceExists(projectID, domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 4 {
		return true // can't parse — assume exists to avoid false positive
	}
	servicePrefix := parts[0]

	parent := fmt.Sprintf("projects/%s/locations/-", projectID)
	resp, err := c.runSvc.Projects.Locations.Services.List(parent).Do()
	if err != nil {
		return true // API error — assume exists
	}

	for _, svc := range resp.Services {
		nameParts := strings.Split(svc.Name, "/")
		serviceName := nameParts[len(nameParts)-1]
		if strings.HasPrefix(servicePrefix, serviceName) {
			return true
		}
	}
	return false
}

func (c *Checker) appEngineExists(projectID string) bool {
	_, err := c.appengineSvc.Apps.Get(fmt.Sprintf("apps/%s", projectID)).Do()
	return err == nil
}
