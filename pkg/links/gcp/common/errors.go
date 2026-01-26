package common

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/googleapi"
)

func HandleGcpError(err error, msg string) error {
	if err == nil {
		return nil
	}
	if reflect.TypeOf(err) == reflect.TypeOf(&googleapi.Error{}) {
		trueErr := err.(*googleapi.Error)
		if trueErr.Code == 403 {
			// Check structured Details field
			for _, detail := range trueErr.Details {
				if detailMap, ok := detail.(map[string]any); ok {
					if reason, ok := detailMap["reason"]; ok && reason == "SERVICE_DISABLED" {
						slog.Info("Skipping", "message", "API disabled for project")
						return nil
					}
					if reason, ok := detailMap["reason"]; ok && reason == "BILLING_DISABLED" {
						slog.Info("Skipping", "message", "Billing disabled for project")
						return nil
					}
				}
			}
			// Check plain text error body for billing/service disabled messages
			if strings.Contains(trueErr.Body, "billing account") && strings.Contains(trueErr.Body, "disabled") {
				slog.Info("Skipping", "message", "Billing disabled for project")
				return nil
			}
			if strings.Contains(trueErr.Body, "service") && strings.Contains(trueErr.Body, "disabled") {
				slog.Info("Skipping", "message", "API disabled for project")
				return nil
			}
		}
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func ParseAggregatedListError(projectName, errorText string) []*ResourceError {
	var resourceErrors []*ResourceError
	lines := strings.SplitSeq(errorText, "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "SERVICE_DISABLED") || strings.Contains(line, "BILLING_DISABLED") {
			slog.Debug("Skipping already handled error", "error", line) // ideally handled by individual links
			continue
		}
		if resourceError := parsePermissionDeniedError(projectName, line); resourceError != nil {
			resourceErrors = append(resourceErrors, resourceError)
		}
	}
	return resourceErrors
}

func parsePermissionDeniedError(projectName, line string) *ResourceError {
	if !strings.Contains(line, "does not have") || !strings.Contains(line, "access") {
		return nil
	}
	permissionMappings := map[string]tab.CloudResourceType{
		"storage.buckets.list":               tab.GCPResourceBucket,
		"cloudsql.instances.list":            tab.GCPResourceSQLInstance,
		"compute.instances.list":             tab.GCPResourceInstance,
		"compute.zones.list":                 tab.GCPResourceInstance,
		"compute.regions.list":               tab.GCPResourceInstance,
		"cloudfunctions.functions.list":      tab.GCPResourceFunction,
		"run.services.list":                  tab.GCPResourceCloudRunService,
		"appengine.applications.get":         tab.GCPResourceAppEngineApplication,
		"artifactregistry.repositories.list": tab.GCRArtifactRepository,
		"compute.globalForwardingRules.list": tab.GCPResourceGlobalForwardingRule,
		"compute.globalAddresses.list":       tab.GCPResourceAddress,
		"dns.managedZones.list":              tab.GCPResourceDNSManagedZone,
	}
	for permission, resourceType := range permissionMappings {
		if strings.Contains(line, permission) {
			return NewResourceError(projectName, resourceType.String(), "list", "Permission denied").
				WithErrorCode(403).
				WithDetails(line)
		}
	}
	return nil
}

type ResourceError struct {
	Timestamp    string `json:"timestamp"`
	Project      string `json:"project"`
	ResourceType string `json:"resourceType"`
	Operation    string `json:"operation"`
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage"`
	Details      string `json:"details,omitempty"`
}

func NewResourceError(project, resourceType, operation, errorMessage string) *ResourceError {
	return &ResourceError{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Project:      project,
		ResourceType: resourceType,
		Operation:    operation,
		ErrorMessage: errorMessage,
	}
}

func (re *ResourceError) WithErrorCode(code int) *ResourceError {
	re.ErrorCode = code
	return re
}

func (re *ResourceError) WithDetails(details string) *ResourceError {
	re.Details = details
	return re
}
