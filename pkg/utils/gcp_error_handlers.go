package utils

import (
	"fmt"
	"log/slog"
	"reflect"

	"google.golang.org/api/googleapi"
)

// logs skips and returns nil if the error is a 403 and the reason is API disabled
// NOTE: for use ONLY in GCP link Process() functions; DO NOT use in Initialize() functions
func HandleGcpError(err error, msg string) error {
	if err == nil {
		return nil
	}
	if reflect.TypeOf(err) == reflect.TypeOf(&googleapi.Error{}) {
		trueErr := err.(*googleapi.Error)
		if trueErr.Code == 403 {
			for _, detail := range trueErr.Details {
				if detailMap, ok := detail.(map[string]any); ok {
					if reason, ok := detailMap["reason"]; ok && reason == "SERVICE_DISABLED" {
						slog.Info("Skipping", "message", "API disabled for project")
						return nil
					}
				}
			}
		}
	}
	return fmt.Errorf("%s: %w", msg, err)
}
