package helpers

import (
	"encoding/json"

	l "github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func PrintMessage(message string) {
	logger := l.ConsoleLogger()
	logger.Info(message)
}

func PrintResult(result types.Result) {
	logger := l.ConsoleLogger()
	r, _ := json.MarshalIndent(result.Data, "", "  ")
	if len(r) > 250 {
		logger.Info("Summary", "result", string(r[:100]))
	} else {
		logger.Info("Result", "result", string(r))
	}

}
