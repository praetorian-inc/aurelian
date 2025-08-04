package general

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links"
)

// NewTypedUnmarshalOutputLink creates a link that unmarshals JSON strings into a specific type.
// This provides more flexibility when you know the exact type you want to unmarshal into.
func NewTypedUnmarshalOutputLink[T any](configs ...cfg.Config) chain.Link {
	return links.NewAdHocLink(func(self chain.Link, input string) error {
		var result T
		err := json.Unmarshal([]byte(input), &result)
		if err != nil {
			slog.Error("Failed to unmarshal JSON", "error", err, "input", input)
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}

		self.Send(result)
		return nil
	})
}
