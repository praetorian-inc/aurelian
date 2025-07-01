package general

import (
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type SupportsResourceTypes interface {
	SupportedResourceTypes() []string
}

func PreprocessResourceTypes(class SupportsResourceTypes) func(chain.Link, string) error {
	processor := func(self chain.Link, input string) error {
		resourceTypes := []string{input}

		if strings.ToLower(input) == "all" {
			resourceTypes = class.SupportedResourceTypes()
		}

		for _, resourceType := range resourceTypes {
			self.Send(resourceType)
		}

		return nil
	}

	return processor
}

func NewResourceTypePreprocessor(class SupportsResourceTypes) func(...cfg.Config) chain.Link {
	preprocessor := PreprocessResourceTypes(class)
	return jlinks.ConstructAdHocLink(preprocessor)
}

// NewSingleResourcePreprocessor returns a link that accepts a string (ARN), constructs an EnrichedResourceDescription, and sends it.
func NewSingleResourcePreprocessor() func(...cfg.Config) chain.Link {
	preprocessor := func(self chain.Link, input string) error {
		erd, err := types.NewEnrichedResourceDescriptionFromArn(input)
		if err != nil {
			return err
		}
		self.Send(erd)
		return nil
	}
	return jlinks.ConstructAdHocLink(preprocessor)
}
