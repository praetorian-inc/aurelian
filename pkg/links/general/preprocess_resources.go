package general

import (
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
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
