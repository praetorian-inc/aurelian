package enrichers

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// enrichTechnologies reads Code.ImageUri, and FetchFunctionImage is what puts
// it there. Enrichers run in registration order (plugin.GetEnrichers returns
// the slice RegisterEnricher appended to), and registration order is init()
// order, which for one package is *filename* order: lambda.go sorts before
// technology.go.
//
// That is a real dependency resting on an alphabetical accident. Renaming
// either file — technology.go to cpe.go, say — would silently reverse it, and
// the only symptom would be image-packaged Lambdas quietly losing their
// technology, with every other test in the suite still green. This test is the
// tripwire.
//
// The ordering matters only for Lambda. Every other type's technology
// enricher reads properties the enumerator already supplied.
func TestLambdaImageEnricherRunsBeforeTechnologyEnricher(t *testing.T) {
	indexOf := func(fn any) int {
		target := reflect.ValueOf(fn).Pointer()
		for i, registered := range plugin.GetEnrichers("AWS::Lambda::Function") {
			if reflect.ValueOf(registered).Pointer() == target {
				return i
			}
		}
		return -1
	}

	// FetchFunctionImage is registered via a wrapper that closes over the
	// concrete client, so match the wrapper rather than the exported seam.
	image := indexOf(fetchFunctionImageWrapper)
	tech := indexOf(enrichTechnologies)

	if image < 0 {
		t.Fatal("lambda image enricher is not registered for AWS::Lambda::Function")
	}
	if tech < 0 {
		t.Fatal("technology enricher is not registered for AWS::Lambda::Function")
	}
	if image > tech {
		t.Errorf("lambda image enricher runs at %d, after the technology enricher at %d; "+
			"image-packaged functions will emit no technology. Enrichers run in "+
			"registration order, which is init() order, which is filename order — "+
			"did a file get renamed?", image, tech)
	}
}
