package software_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/software"
	"github.com/stretchr/testify/assert"
)

func TestImageReferences_ECSWalksEveryContainer(t *testing.T) {
	props := map[string]any{"ContainerDefinitions": []any{
		map[string]any{"name": "web", "Image": "nginx:1.25.3"},
		map[string]any{"name": "app", "Image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/myorg/app:v4"},
		map[string]any{"name": "broken"},
		"not-a-map",
	}}
	assert.Equal(t,
		[]string{"nginx:1.25.3", "123456789012.dkr.ecr.us-east-1.amazonaws.com/myorg/app:v4"},
		software.ImageReferences("AWS::ECS::TaskDefinition", props))
}

func TestImageReferences_LambdaOnlyForImagePackagedFunctions(t *testing.T) {
	image := map[string]any{"PackageType": "Image", "Code": map[string]any{"ImageUri": "123.dkr.ecr.us-east-1.amazonaws.com/fn:1"}}
	assert.Equal(t, []string{"123.dkr.ecr.us-east-1.amazonaws.com/fn:1"}, software.ImageReferences("AWS::Lambda::Function", image))

	zip := map[string]any{"PackageType": "Zip", "Code": map[string]any{"ImageUri": "should-not-be-read"}}
	assert.Empty(t, software.ImageReferences("AWS::Lambda::Function", zip))
}

func TestImageReferences_UnknownTypesAndJunkYieldNothing(t *testing.T) {
	assert.Empty(t, software.ImageReferences("AWS::S3::Bucket", map[string]any{"Image": "nginx:1.25"}))
	assert.Empty(t, software.ImageReferences("AWS::ECS::TaskDefinition", nil))
	assert.Empty(t, software.ImageReferences("AWS::ECS::TaskDefinition", map[string]any{"ContainerDefinitions": 42}))
	assert.Empty(t, software.ImageReferences("AWS::Lambda::Function", map[string]any{"PackageType": "Image", "Code": "nope"}))
}

func TestImageReferences_DeduplicatesWithinAResource(t *testing.T) {
	// A task definition with a sidecar on the same image is one fetch.
	props := map[string]any{"ContainerDefinitions": []any{
		map[string]any{"Image": "nginx:1.25.3"},
		map[string]any{"Image": "nginx:1.25.3"},
	}}
	assert.Equal(t, []string{"nginx:1.25.3"}, software.ImageReferences("AWS::ECS::TaskDefinition", props))
}
