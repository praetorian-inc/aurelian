package dnstakeover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrontDoorEndpointName(t *testing.T) {
	n, ok := frontDoorEndpointName("myfd.azurefd.net")
	require.True(t, ok)
	assert.Equal(t, "myfd", n)

	_, ok = frontDoorEndpointName("myfd-abc.z01.azurefd.net")
	assert.False(t, ok, "hashed Standard/Premium hostnames are a documented FN")

	_, ok = frontDoorEndpointName("x.azureedge.net")
	assert.False(t, ok)
}

func TestFrontDoorEndpointName_TrailingDotAndCase(t *testing.T) {
	n, ok := frontDoorEndpointName("MyFD.AzureFD.net.")
	require.True(t, ok)
	assert.Equal(t, "myfd", n)
}

func TestFrontDoorEndpointName_EmptyLabel(t *testing.T) {
	_, ok := frontDoorEndpointName(".azurefd.net")
	assert.False(t, ok)
}
