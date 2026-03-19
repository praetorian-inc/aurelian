package enrichers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAllowAzureServicesRule(t *testing.T) {
	assert.True(t, isAllowAzureServicesRule("0.0.0.0", "0.0.0.0"))
	assert.False(t, isAllowAzureServicesRule("10.0.0.1", "10.0.0.1"))
	assert.False(t, isAllowAzureServicesRule("0.0.0.0", "255.255.255.255"))
	assert.False(t, isAllowAzureServicesRule("", ""))
}

func TestDerefStr(t *testing.T) {
	s := "hello"
	assert.Equal(t, "hello", derefStr(&s))
	assert.Equal(t, "", derefStr(nil))
}
