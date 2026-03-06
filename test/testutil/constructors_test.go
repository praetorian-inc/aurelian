//go:build integration

package testutil

import "testing"

func TestConstructorSymbolsExist(t *testing.T) {
	_ = NewAWSFixture
	_ = NewAzureFixture
}
