//go:build integration

package testutil

import "testing"

func TestAzureContainerID_FromEnv(t *testing.T) {
	t.Setenv("AZURE_SUBSCRIPTION_ID", "sub-123")

	id, err := resolveAzureSubscriptionID()
	if err != nil {
		t.Fatalf("resolve azure subscription id: %v", err)
	}
	if id != "sub-123" {
		t.Fatalf("unexpected subscription id: got=%q want=%q", id, "sub-123")
	}
}

func TestAzureContainerID_MissingEnvFails(t *testing.T) {
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")

	_, err := resolveAzureSubscriptionID()
	if err == nil {
		t.Fatal("expected error")
	}
}
