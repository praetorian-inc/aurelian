package resourcetypes

import (
	"testing"
)

func TestGetAllReturnsNonEmpty(t *testing.T) {
	all := GetAll()
	if len(all) == 0 {
		t.Fatal("GetAll() returned empty slice")
	}
}

func TestGetSummaryReturnsNonEmpty(t *testing.T) {
	summary := GetSummary()
	if len(summary) == 0 {
		t.Fatal("GetSummary() returned empty slice")
	}
}

func TestSummaryIsSubsetOfAll(t *testing.T) {
	allSet := make(map[string]bool)
	for _, rt := range GetAll() {
		allSet[rt] = true
	}

	for _, rt := range GetSummary() {
		if !allSet[rt] {
			t.Errorf("summary resource type %q is not in All set", rt)
		}
	}
}

func TestGetAllHasNoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, rt := range GetAll() {
		if seen[rt] {
			t.Errorf("duplicate resource type in All: %q", rt)
		}
		seen[rt] = true
	}
}

func TestGetSummaryHasNoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, rt := range GetSummary() {
		if seen[rt] {
			t.Errorf("duplicate resource type in Summary: %q", rt)
		}
		seen[rt] = true
	}
}

func TestIsValidWithKnownType(t *testing.T) {
	if !IsValid("AWS::EC2::Instance") {
		t.Error("expected AWS::EC2::Instance to be valid")
	}
}

func TestIsValidWithUnknownType(t *testing.T) {
	if IsValid("AWS::Fake::Thing") {
		t.Error("expected AWS::Fake::Thing to be invalid")
	}
}

func TestIsValidEmptyString(t *testing.T) {
	if IsValid("") {
		t.Error("expected empty string to be invalid")
	}
}

func TestValidateWithAllValid(t *testing.T) {
	err := Validate([]string{"AWS::EC2::Instance", "AWS::S3::Bucket"})
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateWithInvalidType(t *testing.T) {
	err := Validate([]string{"AWS::EC2::Instance", "AWS::Fake::Thing"})
	if err == nil {
		t.Error("expected error for invalid resource type")
	}
}

func TestValidateEmptySlice(t *testing.T) {
	err := Validate([]string{})
	if err != nil {
		t.Errorf("expected no error for empty slice, got: %v", err)
	}
}

func TestAllTypesFollowAWSFormat(t *testing.T) {
	for _, rt := range GetAll() {
		// AWS CloudControl types follow AWS::Service::Resource pattern
		if len(rt) < 10 || rt[:5] != "AWS::" {
			t.Errorf("resource type %q does not follow AWS::Service::Resource format", rt)
		}
	}
}
