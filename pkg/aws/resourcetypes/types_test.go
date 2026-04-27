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

func TestValidateWithInvalidType(t *testing.T) {
	err := Validate([]string{"AWS::Fake::Thing"})
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

func TestIsExcluded_KnownExclusion(t *testing.T) {
	if !IsExcluded("AWS::Organizations::Account") {
		t.Error("expected AWS::Organizations::Account to be excluded")
	}
}

func TestIsExcluded_NonExcludedType(t *testing.T) {
	if IsExcluded("AWS::S3::Bucket") {
		t.Error("expected AWS::S3::Bucket to not be excluded")
	}
}

func TestExclusions_HaveJustifications(t *testing.T) {
	for rt, justification := range exclusions {
		if justification == "" {
			t.Errorf("exclusion %q has empty justification", rt)
		}
	}
}
