package helpers

import "testing"

func TestIsGlobalService(t *testing.T) {
	tests := []struct {
		resourceType string
		want         bool
	}{
		{"AWS::IAM::Role", true},
		{"AWS::CloudFront::Distribution", true},
		{"AWS::Route53::HostedZone", true},
		{"AWS::Organizations::Account", true},
		{"AWS::ECR::PublicRepository", true},
		{"AWS::S3::Bucket", false},
		{"AWS::Lambda::Function", false},
		{"AWS::ECR::Repository", false}, // private ECR is regional
		{"", false},
	}
	for _, tt := range tests {
		if got := IsGlobalService(tt.resourceType); got != tt.want {
			t.Errorf("IsGlobalService(%q) = %v, want %v", tt.resourceType, got, tt.want)
		}
	}
}

func TestRegionForService(t *testing.T) {
	tests := []struct {
		name           string
		resourceType   string
		resourceRegion string
		want           string
	}{
		{
			name:           "regional resource with real region passes through",
			resourceType:   "AWS::Lambda::Function",
			resourceRegion: "eu-west-1",
			want:           "eu-west-1",
		},
		{
			name:           "global resource with empty region falls back to us-east-1",
			resourceType:   "AWS::CloudFront::Distribution",
			resourceRegion: "",
			want:           "us-east-1",
		},
		{
			name:           "IAM literal global sentinel falls back to us-east-1",
			resourceType:   "AWS::IAM::Role",
			resourceRegion: "global",
			want:           "us-east-1",
		},
		{
			name:           "global resource that already carries a real region keeps it",
			resourceType:   "AWS::CloudFront::Distribution",
			resourceRegion: "us-east-1",
			want:           "us-east-1",
		},
		{
			name:           "regional resource with empty region is left empty (NewAWSConfig warns)",
			resourceType:   "AWS::Lambda::Function",
			resourceRegion: "",
			want:           "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RegionForService(tt.resourceType, tt.resourceRegion); got != tt.want {
				t.Errorf("RegionForService(%q, %q) = %q, want %q",
					tt.resourceType, tt.resourceRegion, got, tt.want)
			}
		})
	}
}
